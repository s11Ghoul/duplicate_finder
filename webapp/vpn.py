"""OpenVPN-based VPN manager for Proton VPN.

Uses OpenVPN directly with Proton VPN .ovpn config files.
This approach works reliably in Docker containers, unlike the
deprecated protonvpn-cli which requires a GUI environment.

Setup:
    1. Download OpenVPN configs from https://account.protonvpn.com/downloads
       → Select "OpenVPN configuration files" → Platform: Linux
       → Protocol: UDP → Download for each country needed
    2. Place .ovpn files in the vpn-configs/ directory
    3. Create vpn-configs/credentials.txt with your OpenVPN credentials:
       Line 1: OpenVPN username (from Proton VPN dashboard, NOT your email)
       Line 2: OpenVPN password
"""

import glob
import os
import re
import signal
import subprocess
import time


class VPNError(Exception):
    pass


# Default paths
DEFAULT_CONFIGS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "vpn-configs"
)
DEFAULT_CREDENTIALS_FILE = os.path.join(DEFAULT_CONFIGS_DIR, "credentials.txt")


class VPNManager:
    """Manages VPN connections via OpenVPN with Proton VPN config files."""

    def __init__(
        self,
        configs_dir: str = DEFAULT_CONFIGS_DIR,
        credentials_file: str = DEFAULT_CREDENTIALS_FILE,
    ):
        self.configs_dir = configs_dir
        self.credentials_file = credentials_file
        self._process: subprocess.Popen | None = None
        self._connected_country: str | None = None

    def _find_config(self, country_code: str) -> str:
        """Find an .ovpn config file for the given country code.

        Proton VPN config filenames follow patterns like:
            de-free-01.protonvpn.udp.ovpn
            de-01.protonvpn.udp.ovpn
            us-free-05.protonvpn.tcp.ovpn
            nl.protonvpn.udp.ovpn
        """
        country_code = country_code.lower()

        # Search for matching config files
        patterns = [
            os.path.join(self.configs_dir, f"{country_code}*.ovpn"),
            os.path.join(self.configs_dir, f"{country_code.upper()}*.ovpn"),
        ]

        matches = []
        for pattern in patterns:
            matches.extend(glob.glob(pattern))

        # Prefer UDP over TCP, and non-free over free
        if not matches:
            # Try case-insensitive search
            all_configs = glob.glob(os.path.join(self.configs_dir, "*.ovpn"))
            matches = [
                f for f in all_configs
                if os.path.basename(f).lower().startswith(country_code)
            ]

        if not matches:
            available = self.list_available_countries()
            raise VPNError(
                f"No OpenVPN config found for country '{country_code.upper()}'. "
                f"Available: {', '.join(available) if available else 'none'}. "
                f"Download configs from https://account.protonvpn.com/downloads"
            )

        # Sort: prefer UDP, prefer non-free servers
        def sort_key(path):
            name = os.path.basename(path).lower()
            score = 0
            if "udp" in name:
                score += 2
            if "free" not in name:
                score += 1
            return -score

        matches.sort(key=sort_key)
        return matches[0]

    def list_available_countries(self) -> list[str]:
        """List country codes that have config files available."""
        configs = glob.glob(os.path.join(self.configs_dir, "*.ovpn"))
        countries = set()
        for path in configs:
            name = os.path.basename(path).lower()
            # Extract country code (first 2 chars before dash or dot)
            match = re.match(r"^([a-z]{2})", name)
            if match:
                countries.add(match.group(1).upper())
        return sorted(countries)

    def _validate_credentials(self):
        """Check that credentials file exists and is valid."""
        if not os.path.exists(self.credentials_file):
            raise VPNError(
                f"Credentials file not found: {self.credentials_file}\n"
                "Create it with your Proton VPN OpenVPN credentials:\n"
                "  Line 1: OpenVPN username\n"
                "  Line 2: OpenVPN password\n"
                "Get them from: https://account.protonvpn.com/account#openvpn"
            )
        with open(self.credentials_file) as f:
            lines = f.read().strip().split("\n")
        if len(lines) < 2 or not lines[0].strip() or not lines[1].strip():
            raise VPNError(
                "Credentials file must contain 2 lines: username and password"
            )

    def status(self) -> dict:
        """Get current VPN connection status."""
        connected = self._process is not None and self._process.poll() is None
        info = {
            "connected": connected,
            "country": self._connected_country if connected else None,
            "server": None,
            "ip": None,
        }

        if connected:
            # Try to get public IP
            try:
                result = subprocess.run(
                    ["curl", "-s", "--max-time", "5", "https://api.ipify.org"],
                    capture_output=True, text=True, timeout=10,
                )
                if result.returncode == 0 and result.stdout.strip():
                    info["ip"] = result.stdout.strip()
            except Exception:
                pass

        return info

    def connect(self, country_code: str, timeout: int = 30) -> bool:
        """Connect to VPN server in the given country.

        Starts OpenVPN process with the country's config file.
        Waits for connection to be established (checks for TUN device).
        """
        country_code = country_code.upper()
        self._validate_credentials()

        config_path = self._find_config(country_code)
        config_name = os.path.basename(config_path)

        # Start OpenVPN
        cmd = [
            "openvpn",
            "--config", config_path,
            "--auth-user-pass", self.credentials_file,
            "--daemon",
            "--log", "/tmp/openvpn.log",
            "--writepid", "/tmp/openvpn.pid",
            "--connect-retry", "3",
            "--connect-timeout", str(timeout),
            # Prevent DNS leaks
            "--script-security", "2",
            "--up", "/etc/openvpn/update-resolv-conf",
            "--down", "/etc/openvpn/update-resolv-conf",
        ]

        # Check if update-resolv-conf exists, if not use simpler approach
        if not os.path.exists("/etc/openvpn/update-resolv-conf"):
            cmd = [
                "openvpn",
                "--config", config_path,
                "--auth-user-pass", self.credentials_file,
                "--daemon",
                "--log", "/tmp/openvpn.log",
                "--writepid", "/tmp/openvpn.pid",
                "--connect-retry", "3",
                "--connect-timeout", str(timeout),
            ]

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=10
            )
        except subprocess.TimeoutExpired:
            pass  # openvpn --daemon returns quickly, but just in case
        except FileNotFoundError:
            raise VPNError("openvpn not found. Install it: apt-get install openvpn")

        # Wait for connection by checking for TUN interface
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self._is_tun_up():
                self._connected_country = country_code
                # Read PID for later management
                try:
                    with open("/tmp/openvpn.pid") as f:
                        pid = int(f.read().strip())
                    # Create a mock Popen-like object to track the process
                    self._process = _PidTracker(pid)
                except Exception:
                    pass
                return True
            time.sleep(2)

        # Connection failed — read log for error details
        error_msg = ""
        try:
            with open("/tmp/openvpn.log") as f:
                error_msg = f.read()[-500:]
        except Exception:
            pass

        raise VPNError(
            f"VPN connection to {country_code} ({config_name}) timed out "
            f"after {timeout}s.\n{error_msg}"
        )

    def disconnect(self) -> bool:
        """Disconnect from VPN."""
        # Kill OpenVPN process
        try:
            pid_file = "/tmp/openvpn.pid"
            if os.path.exists(pid_file):
                with open(pid_file) as f:
                    pid = int(f.read().strip())
                os.kill(pid, signal.SIGTERM)
                time.sleep(2)
                # Force kill if still running
                try:
                    os.kill(pid, 0)  # Check if alive
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                os.remove(pid_file)
        except (FileNotFoundError, ValueError, ProcessLookupError):
            pass

        # Also try killing any remaining openvpn processes
        subprocess.run(
            ["pkill", "-f", "openvpn"],
            capture_output=True, timeout=5,
        )

        self._process = None
        self._connected_country = None
        time.sleep(1)

        return not self._is_tun_up()

    def ensure_connected(self, country_code: str) -> bool:
        """Ensure VPN is connected to the specified country."""
        country_code = country_code.upper()

        if self._connected_country == country_code and self._is_tun_up():
            return True

        # Disconnect from current country first
        if self._is_tun_up():
            self.disconnect()

        return self.connect(country_code)

    @staticmethod
    def _is_tun_up() -> bool:
        """Check if a TUN interface is active (VPN connected)."""
        try:
            result = subprocess.run(
                ["ip", "link", "show", "type", "tun"],
                capture_output=True, text=True, timeout=5,
            )
            return "tun" in result.stdout
        except Exception:
            return False


class _PidTracker:
    """Minimal wrapper to track an external process by PID."""

    def __init__(self, pid: int):
        self.pid = pid

    def poll(self) -> int | None:
        """Return None if process is running, or exit code."""
        try:
            os.kill(self.pid, 0)
            return None  # Still running
        except ProcessLookupError:
            return 1  # Dead
