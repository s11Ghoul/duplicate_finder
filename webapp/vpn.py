"""Proton VPN CLI wrapper for automated country switching."""

import re
import subprocess
import time


class VPNError(Exception):
    pass


class VPNManager:
    """Manages Proton VPN connections via protonvpn-cli."""

    def __init__(self, cli_path: str = "protonvpn-cli"):
        self.cli = cli_path

    def _run(self, *args, timeout: int = 60) -> subprocess.CompletedProcess:
        cmd = [self.cli, *args]
        try:
            return subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except FileNotFoundError:
            raise VPNError(
                f"protonvpn-cli not found at '{self.cli}'. "
                "Install it: https://protonvpn.com/support/linux-vpn-tool/"
            )
        except subprocess.TimeoutExpired:
            raise VPNError(f"VPN command timed out: {' '.join(cmd)}")

    def status(self) -> dict:
        """Get current VPN connection status.

        Returns dict with keys: connected, country, server, ip.
        """
        result = self._run("status")
        output = result.stdout + result.stderr

        info = {
            "connected": False,
            "country": None,
            "server": None,
            "ip": None,
        }

        if "Connected" in output or "connected" in output.lower():
            # Check it's not "Disconnected"
            if "Disconnected" not in output and "No active" not in output:
                info["connected"] = True

        # Parse country
        country_match = re.search(r"Country:\s*(.+)", output)
        if country_match:
            info["country"] = country_match.group(1).strip()

        # Parse server
        server_match = re.search(r"Server:\s*(.+)", output)
        if server_match:
            info["server"] = server_match.group(1).strip()

        # Parse IP
        ip_match = re.search(r"IP:\s*([\d.]+)", output)
        if ip_match:
            info["ip"] = ip_match.group(1).strip()

        return info

    def connect(self, country_code: str, timeout: int = 45) -> bool:
        """Connect to Proton VPN server in given country.

        Runs `protonvpn-cli connect --cc XX`, then polls status
        until connected or timeout reached.
        Returns True if connected successfully.
        """
        country_code = country_code.upper()

        result = self._run("connect", "--cc", country_code, timeout=timeout)
        if result.returncode != 0:
            error_msg = (result.stderr or result.stdout or "Unknown error").strip()
            raise VPNError(f"Failed to connect to {country_code}: {error_msg}")

        # Poll status until connected
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                s = self.status()
                if s["connected"]:
                    return True
            except VPNError:
                pass
            time.sleep(2)

        raise VPNError(
            f"VPN connection to {country_code} timed out after {timeout}s"
        )

    def disconnect(self) -> bool:
        """Disconnect from VPN. Returns True on success."""
        result = self._run("disconnect")
        # Verify disconnected
        time.sleep(2)
        s = self.status()
        return not s["connected"]

    def ensure_connected(self, country_code: str) -> bool:
        """Ensure VPN is connected to the specified country.

        If already connected to this country, does nothing.
        Otherwise disconnects first, then connects.
        """
        country_code = country_code.upper()

        try:
            s = self.status()
            if s["connected"]:
                # Check if already connected to the right country
                # Server names follow pattern like DE#42, US-CA#15
                if s.get("server", "").upper().startswith(country_code):
                    return True
                # Connected to wrong country — disconnect first
                self.disconnect()
        except VPNError:
            pass

        return self.connect(country_code)
