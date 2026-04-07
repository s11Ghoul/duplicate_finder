#!/usr/bin/env python3
"""Tests for the web application modules."""

import json
import os
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

from webapp.models import ScanJob
from webapp.vpn import VPNManager, VPNError


class TestScanJob(unittest.TestCase):
    """Test ScanJob dataclass."""

    def test_create_job(self):
        job = ScanJob(brands=["1xbet"], countries=["DE", "TR"])
        self.assertEqual(job.brands, ["1xbet"])
        self.assertEqual(job.countries, ["DE", "TR"])
        self.assertEqual(job.status, "queued")
        self.assertIsNotNone(job.id)
        self.assertEqual(len(job.id), 12)

    def test_add_log(self):
        job = ScanJob(brands=["test"], countries=["US"])
        job.add_log("Hello")
        self.assertEqual(len(job.log), 1)
        self.assertIn("Hello", job.log[0])
        self.assertRegex(job.log[0], r"\[\d{2}:\d{2}:\d{2}\] Hello")

    def test_to_dict(self):
        job = ScanJob(brands=["1xbet", "betway"], countries=["DE"])
        d = job.to_dict()
        self.assertEqual(d["brands"], ["1xbet", "betway"])
        self.assertEqual(d["countries"], ["DE"])
        self.assertEqual(d["status"], "queued")
        self.assertIn("id", d)
        self.assertIn("progress", d)
        self.assertIn("created_at", d)

    def test_progress_defaults(self):
        job = ScanJob(brands=["x"], countries=["US"])
        self.assertEqual(job.progress["queries_done"], 0)
        self.assertEqual(job.progress["sites_checked"], 0)
        self.assertEqual(job.progress["suspicious_found"], 0)

    def test_captcha_event(self):
        job = ScanJob(brands=["x"], countries=["US"])
        job.captcha_event = threading.Event()
        self.assertFalse(job.captcha_event.is_set())
        job.captcha_event.set()
        self.assertTrue(job.captcha_event.is_set())


class TestVPNManager(unittest.TestCase):
    """Test VPN manager with mocked filesystem and subprocess."""

    def setUp(self):
        import tempfile
        self.tmpdir = tempfile.mkdtemp()
        # Create fake credentials file
        self.creds_file = os.path.join(self.tmpdir, "credentials.txt")
        with open(self.creds_file, "w") as f:
            f.write("testuser\ntestpass\n")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _create_config(self, name: str):
        """Create a fake .ovpn config file."""
        path = os.path.join(self.tmpdir, name)
        with open(path, "w") as f:
            f.write("# fake ovpn config\n")
        return path

    def test_find_config_by_country(self):
        self._create_config("de-01.protonvpn.udp.ovpn")
        self._create_config("us-05.protonvpn.udp.ovpn")
        vpn = VPNManager(configs_dir=self.tmpdir, credentials_file=self.creds_file)
        config = vpn._find_config("DE")
        self.assertIn("de-", config)

    def test_find_config_not_found(self):
        vpn = VPNManager(configs_dir=self.tmpdir, credentials_file=self.creds_file)
        with self.assertRaises(VPNError) as ctx:
            vpn._find_config("XX")
        self.assertIn("No OpenVPN config", str(ctx.exception))

    def test_find_config_prefers_udp(self):
        self._create_config("de-01.protonvpn.tcp.ovpn")
        self._create_config("de-02.protonvpn.udp.ovpn")
        vpn = VPNManager(configs_dir=self.tmpdir, credentials_file=self.creds_file)
        config = vpn._find_config("DE")
        self.assertIn("udp", config)

    def test_list_available_countries(self):
        self._create_config("de-01.protonvpn.udp.ovpn")
        self._create_config("us-05.protonvpn.udp.ovpn")
        self._create_config("tr-03.protonvpn.tcp.ovpn")
        vpn = VPNManager(configs_dir=self.tmpdir, credentials_file=self.creds_file)
        countries = vpn.list_available_countries()
        self.assertEqual(countries, ["DE", "TR", "US"])

    def test_list_available_countries_empty(self):
        vpn = VPNManager(configs_dir=self.tmpdir, credentials_file=self.creds_file)
        self.assertEqual(vpn.list_available_countries(), [])

    def test_validate_credentials_missing(self):
        vpn = VPNManager(
            configs_dir=self.tmpdir,
            credentials_file=os.path.join(self.tmpdir, "nonexistent.txt"),
        )
        with self.assertRaises(VPNError) as ctx:
            vpn._validate_credentials()
        self.assertIn("not found", str(ctx.exception))

    def test_validate_credentials_empty(self):
        empty_creds = os.path.join(self.tmpdir, "empty.txt")
        with open(empty_creds, "w") as f:
            f.write("\n")
        vpn = VPNManager(configs_dir=self.tmpdir, credentials_file=empty_creds)
        with self.assertRaises(VPNError) as ctx:
            vpn._validate_credentials()
        self.assertIn("2 lines", str(ctx.exception))

    def test_validate_credentials_valid(self):
        vpn = VPNManager(configs_dir=self.tmpdir, credentials_file=self.creds_file)
        vpn._validate_credentials()  # Should not raise

    def test_status_disconnected(self):
        vpn = VPNManager(configs_dir=self.tmpdir, credentials_file=self.creds_file)
        s = vpn.status()
        self.assertFalse(s["connected"])
        self.assertIsNone(s["country"])

    @patch("webapp.vpn.VPNManager._is_tun_up", return_value=False)
    @patch("webapp.vpn.time.sleep")
    @patch("subprocess.run")
    def test_disconnect(self, mock_run, mock_sleep, mock_tun):
        mock_run.return_value = MagicMock(returncode=0)
        vpn = VPNManager(configs_dir=self.tmpdir, credentials_file=self.creds_file)
        result = vpn.disconnect()
        self.assertTrue(result)

    def test_ensure_connected_already_connected(self):
        vpn = VPNManager(configs_dir=self.tmpdir, credentials_file=self.creds_file)
        self._create_config("de-01.protonvpn.udp.ovpn")
        vpn._connected_country = "DE"
        with patch.object(vpn, "_is_tun_up", return_value=True):
            result = vpn.ensure_connected("DE")
        self.assertTrue(result)


class TestFlaskApp(unittest.TestCase):
    """Test Flask routes."""

    def setUp(self):
        from webapp.app import create_app
        self.app = create_app()
        self.client = self.app.test_client()

    def test_index_page(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Phishing", resp.data)

    def test_api_countries(self):
        resp = self.client.get("/api/countries")
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertIsInstance(data, list)
        self.assertGreaterEqual(len(data), 70)
        self.assertIn("code", data[0])
        self.assertIn("name", data[0])

    def test_api_create_scan_valid(self):
        resp = self.client.post(
            "/api/scan",
            json={"brands": "1xbet\nbetway", "countries": ["DE", "US"]},
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 201)
        data = json.loads(resp.data)
        self.assertIn("job_id", data)
        self.assertEqual(data["status"], "queued")

    def test_api_create_scan_no_brands(self):
        resp = self.client.post(
            "/api/scan",
            json={"brands": "", "countries": ["DE"]},
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 400)

    def test_api_create_scan_no_countries(self):
        resp = self.client.post(
            "/api/scan",
            json={"brands": "test", "countries": []},
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 400)

    def test_api_create_scan_invalid_country(self):
        resp = self.client.post(
            "/api/scan",
            json={"brands": "test", "countries": ["XX"]},
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 400)

    def test_api_list_jobs(self):
        # Create a job first
        self.client.post(
            "/api/scan",
            json={"brands": "test", "countries": ["DE"]},
            content_type="application/json",
        )
        resp = self.client.get("/api/jobs")
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertGreaterEqual(len(data), 1)

    def test_api_get_job(self):
        resp = self.client.post(
            "/api/scan",
            json={"brands": "test", "countries": ["US"]},
            content_type="application/json",
        )
        job_id = json.loads(resp.data)["job_id"]
        resp = self.client.get(f"/api/jobs/{job_id}")
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertEqual(data["id"], job_id)

    def test_api_get_job_not_found(self):
        resp = self.client.get("/api/jobs/nonexistent")
        self.assertEqual(resp.status_code, 404)

    def test_api_captcha_solved(self):
        resp = self.client.post(
            "/api/scan",
            json={"brands": "test", "countries": ["DE"]},
            content_type="application/json",
        )
        job_id = json.loads(resp.data)["job_id"]
        resp = self.client.post(f"/api/jobs/{job_id}/captcha-solved")
        self.assertEqual(resp.status_code, 200)

    def test_job_detail_page(self):
        resp = self.client.post(
            "/api/scan",
            json={"brands": "test", "countries": ["DE"]},
            content_type="application/json",
        )
        job_id = json.loads(resp.data)["job_id"]
        resp = self.client.get(f"/jobs/{job_id}")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(job_id[:8].encode(), resp.data)

    def test_job_detail_not_found(self):
        resp = self.client.get("/jobs/nonexistent")
        self.assertEqual(resp.status_code, 404)

    def test_download_result_not_found(self):
        resp = self.client.post(
            "/api/scan",
            json={"brands": "test", "countries": ["DE"]},
            content_type="application/json",
        )
        job_id = json.loads(resp.data)["job_id"]
        resp = self.client.get(f"/api/jobs/{job_id}/results/test")
        self.assertEqual(resp.status_code, 404)


if __name__ == "__main__":
    unittest.main(verbosity=2)
