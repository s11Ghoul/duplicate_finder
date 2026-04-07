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
    """Test VPN manager with mocked subprocess calls."""

    def _mock_run(self, stdout="", stderr="", returncode=0):
        mock = MagicMock()
        mock.stdout = stdout
        mock.stderr = stderr
        mock.returncode = returncode
        return mock

    @patch("subprocess.run")
    def test_status_connected(self, mock_run):
        mock_run.return_value = self._mock_run(
            stdout=(
                "Status:     Connected\n"
                "Server:     DE#42\n"
                "Country:    Germany\n"
                "IP:         185.1.2.3\n"
            )
        )
        vpn = VPNManager()
        s = vpn.status()
        self.assertTrue(s["connected"])
        self.assertEqual(s["country"], "Germany")
        self.assertEqual(s["server"], "DE#42")
        self.assertEqual(s["ip"], "185.1.2.3")

    @patch("subprocess.run")
    def test_status_disconnected(self, mock_run):
        mock_run.return_value = self._mock_run(
            stdout="Status:     Disconnected\nNo active connection."
        )
        vpn = VPNManager()
        s = vpn.status()
        self.assertFalse(s["connected"])

    @patch("subprocess.run")
    def test_connect_success(self, mock_run):
        # First call: connect command, second: status poll
        mock_run.side_effect = [
            self._mock_run(stdout="Connected to DE#42"),
            self._mock_run(
                stdout="Status:     Connected\nServer:     DE#42\nIP: 1.2.3.4"
            ),
        ]
        vpn = VPNManager()
        result = vpn.connect("DE", timeout=5)
        self.assertTrue(result)

    @patch("subprocess.run")
    def test_connect_failure(self, mock_run):
        mock_run.return_value = self._mock_run(
            returncode=1, stderr="Authentication failed"
        )
        vpn = VPNManager()
        with self.assertRaises(VPNError):
            vpn.connect("DE", timeout=5)

    @patch("subprocess.run")
    @patch("webapp.vpn.time.sleep")
    def test_disconnect(self, mock_sleep, mock_run):
        mock_run.side_effect = [
            self._mock_run(stdout="Disconnected"),
            self._mock_run(stdout="Status:     Disconnected"),
        ]
        vpn = VPNManager()
        result = vpn.disconnect()
        self.assertTrue(result)

    @patch("subprocess.run")
    def test_ensure_connected_already_connected(self, mock_run):
        mock_run.return_value = self._mock_run(
            stdout="Status:     Connected\nServer:     DE#42\nIP: 1.2.3.4"
        )
        vpn = VPNManager()
        result = vpn.ensure_connected("DE")
        self.assertTrue(result)
        # Should only call status, no connect
        self.assertEqual(mock_run.call_count, 1)

    @patch("subprocess.run")
    def test_cli_not_found(self, mock_run):
        mock_run.side_effect = FileNotFoundError()
        vpn = VPNManager()
        with self.assertRaises(VPNError) as ctx:
            vpn.status()
        self.assertIn("not found", str(ctx.exception))


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
