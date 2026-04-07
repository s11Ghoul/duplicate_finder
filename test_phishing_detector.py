#!/usr/bin/env python3
"""
Integration tests for phishing_detector.py

Spins up a local HTTP server that simulates Google search results
and test websites (with login buttons, redirects, etc.) to verify
the full pipeline without external network access.

Unit tests use standard unittest. Browser integration tests use Playwright
(which bundles a matching Chromium version) to avoid chromedriver version
mismatch issues.
"""

import csv
import http.server
import os
import re
import threading
import time
import unittest
from urllib.parse import urlparse, parse_qs

from countries import resolve_country, list_countries
from phishing_detector import (
    get_domain,
    save_results,
    LOGIN_BUTTON_RE,
    QUERY_TEMPLATES,
)

CHROME_BIN = "/opt/pw-browsers/chromium-1194/chrome-linux/chrome"
TEST_PORT = 18932

# Regex for login button matching (same patterns as phishing_detector)
LOGIN_RE = LOGIN_BUTTON_RE


# ---------------------------------------------------------------------------
# Fake web server simulating Google + target sites
# ---------------------------------------------------------------------------

FAKE_GOOGLE_HTML = """<!DOCTYPE html>
<html><head><title>Google</title></head>
<body>
<div id="search">
  <div class="g"><div class="yuRUbf">
    <a href="http://localhost:{port}/site-normal">
      <h3>Normal Site</h3>
    </a>
  </div></div>
  <div class="g"><div class="yuRUbf">
    <a href="http://localhost:{port}/site-suspicious">
      <h3>Suspicious Site</h3>
    </a>
  </div></div>
  <div class="g"><div class="yuRUbf">
    <a href="http://localhost:{port}/site-no-login">
      <h3>No Login Site</h3>
    </a>
  </div></div>
</div>
</body></html>"""

SITE_NORMAL_HTML = """<!DOCTYPE html>
<html><head><title>Normal Site</title></head>
<body>
<h1>Welcome</h1>
<a href="http://localhost:{port}/site-normal/login-page" class="login-btn">Log in</a>
</body></html>"""

SITE_NORMAL_LOGIN_HTML = """<!DOCTYPE html>
<html><head><title>Login - Normal Site</title></head>
<body><h1>Login Page</h1><form><input name="user"><input type="submit"></form></body></html>"""

SITE_SUSPICIOUS_HTML = """<!DOCTYPE html>
<html><head><title>Suspicious Site</title></head>
<body>
<h1>Welcome</h1>
<a href="http://127.0.0.1:{port}/phishing-redirect" id="login">Sign In</a>
</body></html>"""

PHISHING_REDIRECT_HTML = """<!DOCTYPE html>
<html><head><title>Phishing Target</title></head>
<body><h1>Enter credentials</h1></body></html>"""

SITE_NO_LOGIN_HTML = """<!DOCTYPE html>
<html><head><title>No Login Site</title></head>
<body><h1>Just content</h1><p>No login buttons here.</p></body></html>"""


class FakeHandler(http.server.BaseHTTPRequestHandler):
    """HTTP handler that serves fake Google results and test sites."""

    def log_message(self, format, *args):
        pass  # Suppress logs

    def do_GET(self):
        port = self.server.server_address[1]
        path = self.path.split("?")[0]

        routes = {
            "/search": FAKE_GOOGLE_HTML.format(port=port),
            "/site-normal": SITE_NORMAL_HTML.format(port=port),
            "/site-normal/login-page": SITE_NORMAL_LOGIN_HTML.format(port=port),
            "/site-suspicious": SITE_SUSPICIOUS_HTML.format(port=port),
            "/phishing-redirect": PHISHING_REDIRECT_HTML.format(port=port),
            "/site-no-login": SITE_NO_LOGIN_HTML.format(port=port),
        }

        content = routes.get(path)
        if content:
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(content.encode())
        else:
            self.send_response(404)
            self.end_headers()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestCountries(unittest.TestCase):
    """Test country resolution module."""

    def test_resolve_by_code(self):
        c = resolve_country("DE")
        self.assertEqual(c["name"], "Germany")
        self.assertEqual(c["code"], "DE")

    def test_resolve_by_name(self):
        c = resolve_country("Germany")
        self.assertEqual(c["code"], "DE")
        self.assertEqual(c["domain"], "google.de")

    def test_resolve_case_insensitive(self):
        c = resolve_country("germany")
        self.assertEqual(c["code"], "DE")

    def test_resolve_partial_match(self):
        c = resolve_country("united king")
        self.assertEqual(c["code"], "GB")

    def test_resolve_unknown(self):
        self.assertIsNone(resolve_country("Atlantis"))

    def test_country_count(self):
        countries = list_countries()
        self.assertGreaterEqual(len(countries), 70)

    def test_all_countries_have_required_fields(self):
        for code, name in list_countries():
            c = resolve_country(code)
            self.assertIn("domain", c)
            self.assertIn("gl", c)
            self.assertIn("hl", c)
            self.assertIn("name", c)


class TestHelpers(unittest.TestCase):
    """Test helper functions."""

    def test_get_domain_simple(self):
        self.assertEqual(get_domain("https://example.com/page"), "example.com")

    def test_get_domain_www(self):
        self.assertEqual(get_domain("https://www.example.com"), "example.com")

    def test_get_domain_subdomain(self):
        self.assertEqual(get_domain("https://sub.example.com"), "sub.example.com")

    def test_get_domain_with_port(self):
        self.assertEqual(get_domain("http://localhost:8080/path"), "localhost")

    def test_query_templates(self):
        queries = [t.format(brand="testbrand") for t in QUERY_TEMPLATES]
        self.assertEqual(len(queries), 6)
        self.assertIn("testbrand", queries)
        self.assertIn("testbrand casino", queries)
        self.assertIn("testbrand login", queries)

    def test_login_patterns(self):
        positives = [
            "Log in", "Sign In", "Register", "Sign Up",
            "Войти", "Регистрация", "Anmelden", "Connexion", "Giriş",
        ]
        negatives = ["Home", "Buy Now", "Contact", "About"]

        for text in positives:
            self.assertTrue(LOGIN_BUTTON_RE.search(text), f"Should match: {text}")
        for text in negatives:
            self.assertFalse(LOGIN_BUTTON_RE.search(text), f"Should NOT match: {text}")


class TestCSVOutput(unittest.TestCase):
    """Test CSV file generation."""

    def test_save_and_read_csv(self):
        results = [
            {
                "country": "Germany",
                "query": "1xbet",
                "position": 1,
                "url": "https://example.com",
                "redirect_url": "https://phishing.com/login",
                "suspicious": "YES",
            },
            {
                "country": "Germany",
                "query": "1xbet",
                "position": 2,
                "url": "https://legit.com",
                "redirect_url": "https://legit.com/auth",
                "suspicious": "no",
            },
        ]

        path = "/tmp/test_csv_output.csv"
        try:
            save_results(results, path)
            with open(path, encoding="utf-8-sig") as f:
                reader = csv.reader(f)
                rows = list(reader)

            # Check headers (Russian)
            self.assertEqual(rows[0][0], "Страна")
            self.assertEqual(rows[0][5], "Подозрительный")

            # Check data
            self.assertEqual(len(rows), 3)  # header + 2 rows
            self.assertEqual(rows[1][0], "Germany")
            self.assertEqual(rows[1][5], "YES")
            self.assertEqual(rows[2][5], "no")
        finally:
            if os.path.exists(path):
                os.unlink(path)


class TestBrowserIntegration(unittest.TestCase):
    """
    Integration tests using Playwright + local fake HTTP server.

    Uses Playwright (with its bundled Chromium) instead of Selenium
    to avoid chromedriver version mismatch in CI/server environments.
    Tests the same logic: search result parsing, login button detection,
    redirect tracking, and suspicious site flagging.
    """

    server = None
    server_thread = None
    browser = None
    page = None

    @classmethod
    def setUpClass(cls):
        # Start fake HTTP server
        cls.server = http.server.HTTPServer(("localhost", TEST_PORT), FakeHandler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever)
        cls.server_thread.daemon = True
        cls.server_thread.start()

        # Launch Playwright Chromium
        from playwright.sync_api import sync_playwright

        cls.pw = sync_playwright().start()
        cls.browser = cls.pw.chromium.launch(
            headless=True,
            executable_path=CHROME_BIN,
        )

    @classmethod
    def tearDownClass(cls):
        if cls.browser:
            cls.browser.close()
        if hasattr(cls, "pw") and cls.pw:
            cls.pw.stop()
        if cls.server:
            cls.server.shutdown()

    def setUp(self):
        self.page = self.browser.new_page()

    def tearDown(self):
        self.page.close()

    def test_browser_launched(self):
        self.assertTrue(self.browser.is_connected())

    def test_navigate_to_page(self):
        self.page.goto(f"http://localhost:{TEST_PORT}/site-normal")
        self.assertIn("Normal Site", self.page.title())

    def test_google_search_parses_results(self):
        """Test that fake Google page has parseable search results."""
        self.page.goto(f"http://localhost:{TEST_PORT}/search?q=test")
        links = self.page.query_selector_all("div.yuRUbf a")
        urls = [link.get_attribute("href") for link in links]
        self.assertEqual(len(urls), 3)
        self.assertTrue(any("site-normal" in u for u in urls))
        self.assertTrue(any("site-suspicious" in u for u in urls))
        self.assertTrue(any("site-no-login" in u for u in urls))

    def test_find_login_button_normal(self):
        """Login button on normal site is detected and leads to same domain."""
        self.page.goto(f"http://localhost:{TEST_PORT}/site-normal")
        # Find elements matching login patterns
        login_el = self.page.query_selector("a.login-btn")
        self.assertIsNotNone(login_el)
        text = login_el.text_content()
        self.assertTrue(LOGIN_RE.search(text), f"Should match login pattern: {text}")
        href = login_el.get_attribute("href")
        self.assertIn("login-page", href)

        # Click and verify stay on same domain
        login_el.click()
        self.page.wait_for_load_state("load")
        self.assertIn("localhost", self.page.url)
        self.assertIn("login-page", self.page.url)

    def test_find_login_button_suspicious(self):
        """Login button on suspicious site redirects to different domain."""
        self.page.goto(f"http://localhost:{TEST_PORT}/site-suspicious")
        login_el = self.page.query_selector("#login")
        self.assertIsNotNone(login_el)
        text = login_el.text_content()
        self.assertTrue(LOGIN_RE.search(text), f"Should match login pattern: {text}")
        href = login_el.get_attribute("href")
        # Link goes to 127.0.0.1 (different from localhost)
        self.assertIn("127.0.0.1", href)

        # Click and verify redirect to different domain
        login_el.click()
        self.page.wait_for_load_state("load")
        self.assertIn("127.0.0.1", self.page.url)

    def test_no_login_button_on_clean_site(self):
        """Site without login button: no matching elements found."""
        self.page.goto(f"http://localhost:{TEST_PORT}/site-no-login")
        # Check all links and buttons — none should match login patterns
        elements = self.page.query_selector_all("a, button")
        login_found = False
        for el in elements:
            text = el.text_content() or ""
            if LOGIN_RE.search(text):
                login_found = True
                break
        self.assertFalse(login_found, "Should not find login button on no-login page")

    def test_redirect_domain_detection_normal(self):
        """Normal site: domain stays the same after clicking login."""
        self.page.goto(f"http://localhost:{TEST_PORT}/site-normal")
        original_domain = get_domain(self.page.url)

        login_el = self.page.query_selector("a.login-btn")
        login_el.click()
        self.page.wait_for_load_state("load")

        redirect_domain = get_domain(self.page.url)
        self.assertEqual(original_domain, redirect_domain)

    def test_redirect_domain_detection_suspicious(self):
        """Suspicious site: domain changes after clicking login."""
        self.page.goto(f"http://localhost:{TEST_PORT}/site-suspicious")
        original_domain = get_domain(self.page.url)

        login_el = self.page.query_selector("#login")
        login_el.click()
        self.page.wait_for_load_state("load")

        redirect_domain = get_domain(self.page.url)
        self.assertNotEqual(original_domain, redirect_domain)

    def test_full_pipeline_simulation(self):
        """Simulate the full scan pipeline: search -> visit -> check redirect -> CSV."""
        # Step 1: Get search results
        self.page.goto(f"http://localhost:{TEST_PORT}/search?q=1xbet")
        links = self.page.query_selector_all("div.yuRUbf a")
        urls = [link.get_attribute("href") for link in links]
        self.assertGreaterEqual(len(urls), 3)

        results = []
        for pos, url in enumerate(urls, 1):
            page = self.browser.new_page()
            page.goto(url)
            page.wait_for_load_state("load")

            original_domain = get_domain(url)
            loaded_domain = get_domain(page.url)

            # Find login button
            redirect_url = page.url
            is_suspicious = False

            all_elements = page.query_selector_all("a, button")
            for el in all_elements:
                text = el.text_content() or ""
                el_href = el.get_attribute("href") or ""
                el_class = el.get_attribute("class") or ""
                el_id = el.get_attribute("id") or ""
                combined = f"{text} {el_href} {el_class} {el_id}"
                if LOGIN_RE.search(combined):
                    el.click()
                    page.wait_for_load_state("load")
                    redirect_url = page.url
                    redirect_domain = get_domain(redirect_url)
                    is_suspicious = (
                        redirect_domain != original_domain
                        and redirect_domain != loaded_domain
                        and redirect_domain != ""
                    )
                    break

            results.append({
                "country": "Germany",
                "query": "1xbet",
                "position": pos,
                "url": url,
                "redirect_url": redirect_url,
                "suspicious": "YES" if is_suspicious else "no",
            })
            page.close()

        # Verify results
        self.assertEqual(len(results), 3)

        # site-suspicious should be flagged
        suspicious_results = [r for r in results if r["suspicious"] == "YES"]
        self.assertGreaterEqual(len(suspicious_results), 1)

        # site-normal should NOT be flagged
        normal_results = [r for r in results if "site-normal" in r["url"]]
        self.assertEqual(len(normal_results), 1)
        self.assertEqual(normal_results[0]["suspicious"], "no")

        # Save CSV and verify
        csv_path = "/tmp/test_pipeline.csv"
        try:
            save_results(results, csv_path)
            with open(csv_path, encoding="utf-8-sig") as f:
                reader = csv.reader(f)
                rows = list(reader)
            self.assertEqual(rows[0][0], "Страна")
            self.assertEqual(len(rows), 4)  # header + 3 results
        finally:
            if os.path.exists(csv_path):
                os.unlink(csv_path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
