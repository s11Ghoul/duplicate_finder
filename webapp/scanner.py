"""Scan orchestration: ties together VPN, browser, and phishing detection."""

import os
import threading
import time
from datetime import datetime

from countries import resolve_country
from phishing_detector import (
    QUERY_TEMPLATES,
    create_driver,
    google_search,
    check_site_redirect,
    save_results,
    random_delay,
    DELAY_BETWEEN_QUERIES,
    DELAY_BETWEEN_SITES,
)
from webapp.models import ScanJob
from webapp.vpn import VPNManager, VPNError

RESULTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "results")


class ScanOrchestrator:
    """Runs a full phishing scan job with VPN switching and CAPTCHA handling."""

    def __init__(self, vpn: VPNManager):
        self.vpn = vpn

    def run_job(self, job: ScanJob):
        """Execute the scan job: iterate brands × countries, save CSV per brand."""
        job.status = "running"
        job.started_at = datetime.now()
        job.progress["brands_total"] = len(job.brands)
        job.progress["queries_total"] = (
            len(job.brands) * len(job.countries) * len(QUERY_TEMPLATES)
        )

        os.makedirs(RESULTS_DIR, exist_ok=True)

        try:
            for brand_idx, brand in enumerate(job.brands):
                job.progress["current_brand"] = brand
                job.add_log(f"Starting brand: {brand}")

                all_results = []

                for country_code in job.countries:
                    country = resolve_country(country_code)
                    if not country:
                        job.add_log(f"Unknown country: {country_code}, skipping")
                        continue

                    job.progress["current_country"] = country["name"]
                    job.add_log(
                        f"Connecting VPN to {country['name']} ({country_code})..."
                    )

                    # Switch VPN
                    try:
                        self.vpn.ensure_connected(country_code)
                        vpn_status = self.vpn.status()
                        job.add_log(
                            f"VPN connected: {vpn_status.get('server', '?')} "
                            f"(IP: {vpn_status.get('ip', '?')})"
                        )
                    except VPNError as e:
                        job.add_log(f"VPN error for {country_code}: {e}")
                        continue

                    # Create browser (GUI on Xvfb for noVNC access)
                    driver = create_driver(headless=False)
                    try:
                        results = self._scan_country(
                            driver, brand, country, job
                        )
                        all_results.extend(results)
                    finally:
                        try:
                            driver.quit()
                        except Exception:
                            pass

                # Save CSV per brand
                if all_results:
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    filename = f"phishing_{brand}_{timestamp}.csv"
                    filepath = os.path.join(RESULTS_DIR, filename)
                    save_results(all_results, filepath)
                    job.result_files[brand] = filename
                    job.add_log(
                        f"Brand '{brand}' done: {len(all_results)} sites checked, "
                        f"saved to {filename}"
                    )

                job.progress["brands_done"] = brand_idx + 1

            # Disconnect VPN at the end
            try:
                self.vpn.disconnect()
            except VPNError:
                pass

            job.status = "completed"
            job.add_log("Scan completed successfully")

        except Exception as e:
            job.status = "failed"
            job.error = str(e)
            job.add_log(f"Scan failed: {e}")
            raise
        finally:
            job.completed_at = datetime.now()

    def _scan_country(
        self,
        driver,
        brand: str,
        country: dict,
        job: ScanJob,
    ) -> list[dict]:
        """Scan all queries for a brand in one country."""
        results = []
        queries = [t.format(brand=brand) for t in QUERY_TEMPLATES]

        for q_idx, query in enumerate(queries):
            job.progress["current_query"] = query
            job.add_log(f"Query: '{query}'")

            urls, captcha_hit = google_search(
                driver, query, country, captcha_mode="server"
            )

            if captcha_hit:
                job.add_log("CAPTCHA detected! Pausing for manual solving...")
                self._handle_captcha(driver, job)
                # Retry after CAPTCHA solved
                urls, captcha_hit = google_search(
                    driver, query, country, captcha_mode="server"
                )
                if captcha_hit:
                    job.add_log("CAPTCHA still present, skipping query")
                    job.progress["queries_done"] += 1
                    continue

            if not urls:
                job.add_log("No results found")
                job.progress["queries_done"] += 1
                continue

            job.add_log(f"Found {len(urls)} results")

            for pos, url in enumerate(urls, 1):
                # Open in new tab
                driver.execute_script("window.open('');")
                tabs = driver.window_handles
                driver.switch_to.window(tabs[-1])

                redirect_url, is_suspicious = check_site_redirect(driver, url)
                status = "YES" if is_suspicious else "no"

                if is_suspicious:
                    job.add_log(f"  SUSPICIOUS: {url} -> {redirect_url}")
                    job.progress["suspicious_found"] += 1

                results.append({
                    "country": country["name"],
                    "query": query,
                    "position": pos,
                    "url": url,
                    "redirect_url": redirect_url,
                    "suspicious": status,
                })

                job.progress["sites_checked"] += 1

                # Close tab, go back
                driver.close()
                driver.switch_to.window(tabs[0])

                random_delay(DELAY_BETWEEN_SITES)

            job.progress["queries_done"] += 1

            # Delay between queries
            if q_idx < len(queries) - 1:
                random_delay(DELAY_BETWEEN_QUERIES)

        return results

    def _handle_captcha(self, driver, job: ScanJob):
        """Pause scan and wait for user to solve CAPTCHA via noVNC."""
        # Take screenshot for reference
        try:
            screenshot_path = os.path.join(RESULTS_DIR, f"captcha_{job.id}.png")
            driver.save_screenshot(screenshot_path)
        except Exception:
            pass

        job.status = "paused_captcha"
        job.captcha_pending = True
        job.add_log(
            "Scan paused. Please solve the CAPTCHA via noVNC (port 6080) "
            "and click 'CAPTCHA Solved' in the web interface."
        )

        # Wait for user to signal CAPTCHA is solved
        if job.captcha_event is None:
            job.captcha_event = threading.Event()

        job.captcha_event.wait(timeout=600)  # 10 min max wait
        job.captcha_event.clear()

        job.captcha_pending = False
        job.status = "running"
        job.add_log("CAPTCHA marked as solved, resuming scan...")
        time.sleep(2)
