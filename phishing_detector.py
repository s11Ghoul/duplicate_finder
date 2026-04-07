#!/usr/bin/env python3
"""
Phishing Site Detector — automated Google search + redirect analysis.

Searches Google for brand-related queries, visits top-10 results,
clicks login/register buttons, and flags sites where the redirect
domain differs from the original.

Usage:
    python phishing_detector.py
    python phishing_detector.py --brand 1xbet --country Germany
    python phishing_detector.py --brand 1xbet --country DE --output results.csv
"""

import argparse
import csv
import random
import re
import sys
import time
from datetime import datetime
from urllib.parse import urlparse

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait
from selenium.common.exceptions import (
    TimeoutException,
    WebDriverException,
    NoSuchElementException,
    ElementClickInterceptedException,
    StaleElementReferenceException,
)

from countries import resolve_country, list_countries

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

QUERY_TEMPLATES = [
    "{brand}",
    "{brand} casino",
    "{brand} bonus",
    "{brand} login",
    "{brand} download app",
    "{brand} download apk",
]

# Patterns to identify login / register buttons (multilingual)
LOGIN_BUTTON_PATTERNS = [
    # English
    r"log\s*in", r"sign\s*in", r"register", r"sign\s*up", r"create\s*account",
    r"join\s*now", r"get\s*started", r"my\s*account",
    # Russian
    r"войти", r"вход", r"регистрация", r"зарегистрироваться",
    r"создать\s*аккаунт", r"личный\s*кабинет",
    # Spanish
    r"iniciar\s*sesión", r"registrarse", r"crear\s*cuenta", r"entrar",
    # German
    r"anmelden", r"registrieren", r"einloggen", r"konto\s*erstellen",
    # French
    r"connexion", r"s'inscrire", r"créer\s*un\s*compte", r"se\s*connecter",
    # Portuguese
    r"entrar", r"cadastrar", r"criar\s*conta", r"fazer\s*login",
    # Turkish
    r"giriş", r"kayıt", r"üye\s*ol",
]

LOGIN_BUTTON_RE = re.compile(
    "|".join(LOGIN_BUTTON_PATTERNS), re.IGNORECASE
)

# Delay ranges (seconds) between actions
DELAY_BETWEEN_QUERIES = (8, 15)
DELAY_BETWEEN_SITES = (3, 6)
DELAY_PAGE_LOAD = (2, 4)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def get_domain(url: str) -> str:
    """Extract the registered domain from a URL."""
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    # Remove www. prefix for comparison
    if hostname.startswith("www."):
        hostname = hostname[4:]
    return hostname.lower()


def random_delay(range_tuple: tuple[float, float]):
    """Sleep for a random duration within the given range."""
    time.sleep(random.uniform(*range_tuple))


def create_driver(
    headless: bool = False, chrome_binary: str | None = None
) -> webdriver.Chrome:
    """Create a Chrome WebDriver instance with appropriate settings."""
    options = Options()
    options.add_argument("--start-maximized")
    options.add_argument("--disable-blink-features=AutomationControlled")
    options.add_experimental_option("excludeSwitches", ["enable-automation"])
    options.add_experimental_option("useAutomationExtension", False)

    # Required for Docker / containerized environments
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")

    if chrome_binary:
        options.binary_location = chrome_binary

    if headless:
        options.add_argument("--headless=new")
        options.add_argument("--disable-gpu")
        options.add_argument("--window-size=1920,1080")
    else:
        # Keep browser open for CAPTCHA solving (only in GUI mode)
        options.add_experimental_option("detach", True)

    driver = webdriver.Chrome(options=options)
    # Remove webdriver flag to reduce detection
    driver.execute_script(
        "Object.defineProperty(navigator, 'webdriver', {get: () => undefined})"
    )
    return driver


# ---------------------------------------------------------------------------
# CAPTCHA handling
# ---------------------------------------------------------------------------


def check_and_handle_captcha(driver: webdriver.Chrome, mode: str = "interactive") -> bool:
    """Detect Google CAPTCHA. Returns True if CAPTCHA was detected.

    Modes:
        - "interactive": pause and wait for user input (CLI usage)
        - "server": return True immediately without blocking (server usage)
    """
    captcha_indicators = [
        "sorry/index",
        "recaptcha",
        "/captcha",
        "unusual traffic",
    ]
    current_url = driver.current_url.lower()
    page_source_lower = driver.page_source[:3000].lower()

    is_captcha = any(ind in current_url for ind in captcha_indicators) or any(
        ind in page_source_lower for ind in captcha_indicators
    )

    if is_captcha:
        if mode == "interactive":
            print("\n" + "=" * 60)
            print("  CAPTCHA DETECTED!")
            print("  Please solve the CAPTCHA in the browser window.")
            print("  Press ENTER here when done...")
            print("=" * 60)
            input()
            time.sleep(2)
            return False  # Solved by user
        return True  # Server mode: signal CAPTCHA to caller

    return False


# ---------------------------------------------------------------------------
# Google Search
# ---------------------------------------------------------------------------


def google_search(
    driver: webdriver.Chrome,
    query: str,
    country_config: dict,
    num_results: int = 10,
    captcha_mode: str = "interactive",
) -> tuple[list[str], bool]:
    """
    Perform a Google search and return up to `num_results` organic result URLs.
    Uses the country-specific Google domain and geo parameters.

    Returns:
        (urls, captcha_detected) — list of URLs and whether CAPTCHA was hit.
    """
    domain = country_config["domain"]
    gl = country_config["gl"]
    hl = country_config["hl"]

    search_url = f"https://www.{domain}/search?q={query}&gl={gl}&hl={hl}&num={num_results}"

    print(f"  Searching: {query}")
    driver.get(search_url)
    random_delay(DELAY_PAGE_LOAD)

    captcha_hit = check_and_handle_captcha(driver, mode=captcha_mode)
    if captcha_hit:
        return [], True

    # Accept cookies dialog if present
    try:
        accept_btns = driver.find_elements(
            By.XPATH,
            "//button[contains(., 'Accept') or contains(., 'Принять') "
            "or contains(., 'Akzeptieren') or contains(., 'Accepter') "
            "or contains(., 'Acepto') or contains(., 'Согласен')]",
        )
        if accept_btns:
            accept_btns[0].click()
            time.sleep(1)
    except Exception:
        pass

    # Collect organic results
    urls = []
    selectors = [
        "div.yuRUbf a",          # Standard desktop
        "div.g a[href]",         # Alternative
        "a[jsname='UWckNb']",    # Another variant
    ]

    for selector in selectors:
        try:
            elements = driver.find_elements(By.CSS_SELECTOR, selector)
            for el in elements:
                href = el.get_attribute("href")
                if href and href.startswith("http") and "google" not in get_domain(href):
                    if href not in urls:
                        urls.append(href)
        except Exception:
            continue

    # Fallback: parse all <a> tags in search results
    if not urls:
        try:
            all_links = driver.find_elements(By.CSS_SELECTOR, "#search a[href]")
            for el in all_links:
                href = el.get_attribute("href")
                if (
                    href
                    and href.startswith("http")
                    and "google" not in get_domain(href)
                    and "youtube.com" not in href
                    and "/search?" not in href
                ):
                    if href not in urls:
                        urls.append(href)
        except Exception:
            pass

    return urls[:num_results], False


# ---------------------------------------------------------------------------
# Click login/register + redirect detection
# ---------------------------------------------------------------------------


def find_and_click_login(driver: webdriver.Chrome) -> str | None:
    """
    Try to find and click a login/register button on the current page.
    Returns the final URL after the click, or None if no button found.
    """
    # Collect candidate elements: buttons, links, inputs
    candidates = []
    for tag in ["a", "button", "input[type='button']", "input[type='submit']"]:
        try:
            elements = driver.find_elements(By.CSS_SELECTOR, tag)
            candidates.extend(elements)
        except Exception:
            continue

    # Also look for elements with common login-related classes/ids
    for selector in [
        "[class*='login']", "[class*='signin']", "[class*='sign-in']",
        "[class*='register']", "[class*='signup']", "[class*='sign-up']",
        "[id*='login']", "[id*='signin']", "[id*='register']",
        "[href*='login']", "[href*='signin']", "[href*='register']",
        "[href*='signup']", "[href*='sign-up']", "[href*='sign-in']",
    ]:
        try:
            elements = driver.find_elements(By.CSS_SELECTOR, selector)
            candidates.extend(elements)
        except Exception:
            continue

    # Deduplicate
    seen = set()
    unique_candidates = []
    for el in candidates:
        try:
            el_id = el.id
            if el_id not in seen:
                seen.add(el_id)
                unique_candidates.append(el)
        except StaleElementReferenceException:
            continue

    # Score and find the best match
    best_el = None
    best_score = 0

    for el in unique_candidates:
        try:
            text = (el.text or "").strip()
            aria = el.get_attribute("aria-label") or ""
            title = el.get_attribute("title") or ""
            href = el.get_attribute("href") or ""
            class_name = el.get_attribute("class") or ""
            el_id = el.get_attribute("id") or ""
            combined = f"{text} {aria} {title} {href} {class_name} {el_id}"

            if LOGIN_BUTTON_RE.search(combined):
                score = 1
                # Prefer visible elements
                if el.is_displayed():
                    score += 2
                # Prefer elements with text
                if text:
                    score += 1
                # Prefer buttons
                if el.tag_name == "button":
                    score += 1
                # Strong text match
                if LOGIN_BUTTON_RE.search(text):
                    score += 3

                if score > best_score:
                    best_score = score
                    best_el = el
        except StaleElementReferenceException:
            continue

    if not best_el:
        return None

    # Click the element
    try:
        original_windows = driver.window_handles

        try:
            best_el.click()
        except ElementClickInterceptedException:
            driver.execute_script("arguments[0].click();", best_el)

        time.sleep(3)

        # Handle new tab/window
        new_windows = driver.window_handles
        if len(new_windows) > len(original_windows):
            driver.switch_to.window(new_windows[-1])
            time.sleep(2)

        return driver.current_url

    except Exception as e:
        print(f"    Click failed: {e}")
        return None


def check_site_redirect(
    driver: webdriver.Chrome, url: str
) -> tuple[str, bool]:
    """
    Visit a site, click login/register, and check for domain change.
    Returns (redirect_url, is_suspicious).
    """
    original_domain = get_domain(url)

    try:
        driver.get(url)
        random_delay(DELAY_PAGE_LOAD)

        # Get the actual loaded URL (might already be a redirect)
        loaded_url = driver.current_url
        loaded_domain = get_domain(loaded_url)

        # Try to find and click login/register
        redirect_url = find_and_click_login(driver)

        if redirect_url:
            redirect_domain = get_domain(redirect_url)
            is_suspicious = (
                redirect_domain != original_domain
                and redirect_domain != loaded_domain
                and redirect_domain != ""
            )
            return redirect_url, is_suspicious
        else:
            # No login button found — check if initial load redirected
            is_suspicious = loaded_domain != original_domain and loaded_domain != ""
            return loaded_url, is_suspicious

    except TimeoutException:
        print(f"    Timeout loading {url}")
        return url, False
    except WebDriverException as e:
        print(f"    Error loading {url}: {e}")
        return url, False


# ---------------------------------------------------------------------------
# Main workflow
# ---------------------------------------------------------------------------


def run_scan(
    brand: str,
    country_str: str,
    output_file: str | None = None,
    headless: bool = False,
    chrome_binary: str | None = None,
):
    """Run the full phishing detection scan."""
    country = resolve_country(country_str)
    if not country:
        print(f"Error: Unknown country '{country_str}'")
        print("\nSupported countries:")
        for code, name in list_countries():
            print(f"  {code} — {name}")
        sys.exit(1)

    if not output_file:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"phishing_results_{brand}_{country['code']}_{timestamp}.csv"

    queries = [t.format(brand=brand) for t in QUERY_TEMPLATES]

    print(f"\nPhishing Detection Scan")
    print(f"  Brand:   {brand}")
    print(f"  Country: {country['name']} ({country['code']})")
    print(f"  Google:  {country['domain']} (gl={country['gl']}, hl={country['hl']})")
    print(f"  Output:  {output_file}")
    print(f"  Queries: {len(queries)}")
    print()
    print("IMPORTANT: Make sure your VPN is connected to", country["name"])
    print()

    results = []
    driver = create_driver(headless=headless, chrome_binary=chrome_binary)

    try:
        for q_idx, query in enumerate(queries):
            print(f"\n[{q_idx + 1}/{len(queries)}] Query: '{query}'")
            print("-" * 50)

            urls, _captcha = google_search(driver, query, country)

            if not urls:
                print("  No results found.")
                continue

            print(f"  Found {len(urls)} results")

            for pos, url in enumerate(urls, 1):
                print(f"\n  [{pos}/{len(urls)}] {url}")

                # Open in new tab to preserve search results
                driver.execute_script("window.open('');")
                tabs = driver.window_handles
                driver.switch_to.window(tabs[-1])

                redirect_url, is_suspicious = check_site_redirect(driver, url)

                status = "YES" if is_suspicious else "no"
                print(f"    Redirect: {redirect_url}")
                print(f"    Suspicious: {status}")

                results.append({
                    "country": country["name"],
                    "query": query,
                    "position": pos,
                    "url": url,
                    "redirect_url": redirect_url,
                    "suspicious": status,
                })

                # Close tab and go back to search results
                driver.close()
                driver.switch_to.window(tabs[0])

                random_delay(DELAY_BETWEEN_SITES)

            # Delay between queries
            if q_idx < len(queries) - 1:
                delay = random.uniform(*DELAY_BETWEEN_QUERIES)
                print(f"\n  Waiting {delay:.0f}s before next query...")
                time.sleep(delay)

    except KeyboardInterrupt:
        print("\n\nScan interrupted by user. Saving collected results...")
    finally:
        # Save results
        if results:
            save_results(results, output_file)
        else:
            print("\nNo results collected.")

        try:
            driver.quit()
        except Exception:
            pass


def save_results(results: list[dict], output_file: str):
    """Save results to CSV."""
    fieldnames = ["country", "query", "position", "url", "redirect_url", "suspicious"]
    headers = {
        "country": "Страна",
        "query": "Запрос",
        "position": "Позиция",
        "url": "URL сайта",
        "redirect_url": "Редирект URL",
        "suspicious": "Подозрительный",
    }

    with open(output_file, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        # Write Russian headers
        writer.writerow(headers)
        writer.writerows(results)

    suspicious_count = sum(1 for r in results if r["suspicious"] == "YES")
    print(f"\nResults saved to: {output_file}")
    print(f"Total sites checked: {len(results)}")
    print(f"Suspicious sites:    {suspicious_count}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description="Phishing Site Detector — find suspicious sites imitating a brand"
    )
    parser.add_argument(
        "--brand", type=str, help="Brand name to search for (e.g. 1xbet)"
    )
    parser.add_argument(
        "--country",
        type=str,
        help="Country name or 2-letter code (e.g. Germany or DE)",
    )
    parser.add_argument(
        "--output", type=str, help="Output CSV file path (auto-generated if omitted)"
    )
    parser.add_argument(
        "--headless",
        action="store_true",
        help="Run browser in headless mode (no GUI)",
    )
    parser.add_argument(
        "--chrome-binary",
        type=str,
        help="Path to Chrome/Chromium binary",
    )
    parser.add_argument(
        "--list-countries",
        action="store_true",
        help="List all supported countries and exit",
    )
    args = parser.parse_args()

    if args.list_countries:
        print("Supported countries:")
        for code, name in list_countries():
            print(f"  {code} — {name}")
        sys.exit(0)

    brand = args.brand
    country = args.country

    # Interactive mode if args not provided
    if not brand:
        brand = input("Enter brand name (e.g. 1xbet): ").strip()
        if not brand:
            print("Error: Brand name is required.")
            sys.exit(1)

    if not country:
        country = input("Enter country name or code (e.g. Germany or DE): ").strip()
        if not country:
            print("Error: Country is required.")
            sys.exit(1)

    run_scan(brand, country, args.output, args.headless, args.chrome_binary)


if __name__ == "__main__":
    main()
