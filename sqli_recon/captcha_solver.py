"""Interactive CAPTCHA solver — opens a browser for the user to solve manually."""

import logging
import time

log = logging.getLogger(__name__)

try:
    from playwright.sync_api import sync_playwright
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False


class CaptchaSolver:
    """
    When a CAPTCHA is detected, opens a visible browser window at the
    CAPTCHA page. The user solves it manually. Once solved (page changes
    or user closes the prompt), captures the fresh cookies and injects
    them back into the HTTP client's session.
    """

    def __init__(self, client, proxy=None, verify_ssl=True):
        self.client = client
        self.proxy = proxy
        self.verify_ssl = verify_ssl
        self._available = HAS_PLAYWRIGHT

    @property
    def available(self):
        return self._available

    def solve(self, url, timeout=300):
        """
        Open a browser at the given URL for manual CAPTCHA solving.

        Args:
            url: The URL that triggered the CAPTCHA
            timeout: Max seconds to wait for the user (default: 5 min)

        Returns:
            True if new cookies were captured, False if timed out or failed.
        """
        if not self._available:
            log.warning("Playwright not installed — can't open browser for CAPTCHA")
            return False

        print(f"\n  *** CAPTCHA detected on {url} ***")
        print(f"  Opening browser — solve the CAPTCHA, then the scan will continue.")
        print(f"  (Waiting up to {timeout // 60} minutes...)\n")

        new_cookies = {}

        try:
            with sync_playwright() as pw:
                launch_args = {"headless": False}  # Visible browser
                if self.proxy:
                    launch_args["proxy"] = {"server": self.proxy}

                browser = pw.chromium.launch(**launch_args)
                context = browser.new_context(
                    ignore_https_errors=not self.verify_ssl,
                    user_agent=self.client.session.headers.get("User-Agent", ""),
                )

                # Inject existing cookies into the browser
                existing_cookies = []
                for name, value in self.client.session.cookies.get_dict().items():
                    from urllib.parse import urlparse
                    parsed = urlparse(url)
                    existing_cookies.append({
                        "name": name,
                        "value": value,
                        "domain": parsed.hostname,
                        "path": "/",
                    })
                if existing_cookies:
                    context.add_cookies(existing_cookies)

                page = context.new_page()

                try:
                    page.goto(url, wait_until="domcontentloaded", timeout=30000)
                except Exception:
                    pass  # Page may partially load with CAPTCHA

                # Wait for the user to solve the CAPTCHA
                # We detect "solved" by either:
                # 1. The URL changes (redirect after solving)
                # 2. The page content changes (CAPTCHA form disappears)
                # 3. Timeout
                initial_url = page.url
                initial_content_hash = hash(page.content()[:1000])

                start = time.time()
                solved = False

                while time.time() - start < timeout:
                    time.sleep(2)

                    try:
                        current_url = page.url
                        current_hash = hash(page.content()[:1000])
                    except Exception:
                        # Browser was closed by user
                        break

                    # Check if page changed (CAPTCHA was solved)
                    if current_url != initial_url or current_hash != initial_content_hash:
                        # Wait a moment for cookies to settle after redirect
                        time.sleep(3)
                        solved = True
                        break

                if solved or time.time() - start >= 2:
                    # Capture all cookies from the browser
                    try:
                        browser_cookies = context.cookies()
                        for cookie in browser_cookies:
                            new_cookies[cookie["name"]] = cookie["value"]
                    except Exception:
                        pass

                browser.close()

        except Exception as e:
            log.warning(f"CAPTCHA solver error: {e}")
            return False

        if new_cookies:
            # Inject new cookies back into the HTTP client
            self.client.session.cookies.update(new_cookies)

            # Reset CAPTCHA backoff state
            self.client._captcha_backoff = False
            self.client._adaptive_delay = max(0, self.client._adaptive_delay - 3.0)

            cookie_count = len(new_cookies)
            print(f"  CAPTCHA solved — {cookie_count} cookies captured, scan resuming.\n")
            return True

        print(f"  No new cookies captured. Continuing without CAPTCHA bypass.\n")
        return False
