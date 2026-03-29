"""HTTP client with Tor/SOCKS proxy support, rate limiting, and session management."""

import time
import logging
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib.parse import urlparse

log = logging.getLogger(__name__)


class HttpClient:
    """Shared HTTP client with proxy, timeout, rate limiting, WAF handling, and retry support."""

    def __init__(
        self,
        proxy=None,
        timeout=30,
        user_agent=None,
        cookies=None,
        headers=None,
        verify_ssl=True,
        rate_limit=0.0,
        max_retries=2,
    ):
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.rate_limit = rate_limit  # Seconds between requests
        self._last_request_time = 0.0
        self._adaptive_delay = 0.0  # Auto-increases when rate limited

        # WAF/rate-limit/CAPTCHA tracking
        self.stats = {
            "requests": 0,
            "success": 0,
            "waf_blocks": 0,
            "rate_limited": 0,
            "captchas": 0,
            "errors": 0,
            "timeouts": 0,
        }
        self._captcha_backoff = False  # True when CAPTCHA detected, triggers slowdown
        self._session_mgr = None      # Set by CLI when --login is used
        self._reauth_in_progress = False  # Prevent re-login loops

        self.session = requests.Session()

        # Retry strategy for transient failures
        retry = Retry(
            total=max_retries,
            backoff_factor=0.5,
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=["GET", "HEAD", "OPTIONS"],
        )
        adapter = HTTPAdapter(max_retries=retry, pool_connections=10, pool_maxsize=20)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        # Proxy (Tor: socks5h://127.0.0.1:9050)
        if proxy:
            self.session.proxies = {
                "http": proxy,
                "https": proxy,
            }

        # Default headers
        self.session.headers.update({
            "User-Agent": user_agent or (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate",
        })

        if headers:
            self.session.headers.update(headers)
        if cookies:
            self.session.cookies.update(cookies)

        # SSL verification
        self.session.verify = verify_ssl
        if not verify_ssl:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def _rate_limit_wait(self):
        delay = max(self.rate_limit, self._adaptive_delay)
        if delay > 0:
            elapsed = time.time() - self._last_request_time
            if elapsed < delay:
                time.sleep(delay - elapsed)
        self._last_request_time = time.time()

    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self.request("POST", url, **kwargs)

    def head(self, url, **kwargs):
        return self.request("HEAD", url, **kwargs)

    def request(self, method, url, **kwargs):
        """Make an HTTP request with rate limiting, WAF detection, and error handling."""
        self._rate_limit_wait()
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("allow_redirects", True)

        self.stats["requests"] += 1

        try:
            resp = self.session.request(method, url, **kwargs)
            log.debug(f"{method} {url} -> {resp.status_code}")

            # Handle rate limiting (429)
            if resp.status_code == 429:
                self.stats["rate_limited"] += 1
                retry_after = int(resp.headers.get("Retry-After", 5))
                log.warning(f"Rate limited on {url}, backing off {retry_after}s")
                # Increase adaptive delay to avoid further rate limiting
                self._adaptive_delay = max(self._adaptive_delay, retry_after / 2)
                time.sleep(retry_after)
                # Retry once
                self.stats["requests"] += 1
                resp = self.session.request(method, url, **kwargs)
                if resp.status_code == 429:
                    # Still rate limited — increase delay more and give up on this request
                    self._adaptive_delay = min(self._adaptive_delay * 2, 10.0)
                    self.stats["rate_limited"] += 1
                    return resp

            # Track WAF blocks (403 that look like WAF, not auth)
            if resp.status_code == 403:
                body_lower = resp.text[:500].lower()
                if any(w in body_lower for w in [
                    "firewall", "blocked", "waf", "forbidden",
                    "access denied", "security", "rule",
                ]):
                    self.stats["waf_blocks"] += 1
                    log.debug(f"WAF block on {method} {url}")
                else:
                    self.stats["success"] += 1  # Auth 403, not WAF
                return resp

            # CAPTCHA detection — check response body for challenge pages
            if _is_captcha_response(resp):
                self.stats["captchas"] += 1
                resp._is_captcha = True
                log.debug(f"CAPTCHA detected on {method} {url}")

                if not self._captcha_backoff:
                    self._captcha_backoff = True
                    # First CAPTCHA — increase delay significantly
                    self._adaptive_delay = max(self._adaptive_delay, 3.0)
                    log.warning(f"CAPTCHA triggered — increasing delay to {self._adaptive_delay}s")
                else:
                    # Repeated CAPTCHAs — back off more
                    self._adaptive_delay = min(self._adaptive_delay * 1.5, 15.0)

                return resp
            else:
                resp._is_captcha = False

            # Session health check — detect expired sessions on every response
            if (self._session_mgr and not self._reauth_in_progress
                    and not self._session_mgr.check_session(resp)):
                self._reauth_in_progress = True
                log.info(f"Session expired (detected on {method} {url}), re-authenticating...")
                if self._session_mgr.ensure_session(resp):
                    log.info("Re-authentication successful, retrying request")
                    self._reauth_in_progress = False
                    # Retry the original request with fresh session
                    self.stats["requests"] += 1
                    resp = self.session.request(method, url, **kwargs)
                self._reauth_in_progress = False

            self.stats["success"] += 1

            # Decay adaptive delay on success
            if self._adaptive_delay > 0:
                self._adaptive_delay = max(0, self._adaptive_delay - 0.1)

            # If we were in CAPTCHA backoff and got a clean response, recover
            if self._captcha_backoff:
                self._captcha_backoff = False

            return resp

        except requests.exceptions.ConnectionError as e:
            self.stats["errors"] += 1
            log.debug(f"{method} {url} -> ConnectionError: {e}")
            return None
        except requests.exceptions.Timeout:
            self.stats["timeouts"] += 1
            log.debug(f"{method} {url} -> Timeout")
            return None
        except requests.exceptions.RequestException as e:
            self.stats["errors"] += 1
            log.debug(f"{method} {url} -> Error: {e}")
            return None

    def is_same_scope(self, url, target_url, scope="domain"):
        """Check if a URL is within the crawl scope."""
        try:
            target_parsed = urlparse(target_url)
            url_parsed = urlparse(url)
        except Exception:
            return False

        if scope == "strict":
            # Same scheme + netloc + path prefix
            return (url_parsed.scheme == target_parsed.scheme and
                    url_parsed.netloc == target_parsed.netloc and
                    url_parsed.path.startswith(target_parsed.path))
        elif scope == "domain":
            # Same netloc (host:port)
            return url_parsed.netloc == target_parsed.netloc
        elif scope == "subdomain":
            # Same base domain (e.g., api.example.com and www.example.com both match example.com)
            target_domain = _extract_base_domain(target_parsed.netloc)
            url_domain = _extract_base_domain(url_parsed.netloc)
            return target_domain == url_domain
        return False


def _is_captcha_response(resp):
    """Detect if a response is a CAPTCHA challenge page instead of real content.

    Catches: Cloudflare JS challenges, reCAPTCHA, hCaptcha, Turnstile,
    and generic/custom CAPTCHA implementations.
    """
    if resp is None:
        return False

    # Cloudflare challenge pages return 403 or 503 with specific headers
    if resp.status_code in (403, 503):
        server = resp.headers.get("Server", "").lower()
        if "cloudflare" in server:
            body = resp.text[:3000].lower()
            if any(s in body for s in [
                "checking your browser", "just a moment",
                "cf-browser-verification", "challenge-platform",
                "ray id", "cf_chl_opt",
            ]):
                return True

    # Only scan body for 200 responses if they look suspicious
    # (CAPTCHA pages often return 200 with a challenge form)
    body = resp.text[:5000].lower() if resp.text else ""
    if not body:
        return False

    # Known CAPTCHA service markers
    captcha_markers = [
        # Google reCAPTCHA
        "recaptcha", "g-recaptcha", "grecaptcha",
        "www.google.com/recaptcha",
        "www.gstatic.com/recaptcha",
        # hCaptcha
        "hcaptcha", "h-captcha",
        "hcaptcha.com",
        # Cloudflare Turnstile
        "cf-turnstile", "challenges.cloudflare.com/turnstile",
        # Generic CAPTCHA indicators
        "captcha", "solve the challenge",
        "verify you are human", "verify you're human",
        "are you a robot", "are you human",
        "prove you are not a robot",
        "bot detection", "bot protection",
        "human verification",
    ]

    # Count how many markers match — a single "captcha" in a page about
    # CAPTCHAs (like a blog post) shouldn't trigger, but a page with
    # multiple markers (form + script + message) is a real challenge.
    hits = sum(1 for marker in captcha_markers if marker in body)

    # 2+ markers = almost certainly a CAPTCHA page
    if hits >= 2:
        return True

    # Single "captcha" hit + it's a short page (challenge pages are small)
    if hits == 1 and len(body) < 3000:
        return True

    return False


def _extract_base_domain(netloc):
    """Extract base domain from netloc. Handles .onion domains."""
    host = netloc.split(":")[0]
    parts = host.split(".")
    if host.endswith(".onion"):
        return host  # .onion addresses are already the full domain
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host
