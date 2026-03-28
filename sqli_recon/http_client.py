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

        # WAF/rate-limit tracking
        self.stats = {
            "requests": 0,
            "success": 0,
            "waf_blocks": 0,
            "rate_limited": 0,
            "errors": 0,
            "timeouts": 0,
        }

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

            self.stats["success"] += 1

            # Decay adaptive delay on success
            if self._adaptive_delay > 0:
                self._adaptive_delay = max(0, self._adaptive_delay - 0.1)

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


def _extract_base_domain(netloc):
    """Extract base domain from netloc. Handles .onion domains."""
    host = netloc.split(":")[0]
    parts = host.split(".")
    if host.endswith(".onion"):
        return host  # .onion addresses are already the full domain
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host
