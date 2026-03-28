"""
Headless browser crawler using Playwright.

Captures XHR/fetch API calls that JS-heavy SPAs make at runtime,
plus the fully-rendered DOM for link/form extraction.

Optional — only used when --headless flag is passed and playwright is installed.
"""

import re
import logging
from urllib.parse import urlparse, parse_qs, urljoin

from sqli_recon.models import Endpoint, Parameter, ParamLocation, Source

log = logging.getLogger(__name__)

try:
    from playwright.sync_api import sync_playwright
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False


class HeadlessCrawler:
    """
    Crawls pages with a real browser, capturing network requests and rendered DOM.

    Captures:
    - All XHR/fetch requests (URL, method, headers, POST body)
    - Links and forms from the fully-rendered DOM (after JS execution)
    """

    def __init__(self, target_url, max_pages=30, scope="domain",
                 proxy=None, timeout=30, verify_ssl=True):
        if not HAS_PLAYWRIGHT:
            raise RuntimeError(
                "Playwright is required for --headless mode.\n"
                "Install it with: pip install playwright && playwright install chromium"
            )

        self.target_url = target_url.rstrip("/")
        self.max_pages = max_pages
        self.scope = scope
        self.proxy = proxy
        self.timeout = timeout * 1000  # Playwright uses ms
        self.verify_ssl = verify_ssl

        self.visited = set()
        self.endpoints = []
        self._seen = set()
        self._captured_requests = []

    def crawl(self, urls_to_visit=None, progress_callback=None):
        """
        Visit pages with headless browser, capture network traffic.

        Args:
            urls_to_visit: List of URLs to visit. If None, starts from target_url.
            progress_callback: Called with (pages_done, total).

        Returns list of Endpoints discovered from network captures + rendered DOM.
        """
        if urls_to_visit is None:
            urls_to_visit = [self.target_url]

        launch_args = {"headless": True}
        if self.proxy:
            launch_args["proxy"] = {"server": self.proxy}

        with sync_playwright() as pw:
            browser = pw.chromium.launch(**launch_args)

            context_args = {
                "ignore_https_errors": not self.verify_ssl,
                "user_agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
            }
            context = browser.new_context(**context_args)
            page = context.new_page()

            # Intercept all network requests
            page.on("request", self._on_request)

            pages_done = 0
            queue = list(urls_to_visit)

            while queue and pages_done < self.max_pages:
                url = queue.pop(0)
                normalized = self._normalize(url)
                if normalized in self.visited:
                    continue
                self.visited.add(normalized)

                if not self._in_scope(url):
                    continue

                self._captured_requests.clear()

                try:
                    page.goto(url, wait_until="networkidle", timeout=self.timeout)
                except Exception as e:
                    log.debug(f"Headless navigation error for {url}: {e}")
                    try:
                        # Fallback: just wait for DOM
                        page.goto(url, wait_until="domcontentloaded", timeout=self.timeout)
                    except Exception:
                        continue

                pages_done += 1
                if progress_callback and pages_done % 2 == 0:
                    progress_callback(pages_done, len(queue))

                # Process captured network requests
                for req_data in self._captured_requests:
                    ep = self._request_to_endpoint(req_data)
                    if ep:
                        key = (ep.base_url, ep.method, frozenset(p.name for p in ep.parameters))
                        if key not in self._seen:
                            self._seen.add(key)
                            self.endpoints.append(ep)

                # Extract links from rendered DOM for further crawling
                try:
                    links = page.evaluate("""() => {
                        return Array.from(document.querySelectorAll('a[href], area[href]'))
                            .map(a => a.href)
                            .filter(h => h && !h.startsWith('javascript:') && !h.startsWith('mailto:'));
                    }""")
                    for link in links:
                        link = link.split("#")[0]
                        if self._in_scope(link) and self._normalize(link) not in self.visited:
                            queue.append(link)
                except Exception:
                    pass

                # Extract forms from rendered DOM
                try:
                    forms = page.evaluate("""() => {
                        return Array.from(document.querySelectorAll('form')).map(form => ({
                            action: form.action || window.location.href,
                            method: (form.method || 'GET').toUpperCase(),
                            fields: Array.from(form.querySelectorAll('input[name], select[name], textarea[name]'))
                                .map(f => ({name: f.name, value: f.value || '', type: f.type || 'text'}))
                        }));
                    }""")
                    for form_data in forms:
                        ep = self._form_to_endpoint(form_data, url)
                        if ep:
                            key = (ep.base_url, ep.method, frozenset(p.name for p in ep.parameters))
                            if key not in self._seen:
                                self._seen.add(key)
                                self.endpoints.append(ep)
                except Exception:
                    pass

            browser.close()

        if progress_callback:
            progress_callback(pages_done, 0)

        return self.endpoints

    def _on_request(self, request):
        """Playwright request interceptor — captures XHR/fetch details."""
        resource_type = request.resource_type
        if resource_type not in ("xhr", "fetch"):
            return

        url = request.url
        if not self._in_scope(url):
            return

        self._captured_requests.append({
            "url": url,
            "method": request.method,
            "headers": request.headers,
            "post_data": request.post_data,
            "resource_type": resource_type,
        })

    def _request_to_endpoint(self, req_data):
        """Convert a captured network request to an Endpoint."""
        url = req_data["url"]
        method = req_data["method"]
        headers = req_data.get("headers", {})
        post_data = req_data.get("post_data")
        content_type = headers.get("content-type", "")

        parsed = urlparse(url)
        params = []

        # Query string params
        if parsed.query:
            qs = parse_qs(parsed.query, keep_blank_values=True)
            for name, values in qs.items():
                value = values[0] if values else ""
                params.append(Parameter(
                    name=name,
                    location=ParamLocation.QUERY,
                    value=value,
                    param_type=_infer_type(value),
                ))

        # Path params (numeric IDs, UUIDs)
        for match in re.finditer(r"/(\d+)(?:/|$|\?)", parsed.path):
            params.append(Parameter(
                name=f"[path:{match.group(1)}]",
                location=ParamLocation.PATH,
                value=match.group(1),
                param_type="numeric",
            ))

        # POST body params
        body_template = ""
        if post_data and method in ("POST", "PUT", "PATCH"):
            if "application/json" in content_type:
                # Parse JSON body for field names
                try:
                    import json
                    body = json.loads(post_data)
                    if isinstance(body, dict):
                        for key, value in body.items():
                            params.append(Parameter(
                                name=key,
                                location=ParamLocation.JSON,
                                value=str(value) if not isinstance(value, (dict, list)) else "",
                                param_type=_infer_type(str(value)) if not isinstance(value, (dict, list)) else "string",
                            ))
                    body_template = post_data
                except (ValueError, TypeError):
                    pass
            elif "application/x-www-form-urlencoded" in content_type:
                qs = parse_qs(post_data, keep_blank_values=True)
                for name, values in qs.items():
                    value = values[0] if values else ""
                    params.append(Parameter(
                        name=name,
                        location=ParamLocation.BODY,
                        value=value,
                        param_type=_infer_type(value),
                    ))
                body_template = post_data

        if not params:
            return None

        return Endpoint(
            url=url,
            method=method,
            parameters=params,
            content_type=content_type,
            source=Source.HEADLESS,
            body_template=body_template,
        )

    def _form_to_endpoint(self, form_data, page_url):
        """Convert a rendered form to an Endpoint."""
        action = form_data.get("action", page_url)
        method = form_data.get("method", "GET")
        fields = form_data.get("fields", [])

        if not fields:
            return None
        if not self._in_scope(action):
            return None

        location = ParamLocation.QUERY if method == "GET" else ParamLocation.BODY
        params = []
        body_parts = []
        for field in fields:
            name = field.get("name", "")
            if not name:
                continue
            value = field.get("value", "")
            params.append(Parameter(
                name=name,
                location=location,
                value=value,
                param_type=_infer_type(value),
            ))
            body_parts.append(f"{name}={value}")

        if not params:
            return None

        return Endpoint(
            url=action,
            method=method,
            parameters=params,
            content_type="application/x-www-form-urlencoded" if method != "GET" else "",
            source=Source.HEADLESS,
            body_template="&".join(body_parts) if method != "GET" else "",
        )

    def _in_scope(self, url):
        """Check if URL is in scope."""
        try:
            target = urlparse(self.target_url)
            parsed = urlparse(url)
        except Exception:
            return False

        if self.scope == "domain":
            return parsed.netloc == target.netloc
        elif self.scope == "subdomain":
            t = target.netloc.split(".")
            p = parsed.netloc.split(".")
            return ".".join(t[-2:]) == ".".join(p[-2:])
        elif self.scope == "strict":
            return parsed.netloc == target.netloc and parsed.path.startswith(target.path)
        return False

    def _normalize(self, url):
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path.rstrip('/') or '/'}"


def _infer_type(value):
    if not value:
        return "string"
    if re.match(r"^\d+$", value):
        return "numeric"
    return "string"
