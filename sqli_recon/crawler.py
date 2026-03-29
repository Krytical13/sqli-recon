"""Active web crawler - spiders a target site to discover endpoints, forms, and parameters."""

import re
import logging
from collections import deque
from urllib.parse import (
    urlparse, urljoin, parse_qs, urlunparse, unquote,
)

from bs4 import BeautifulSoup

from sqli_recon.models import Endpoint, Parameter, ParamLocation, Source

log = logging.getLogger(__name__)

# Regex to detect likely path parameters (numeric IDs, UUIDs)
PATH_PARAM_NUMERIC = re.compile(r"/(\d+)(?:/|$|\?)")
PATH_PARAM_UUID = re.compile(
    r"/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:/|$|\?)", re.I
)
PATH_PARAM_HEX = re.compile(r"/([0-9a-f]{24,})(?:/|$|\?)", re.I)  # MongoDB ObjectIds etc.

# File extensions to skip
SKIP_EXTENSIONS = {
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp3", ".mp4", ".avi", ".mov", ".webm",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".zip", ".tar", ".gz", ".rar",
    ".map", ".min.js", ".min.css",
}

# JS file extensions to collect for analysis
JS_EXTENSIONS = {".js", ".mjs", ".jsx", ".ts", ".tsx"}


class Crawler:
    """BFS web crawler that discovers endpoints, forms, parameters, and JS files."""

    def __init__(self, client, target_url, max_depth=3, max_pages=200, scope="domain"):
        self.client = client
        self.target_url = target_url.rstrip("/")
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.scope = scope

        self.visited = set()
        self.endpoints = []
        self.js_urls = set()
        self._seen_endpoints = set()  # Dedup key: (base_url, method, frozenset(param_names))
        self._seen_surfaces = set()   # (path, frozenset(param_names)) — skip same-shape URLs

    def crawl(self, progress_callback=None, seed_urls=None):
        """
        Crawl the target site. Returns (endpoints, js_urls).

        Args:
            progress_callback: Called with (pages_crawled, queued_count).
            seed_urls: Extra URLs to inject into the crawl queue (e.g., from
                       platform-specific intelligence). These get crawled at
                       depth 1 alongside robots/sitemap discoveries.
        """
        queue = deque()
        queue.append((self.target_url, 0))
        self.visited.add(self._normalize_url(self.target_url))

        # Discover additional URLs from robots.txt and sitemaps, add to queue
        for url in self._discover_from_robots():
            normalized = self._normalize_url(url)
            if normalized not in self.visited:
                self.visited.add(normalized)
                queue.append((url, 1))

        # Platform-specific priority endpoints
        if seed_urls:
            for url in seed_urls:
                normalized = self._normalize_url(url)
                if normalized not in self.visited:
                    self.visited.add(normalized)
                    queue.append((url, 1))

        pages_crawled = 0

        while queue and pages_crawled < self.max_pages:
            url, depth = queue.popleft()

            if depth > self.max_depth:
                continue

            resp = self.client.get(url)
            if resp is None:
                continue

            # Skip CAPTCHA challenge pages — not real content
            if getattr(resp, '_is_captcha', False):
                continue

            pages_crawled += 1
            if progress_callback and pages_crawled % 5 == 0:
                progress_callback(pages_crawled, len(queue))

            content_type = resp.headers.get("Content-Type", "")

            # Extract endpoints from the URL itself (query params)
            self._extract_url_params(url, resp.status_code, dict(resp.headers), Source.CRAWL)

            # Detect path parameters
            self._detect_path_params(url, resp.status_code, dict(resp.headers))

            # Only parse HTML responses for links/forms
            if "text/html" not in content_type and "application/xhtml" not in content_type:
                continue

            try:
                soup = BeautifulSoup(resp.text, "lxml")
            except Exception:
                try:
                    soup = BeautifulSoup(resp.text, "html.parser")
                except Exception:
                    continue

            # Extract links
            for link_url in self._extract_links(soup, url):
                normalized = self._normalize_url(link_url)
                if normalized in self.visited:
                    continue
                if not self.client.is_same_scope(link_url, self.target_url, self.scope):
                    continue

                # Surface dedup: if we've already seen this path with the same
                # parameter names, skip it. /showthread.php?tid=1 and tid=500
                # are the same injection surface — no need to crawl both.
                link_parsed = urlparse(link_url)
                link_qs = parse_qs(link_parsed.query, keep_blank_values=True)
                surface_key = (link_parsed.path, frozenset(link_qs.keys()))
                if link_qs and surface_key in self._seen_surfaces:
                    continue
                if link_qs:
                    self._seen_surfaces.add(surface_key)

                self.visited.add(normalized)

                # Check if it's a JS file
                path = link_parsed.path.lower()
                if any(path.endswith(ext) for ext in JS_EXTENSIONS):
                    self.js_urls.add(link_url)
                    continue

                # Skip non-page resources
                if any(path.endswith(ext) for ext in SKIP_EXTENSIONS):
                    continue

                queue.append((link_url, depth + 1))

            # Extract forms
            self._extract_forms(soup, url)

            # Extract JS file references
            self._extract_js_refs(soup, url)

            # Extract inline script hints
            self._extract_inline_js(soup, url)

            # Look for HTML comments with hidden endpoints
            self._extract_comments(soup, url)

        if progress_callback:
            progress_callback(pages_crawled, 0)

        return self.endpoints, list(self.js_urls)

    def _normalize_url(self, url):
        """Normalize URL for dedup (strip fragment, sort query params)."""
        parsed = urlparse(url)
        # Sort query parameters for consistent comparison
        qs = parse_qs(parsed.query, keep_blank_values=True)
        sorted_qs = "&".join(
            f"{k}={v[0]}" for k, v in sorted(qs.items())
        ) if qs else ""
        return urlunparse((
            parsed.scheme, parsed.netloc, parsed.path.rstrip("/") or "/",
            "", sorted_qs, ""
        ))

    def _add_endpoint(self, endpoint):
        """Add endpoint if not a duplicate."""
        key = (
            endpoint.base_url,
            endpoint.method,
            frozenset(p.name for p in endpoint.parameters),
        )
        if key not in self._seen_endpoints:
            self._seen_endpoints.add(key)
            self.endpoints.append(endpoint)

    def _extract_url_params(self, url, status_code, headers, source):
        """Extract query string parameters from a URL."""
        parsed = urlparse(url)
        if not parsed.query:
            return
        qs = parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            return

        params = []
        for name, values in qs.items():
            value = values[0] if values else ""
            param_type = _infer_type(value)
            params.append(Parameter(
                name=name,
                location=ParamLocation.QUERY,
                value=value,
                param_type=param_type,
            ))

        self._add_endpoint(Endpoint(
            url=url,
            method="GET",
            parameters=params,
            source=source,
            status_code=status_code,
            response_headers=headers,
        ))

    def _detect_path_params(self, url, status_code, headers):
        """Detect numeric IDs, UUIDs, and hex strings in URL paths."""
        parsed = urlparse(url)
        path = parsed.path

        found = False
        for pattern, ptype in [
            (PATH_PARAM_NUMERIC, "numeric"),
            (PATH_PARAM_UUID, "uuid"),
            (PATH_PARAM_HEX, "string"),
        ]:
            for match in pattern.finditer(path):
                found = True
                # Create a path parameter with the matched segment
                value = match.group(1)
                # Build a "template" path marking the param location
                start, end = match.span(1)
                template_path = path[:start] + "{PATH_PARAM}" + path[end:]

                params = [Parameter(
                    name=f"[path:{value}]",
                    location=ParamLocation.PATH,
                    value=value,
                    param_type=ptype,
                )]

                # Include any query params too
                if parsed.query:
                    qs = parse_qs(parsed.query, keep_blank_values=True)
                    for name, values in qs.items():
                        val = values[0] if values else ""
                        params.append(Parameter(
                            name=name,
                            location=ParamLocation.QUERY,
                            value=val,
                            param_type=_infer_type(val),
                        ))

                self._add_endpoint(Endpoint(
                    url=url,
                    method="GET",
                    parameters=params,
                    source=Source.CRAWL,
                    status_code=status_code,
                    response_headers=headers,
                ))

    def _extract_links(self, soup, base_url):
        """Extract all link URLs from HTML."""
        urls = []
        for tag in soup.find_all(["a", "area", "link"]):
            href = tag.get("href")
            if not href:
                continue
            href = href.strip()
            if href.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
                continue
            absolute = urljoin(base_url, href)
            urls.append(absolute.split("#")[0])  # Strip fragment
        return urls

    def _extract_forms(self, soup, base_url):
        """Extract forms and their fields as POST/GET endpoints."""
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "GET").upper()
            enctype = form.get("enctype", "application/x-www-form-urlencoded")

            action_url = urljoin(base_url, action) if action else base_url

            if not self.client.is_same_scope(action_url, self.target_url, self.scope):
                continue

            params = []
            body_parts = []

            for inp in form.find_all(["input", "select", "textarea"]):
                name = inp.get("name")
                if not name:
                    continue

                value = inp.get("value", "")
                input_type = inp.get("type", "text").lower()

                # Infer param type from input attributes
                if input_type in ("number", "range"):
                    param_type = "numeric"
                elif input_type == "email":
                    param_type = "string"
                elif input_type == "hidden":
                    param_type = _infer_type(value)
                else:
                    param_type = _infer_type(value)

                location = ParamLocation.QUERY if method == "GET" else ParamLocation.BODY

                params.append(Parameter(
                    name=name,
                    location=location,
                    value=value,
                    param_type=param_type,
                ))
                body_parts.append(f"{name}={value}")

            if params:
                content_type = ""
                body_template = ""
                if method in ("POST", "PUT", "PATCH"):
                    content_type = enctype
                    body_template = "&".join(body_parts)

                self._add_endpoint(Endpoint(
                    url=action_url,
                    method=method,
                    parameters=params,
                    content_type=content_type,
                    source=Source.FORM,
                    body_template=body_template,
                ))

    def _extract_js_refs(self, soup, base_url):
        """Collect JavaScript file URLs for later analysis."""
        for script in soup.find_all("script", src=True):
            src = script["src"].strip()
            if src.startswith("data:"):
                continue
            absolute = urljoin(base_url, src)
            if self.client.is_same_scope(absolute, self.target_url, self.scope):
                self.js_urls.add(absolute)

    def _extract_inline_js(self, soup, base_url):
        """Look for API calls in inline <script> blocks."""
        fetch_pattern = re.compile(
            r"""(?:fetch|axios\.(?:get|post|put|patch|delete)|"""
            r"""\$\.(?:get|post|ajax|getJSON)|"""
            r"""XMLHttpRequest)\s*\(\s*['"`]([^'"`\s]+)['"`]""",
            re.I,
        )
        url_assignment = re.compile(
            r"""(?:api[_\-]?(?:url|base|endpoint|host)|base[_\-]?url|endpoint)\s*[:=]\s*['"`]([^'"`]+)['"`]""",
            re.I,
        )

        for script in soup.find_all("script", src=False):
            text = script.string
            if not text:
                continue

            for pattern in [fetch_pattern, url_assignment]:
                for match in pattern.finditer(text):
                    path = match.group(1)
                    if path.startswith(("http://", "https://", "//")):
                        url = path
                    elif path.startswith("/"):
                        url = urljoin(base_url, path)
                    else:
                        continue

                    if not self.client.is_same_scope(url, self.target_url, self.scope):
                        continue

                    self._extract_url_params(url, 0, {}, Source.INLINE_JS)
                    # Also add as bare endpoint if no params
                    parsed = urlparse(url)
                    if not parsed.query:
                        self._add_endpoint(Endpoint(
                            url=url,
                            method="GET",
                            source=Source.INLINE_JS,
                        ))

    def _extract_comments(self, soup, base_url):
        """Look for URLs and API hints in HTML comments."""
        from bs4 import Comment
        # Match full URLs and any absolute paths (not just /api/)
        url_pattern = re.compile(
            r'(?:https?://[^\s"\'<>]+|/[a-zA-Z][a-zA-Z0-9_\-/]*(?:\?[^\s"\'<>]*)?)',
            re.I,
        )

        for comment in soup.find_all(string=lambda t: isinstance(t, Comment)):
            for match in url_pattern.finditer(comment):
                url = match.group(0)
                if url.startswith("/"):
                    url = urljoin(base_url, url)
                if self.client.is_same_scope(url, self.target_url, self.scope):
                    self._extract_url_params(url, 0, {}, Source.CRAWL)
                    # Also add bare endpoints for path-only URLs
                    parsed = urlparse(url)
                    if not parsed.query:
                        self._add_endpoint(Endpoint(
                            url=url, method="GET", source=Source.CRAWL,
                        ))

    def _discover_from_robots(self):
        """Parse robots.txt and sitemaps. Returns list of discovered URLs to crawl."""
        discovered = []
        parsed = urlparse(self.target_url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"

        resp = self.client.get(robots_url)
        if resp is None or resp.status_code != 200:
            return discovered

        sitemap_urls = []
        for line in resp.text.splitlines():
            line = line.strip()
            if line.lower().startswith("sitemap:"):
                sitemap_url = line.split(":", 1)[1].strip()
                sitemap_urls.append(sitemap_url)
            elif line.lower().startswith(("allow:", "disallow:")):
                path = line.split(":", 1)[1].strip()
                if path and path != "/" and "*" not in path:
                    url = f"{parsed.scheme}://{parsed.netloc}{path}"
                    if self.client.is_same_scope(url, self.target_url, self.scope):
                        discovered.append(url)

        for sitemap_url in sitemap_urls:
            discovered.extend(self._discover_from_sitemap(sitemap_url))

        return discovered

    def _discover_from_sitemap(self, sitemap_url):
        """Parse XML sitemap. Returns list of discovered URLs."""
        discovered = []
        resp = self.client.get(sitemap_url)
        if resp is None or resp.status_code != 200:
            return discovered

        try:
            soup = BeautifulSoup(resp.text, "lxml-xml")
        except Exception:
            try:
                soup = BeautifulSoup(resp.text, "html.parser")
            except Exception:
                return discovered

        for loc in soup.find_all("loc"):
            url = loc.text.strip()
            if self.client.is_same_scope(url, self.target_url, self.scope):
                discovered.append(url)

        return discovered


def _infer_type(value):
    """Infer parameter type from its value."""
    if not value:
        return "string"
    if re.match(r"^\d+$", value):
        return "numeric"
    if re.match(r"^\d+\.\d+$", value):
        return "numeric"
    if re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", value, re.I):
        return "uuid"
    if re.match(r"^(true|false)$", value, re.I):
        return "boolean"
    return "string"
