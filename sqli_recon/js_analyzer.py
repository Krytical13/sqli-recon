"""JavaScript file analyzer - extracts API endpoints, routes, and parameters from JS bundles."""

import re
import logging
from urllib.parse import urljoin, urlparse, parse_qs

from sqli_recon.models import Endpoint, Parameter, ParamLocation, Source

log = logging.getLogger(__name__)


# Patterns adapted from LinkFinder + custom additions for modern frameworks.
# Each pattern tries to capture URL-like strings from JS source.

ENDPOINT_PATTERNS = [
    # Quoted strings that look like paths: "/api/users", '/v1/products'
    re.compile(
        r"""(?:['"`])(/(?:api|rest|graphql|v[0-9]|internal|admin|auth|search|data)"""
        r"""(?:/[a-zA-Z0-9_\-{}.:]+)*)(?:['"`])""",
        re.I,
    ),

    # Generic relative paths starting with /  (at least 2 segments to reduce noise)
    re.compile(
        r"""(?:['"`])(\/[a-zA-Z0-9_\-]+\/[a-zA-Z0-9_\-/.{}:]+)(?:['"`])""",
    ),

    # Full URLs
    re.compile(
        r"""(?:['"`])(https?://[a-zA-Z0-9_\-.:]+(?:/[a-zA-Z0-9_\-/.{}:?&=]*)?)(?:['"`])""",
        re.I,
    ),

    # Template literals with embedded paths: `/api/users/${id}`
    re.compile(
        r"""`(/(?:api|rest|v[0-9]|admin|auth|search)[^`]*)`""",
        re.I,
    ),

    # String concatenation: "/api/users/" + id or '/api/' + endpoint
    re.compile(
        r"""['"](/(?:api|rest|v[0-9]|admin|auth)[/a-zA-Z0-9_\-]*)['"]\s*\+""",
        re.I,
    ),

    # Webpack/minified: e="/api/v1/users",t="/api/v1/products" (short variable assignments)
    re.compile(
        r"""[=,]\s*['"](/(?:api|rest|v[0-9])[/a-zA-Z0-9_\-{}.:]+)['"]""",
        re.I,
    ),
]

# Patterns for fetch/XHR/axios calls - captures the URL argument
FETCH_PATTERNS = [
    # fetch("/api/endpoint") or fetch(`/api/endpoint`)
    re.compile(
        r"""fetch\s*\(\s*['"`]([^'"`\s]+)['"`]""", re.I,
    ),
    # axios.get/post/put/delete/patch("/api/endpoint")
    re.compile(
        r"""axios\s*\.\s*(?:get|post|put|delete|patch|head|options|request)\s*\(\s*['"`]([^'"`\s]+)['"`]""",
        re.I,
    ),
    # $.ajax({url: "/api/endpoint"})
    re.compile(
        r"""\$\s*\.\s*(?:ajax|get|post|getJSON|put)\s*\(\s*(?:\{[^}]*url\s*:\s*)?['"`]([^'"`\s]+)['"`]""",
        re.I,
    ),
    # XMLHttpRequest .open("GET", "/api/endpoint")
    re.compile(
        r"""\.open\s*\(\s*['"`](?:GET|POST|PUT|DELETE|PATCH)['"`]\s*,\s*['"`]([^'"`\s]+)['"`]""",
        re.I,
    ),
    # http.get/post/put/delete (Angular HttpClient, generic)
    re.compile(
        r"""(?:http|this\.\w+)\s*\.\s*(?:get|post|put|delete|patch|request)\s*(?:<[^>]*>)?\s*\(\s*['"`]([^'"`\s]+)['"`]""",
        re.I,
    ),
]

# Patterns for extracting route definitions (React Router, Vue Router, Express, etc.)
ROUTE_PATTERNS = [
    # path: "/users/:id" or path: '/products/:slug'
    re.compile(
        r"""path\s*:\s*['"`]([^'"`]+)['"`]""", re.I,
    ),
    # app.get("/api/users", ...) or router.post("/api/login", ...)
    re.compile(
        r"""(?:app|router)\s*\.\s*(?:get|post|put|delete|patch|all|use)\s*\(\s*['"`]([^'"`]+)['"`]""",
        re.I,
    ),
    # @Get("/endpoint"), @Post("/endpoint") - NestJS / decorators
    re.compile(
        r"""@(?:Get|Post|Put|Delete|Patch|All|Head|Options)\s*\(\s*['"`]([^'"`]+)['"`]""",
    ),
]

# API base URL patterns
BASE_URL_PATTERNS = [
    re.compile(
        r"""(?:(?:api|base|backend|server)[_\-]?(?:url|base|endpoint|host|root|prefix)"""
        r"""|(?:API|BASE|BACKEND|SERVER)[_\-]?(?:URL|BASE|ENDPOINT|HOST|ROOT|PREFIX))\s*[:=]\s*['"`]([^'"`]+)['"`]""",
    ),
]

# Query parameter patterns in template literals and string concatenation
QUERY_PARAM_PATTERNS = [
    # ?key=value or &key=value in strings
    re.compile(r"""[?&]([a-zA-Z_][a-zA-Z0-9_]*)\s*="""),
    # URLSearchParams.append("key", ...) or .set("key", ...)
    re.compile(
        r"""(?:URLSearchParams|searchParams|params|query)\s*\.\s*(?:append|set|get|has)\s*\(\s*['"`]([a-zA-Z_][a-zA-Z0-9_]*)['"`]""",
        re.I,
    ),
    # {key: value} in request bodies or params objects
    re.compile(
        r"""(?:params|query|data|body|payload|fields)\s*[:=]\s*\{[^}]*?['"]?([a-zA-Z_][a-zA-Z0-9_]*)['"]?\s*:""",
        re.I,
    ),
]

# ---- POST / JSON body detection ----
# These patterns capture the FULL fetch/axios call context to extract method + body fields.
# They use re.DOTALL to span multiple lines in minified or formatted JS.

FETCH_CONTEXT_PATTERNS = [
    # fetch("/url", { method: "POST", body: JSON.stringify({key: val, key2: val2}) })
    re.compile(
        r"""fetch\s*\(\s*['"`]([^'"`\s]+)['"`]\s*,\s*(\{.{0,500}?\})\s*\)""",
        re.I | re.DOTALL,
    ),
    # axios.post("/url", {key: val, key2: val2})
    re.compile(
        r"""axios\s*\.\s*(post|put|patch|delete)\s*\(\s*['"`]([^'"`\s]+)['"`]\s*,\s*(\{.{0,500}?\})""",
        re.I | re.DOTALL,
    ),
    # $.post("/url", {key: val}) or $.ajax({url: "/url", method: "POST", data: {key: val}})
    re.compile(
        r"""\$\s*\.\s*(post|put)\s*\(\s*['"`]([^'"`\s]+)['"`]\s*,\s*(\{.{0,500}?\})""",
        re.I | re.DOTALL,
    ),
]

# Extract method from fetch options: { method: "POST" }
FETCH_METHOD_RE = re.compile(r"""method\s*:\s*['"`](GET|POST|PUT|PATCH|DELETE)['"`]""", re.I)

# Extract JSON field names AND values from objects
# Matches: key: "value", key: 'value', "key": value, key: 50
JSON_FIELD_VALUE_RE = re.compile(
    r"""['"]?([a-zA-Z_]\w*)['"]?\s*:\s*(?:['"]([^'"]*?)['"]|(\d+(?:\.\d+)?)|(\w+))"""
)
# Simpler: just field names (fallback)
JSON_FIELDS_RE = re.compile(r"""['"]?([a-zA-Z_]\w*)['"]?\s*:""")

# Detect JSON content type in fetch headers
JSON_CONTENT_TYPE_RE = re.compile(r"""['"](application/json)['"]""", re.I)

# Strings that are NOT endpoints (false positive reduction)
FALSE_POSITIVE_PATTERNS = [
    re.compile(r"^/[*]"),  # JS comment
    re.compile(r"^\./"),  # Relative import
    re.compile(r"^/\w+\.\w+$"),  # Single file like /style.css
    re.compile(r"node_modules|webpack|__webpack|\.chunk\.|\.bundle\."),
    re.compile(r"^/[a-z]{1,3}$"),  # Too short
    re.compile(r"^/(en|fr|de|es|it|pt|ru|ja|ko|zh|ar|nl|sv|no|da|fi|pl|tr|cs|el|he|hi|th|vi|id|ms)/"),  # Locale prefixes only
]


class JsAnalyzer:
    """Analyzes JavaScript files to discover hidden API endpoints and parameters."""

    def __init__(self, client, target_url):
        self.client = client
        self.target_url = target_url
        self._seen = set()

    def analyze(self, js_urls, progress_callback=None):
        """
        Download and analyze JS files. Returns list of discovered Endpoints.
        """
        endpoints = []
        base_urls = set()

        for i, js_url in enumerate(js_urls):
            if progress_callback and (i + 1) % 3 == 0:
                progress_callback(i + 1, len(js_urls))

            resp = self.client.get(js_url)
            if resp is None or resp.status_code != 200:
                continue

            js_text = resp.text
            if len(js_text) > 5_000_000:  # Skip files > 5MB (likely vendor bundles)
                log.debug(f"Skipping large JS file: {js_url} ({len(js_text)} bytes)")
                continue

            # Light deobfuscation for minified JS — add newlines at statement
            # boundaries so regex patterns can match across logical lines
            js_text = _deobfuscate(js_text)

            # Find base URLs first
            for pattern in BASE_URL_PATTERNS:
                for match in pattern.finditer(js_text):
                    base_url = match.group(1).rstrip("/")
                    if base_url.startswith(("http://", "https://")):
                        base_urls.add(base_url)

            # ---- Phase A: Extract POST/JSON endpoints with full context ----
            post_endpoints = self._extract_post_endpoints(js_text, js_url, base_urls)
            for ep in post_endpoints:
                key = self._dedup_key(ep)
                if key not in self._seen:
                    self._seen.add(key)
                    endpoints.append(ep)

            # ---- Phase B: Extract URL-only endpoints (GET by default) ----
            found_paths = set()

            for patterns in [ENDPOINT_PATTERNS, FETCH_PATTERNS, ROUTE_PATTERNS]:
                for pattern in patterns:
                    for match in pattern.finditer(js_text):
                        path = match.group(1).strip()
                        if path and not self._is_false_positive(path):
                            found_paths.add(path)

            # Extract standalone query parameters referenced in JS
            found_params = set()
            for pattern in QUERY_PARAM_PATTERNS:
                for match in pattern.finditer(js_text):
                    param_name = match.group(1)
                    if len(param_name) > 1:  # Skip single-char vars
                        found_params.add(param_name)

            # Resolve paths to full URLs and create endpoints
            for path in found_paths:
                resolved_urls = self._resolve_path(path, js_url, base_urls)
                for url in resolved_urls:
                    ep = self._url_to_endpoint(url, found_params)
                    if ep and self._dedup_key(ep) not in self._seen:
                        self._seen.add(self._dedup_key(ep))
                        endpoints.append(ep)

        if progress_callback:
            progress_callback(len(js_urls), len(js_urls))

        return endpoints

    def _is_false_positive(self, path):
        """Check if a path is likely a false positive."""
        for pattern in FALSE_POSITIVE_PATTERNS:
            if pattern.search(path):
                return True
        # Skip paths that are just static file references
        ext = path.rsplit(".", 1)[-1].lower() if "." in path.split("/")[-1] else ""
        if ext in {"js", "css", "png", "jpg", "jpeg", "gif", "svg", "ico",
                    "woff", "woff2", "ttf", "eot", "map", "json", "xml"}:
            return True
        return False

    def _resolve_path(self, path, source_url, base_urls):
        """Resolve a path to full URL(s)."""
        urls = []

        if path.startswith(("http://", "https://")):
            if self.client.is_same_scope(path, self.target_url, "domain"):
                urls.append(path)
        elif path.startswith("/"):
            # Absolute path - resolve against target
            url = urljoin(self.target_url, path)
            urls.append(url)
            # Also try against discovered base URLs
            for base in base_urls:
                if self.client.is_same_scope(base, self.target_url, "subdomain"):
                    urls.append(base + path)
        else:
            # Relative path - resolve against JS file's directory
            url = urljoin(source_url, path)
            if self.client.is_same_scope(url, self.target_url, "domain"):
                urls.append(url)

        # Clean up route parameters (:id -> {id} for readability, keep for detection)
        cleaned = []
        for url in urls:
            cleaned.append(re.sub(r":([a-zA-Z_]\w*)", r"{\1}", url))
        return cleaned

    def _extract_post_endpoints(self, js_text, source_url, base_urls):
        """Extract POST/PUT/PATCH endpoints with JSON body field names."""
        endpoints = []

        # Pattern 1: fetch("/url", { method: "POST", body: JSON.stringify({...}) })
        for pattern in FETCH_CONTEXT_PATTERNS:
            for match in pattern.finditer(js_text):
                groups = match.groups()

                if len(groups) == 2:
                    # fetch(url, options) pattern
                    url_str, options_str = groups
                    method_match = FETCH_METHOD_RE.search(options_str)
                    method = method_match.group(1).upper() if method_match else "POST"
                elif len(groups) == 3:
                    # axios.post(url, data) or $.post(url, data) pattern
                    method = groups[0].upper()
                    url_str = groups[1]
                    options_str = groups[2]
                else:
                    continue

                if self._is_false_positive(url_str):
                    continue

                # Detect if JSON content type
                is_json = bool(JSON_CONTENT_TYPE_RE.search(options_str))

                # Extract JSON body fields from JSON.stringify({...}) or plain objects
                body_fields = self._extract_json_fields(options_str)

                if not body_fields:
                    continue

                # Resolve URL
                resolved = self._resolve_path(url_str, source_url, base_urls)
                for url in resolved:
                    params = []

                    # Add body fields as JSON params, preserving source values
                    body_parts = []
                    for field_name, field_value in body_fields:
                        ptype = "numeric" if field_value and field_value.isdigit() else "string"
                        params.append(Parameter(
                            name=field_name,
                            location=ParamLocation.JSON,
                            value=field_value,
                            param_type=ptype,
                        ))
                        if field_value:
                            if ptype == "numeric":
                                body_parts.append(f'"{field_name}": {field_value}')
                            else:
                                body_parts.append(f'"{field_name}": "{field_value}"')
                        else:
                            body_parts.append(f'"{field_name}": "test"')

                    # Also extract query params from the URL
                    parsed = urlparse(url)
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

                    # Route params
                    for rp in re.findall(r"\{(\w+)\}", parsed.path):
                        params.append(Parameter(
                            name=rp, location=ParamLocation.PATH,
                            value="", param_type="string",
                        ))

                    body_template = "{" + ", ".join(body_parts) + "}"

                    endpoints.append(Endpoint(
                        url=url,
                        method=method,
                        parameters=params,
                        content_type="application/json",
                        source=Source.JS,
                        body_template=body_template,
                    ))

        return endpoints

    def _extract_json_fields(self, text):
        """Extract field names and values from a JSON.stringify({...}) call or object literal.

        Returns list of (name, value) tuples. Values are preserved from the source
        so sqlmap request files use realistic data that won't break the target.
        """
        # First try to find JSON.stringify({...})
        stringify_match = re.search(
            r"JSON\.stringify\s*\(\s*\{([^}]{1,500})\}",
            text, re.I | re.DOTALL,
        )
        target = stringify_match.group(1) if stringify_match else text

        js_keywords = {
            "method", "headers", "body", "mode", "cache", "credentials",
            "redirect", "referrer", "integrity", "signal", "keepalive",
            "content", "type", "accept", "authorization",
            "true", "false", "null", "undefined", "var", "let", "const",
            "function", "return", "if", "else", "new", "this",
        }

        fields = []
        for match in JSON_FIELD_VALUE_RE.finditer(target):
            name = match.group(1)
            if name.lower() in js_keywords:
                continue
            # Pick the first non-None value group
            str_val = match.group(2)  # quoted string
            num_val = match.group(3)  # number
            ident_val = match.group(4)  # identifier (variable name)
            if str_val is not None:
                value = str_val
            elif num_val is not None:
                value = num_val
            elif ident_val and ident_val.lower() not in {"true", "false", "null", "undefined"}:
                value = ""  # Variable reference — can't resolve
            else:
                value = ""
            fields.append((name, value))

        return fields

    def _url_to_endpoint(self, url, extra_params=None):
        """Convert a URL to an Endpoint with detected parameters."""
        parsed = urlparse(url)
        params = []

        # Query string parameters
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

        # Route parameters like {id}, {slug}
        route_params = re.findall(r"\{(\w+)\}", parsed.path)
        for param_name in route_params:
            params.append(Parameter(
                name=param_name,
                location=ParamLocation.PATH,
                value="",
                param_type="string",
            ))

        return Endpoint(
            url=url,
            method="GET",
            parameters=params,
            source=Source.JS,
        )

    def _dedup_key(self, ep):
        return (ep.base_url, ep.method, frozenset(p.name for p in ep.parameters))


def _infer_type(value):
    if not value:
        return "string"
    if re.match(r"^\d+$", value):
        return "numeric"
    return "string"


def _deobfuscate(js_text):
    """Light deobfuscation/beautification for minified JavaScript.

    Doesn't fully parse — just adds whitespace at statement boundaries
    so regex patterns can match across what were single-line constructs.
    Also resolves common webpack patterns.
    """
    # Add newlines after semicolons and braces (basic beautification)
    # This helps patterns match in minified code like: a="/api/v1";b="/users"
    text = re.sub(r";(?=[^\s])", ";\n", js_text)

    # Resolve template literal interpolations: `/api/${version}/users` → /api/{version}/users
    text = re.sub(r"\$\{(\w+)\}", r"{\1}", text)

    # Decode common hex/unicode escapes in strings: \x2f → /
    def _hex_replace(m):
        try:
            return chr(int(m.group(1), 16))
        except ValueError:
            return m.group(0)
    text = re.sub(r"\\x([0-9a-fA-F]{2})", _hex_replace, text)
    text = re.sub(r"\\u([0-9a-fA-F]{4})", _hex_replace, text)

    return text
