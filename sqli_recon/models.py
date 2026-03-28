"""Data models for discovered endpoints, parameters, and findings."""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

# Param names that expect numeric values
_NUMERIC_PARAM_NAMES = re.compile(
    r"^(limit|offset|count|num|page|per_page|page_size|skip|take|"
    r"first|last|top|max|min|id|quantity|qty|amount|price|size|"
    r"width|height|age|year|month|day|port|timeout|retries)$",
    re.I,
)


def _placeholder_value(param):
    """Return a realistic placeholder value for a non-target parameter."""
    if param.value:
        return param.value
    if param.param_type == "numeric" or _NUMERIC_PARAM_NAMES.match(param.name):
        return 10
    return "test"


class ParamLocation(str, Enum):
    QUERY = "query"
    BODY = "body"
    JSON = "json"
    PATH = "path"
    HEADER = "header"
    COOKIE = "cookie"


class Source(str, Enum):
    CRAWL = "crawl"
    FORM = "form"
    JS = "js"
    FUZZ = "fuzz"
    ROBOTS = "robots"
    SITEMAP = "sitemap"
    API_BRUTE = "api_brute"
    HEADLESS = "headless"
    INLINE_JS = "inline_js"


@dataclass
class Parameter:
    name: str
    location: ParamLocation
    value: str = ""
    param_type: str = "string"  # string, numeric, uuid, boolean

    def __hash__(self):
        return hash((self.name, self.location))

    def __eq__(self, other):
        if not isinstance(other, Parameter):
            return False
        return self.name == other.name and self.location == other.location


@dataclass
class Endpoint:
    url: str
    method: str = "GET"
    parameters: List[Parameter] = field(default_factory=list)
    content_type: str = ""
    source: Source = Source.CRAWL
    status_code: int = 0
    response_headers: dict = field(default_factory=dict)
    body_template: str = ""  # For POST bodies (raw template)

    @property
    def base_url(self) -> str:
        """URL without query string."""
        parsed = urlparse(self.url)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))

    @property
    def domain(self) -> str:
        return urlparse(self.url).netloc

    def __hash__(self):
        return hash((self.base_url, self.method, tuple(sorted(p.name for p in self.parameters))))

    def __eq__(self, other):
        if not isinstance(other, Endpoint):
            return False
        return (self.base_url == other.base_url and
                self.method == other.method and
                set(self.parameters) == set(other.parameters))


@dataclass
class Finding:
    endpoint: Endpoint
    parameter: Parameter
    score: float = 0.0
    reasons: List[str] = field(default_factory=list)

    @property
    def risk_level(self) -> str:
        if self.score >= 0.7:
            return "HIGH"
        elif self.score >= 0.4:
            return "MEDIUM"
        return "LOW"

    def sqlmap_url(self) -> str:
        """Generate a sqlmap-compatible URL with injection marker."""
        parsed = urlparse(self.endpoint.url)
        if self.parameter.location == ParamLocation.QUERY:
            qs = parse_qs(parsed.query, keep_blank_values=True)
            parts = []
            for key, values in qs.items():
                val = values[0] if values else ""
                if key == self.parameter.name:
                    val = val + "*" if val else "*"
                parts.append(f"{key}={val}")
            # If the param wasn't in the original query string, add it
            if self.parameter.name not in qs:
                parts.append(f"{self.parameter.name}=*")
            new_query = "&".join(parts)
            return urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                               parsed.params, new_query, parsed.fragment))
        elif self.parameter.location == ParamLocation.PATH:
            # Mark the path segment with *
            return self.endpoint.url  # Caller handles path marking
        return self.endpoint.url

    def sqlmap_request(self) -> str:
        """Generate a raw HTTP request for sqlmap -r.

        For JSON bodies, marks ONLY the target parameter with * so sqlmap
        knows which field to inject into. Other fields get placeholder values.
        """
        parsed = urlparse(self.endpoint.url)
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"

        lines = [f"{self.endpoint.method} {path} HTTP/1.1"]
        lines.append(f"Host: {parsed.netloc}")

        if self.endpoint.content_type:
            lines.append(f"Content-Type: {self.endpoint.content_type}")

        lines.append("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        lines.append("Accept: */*")
        lines.append("Connection: close")

        # Add body for POST/PUT requests
        if self.endpoint.method in ("POST", "PUT", "PATCH"):
            body = self._build_request_body()
            lines.append(f"Content-Length: {len(body)}")
            lines.append("")
            lines.append(body)
        else:
            lines.append("")
            lines.append("")

        return "\r\n".join(lines)

    def _build_request_body(self):
        """Build the request body, marking only the target param with * for sqlmap.

        Non-target params get realistic placeholder values so the backend
        doesn't error on type mismatches (e.g., LIMIT needs a number, not 'test').
        """
        import json as json_mod

        if self.parameter.location == ParamLocation.JSON:
            body_obj = {}
            for p in self.endpoint.parameters:
                if p.location == ParamLocation.JSON:
                    if p.name == self.parameter.name:
                        body_obj[p.name] = p.value or "test"  # target param
                    else:
                        body_obj[p.name] = _placeholder_value(p)
            return json_mod.dumps(body_obj)

        elif self.parameter.location == ParamLocation.BODY:
            parts = []
            for p in self.endpoint.parameters:
                if p.location == ParamLocation.BODY:
                    val = p.value if p.value else _placeholder_value(p)
                    parts.append(f"{p.name}={val}")
            return "&".join(parts)

        if self.endpoint.body_template:
            return self.endpoint.body_template
        return f"{self.parameter.name}=test"
