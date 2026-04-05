"""Reversible data sanitizer for recon output.

Replaces sensitive values (IPs, domains, tokens, PII, file paths, etc.)
with consistent placeholders. Maintains a bidirectional mapping so
AI-generated findings can be de-sanitized back to real values.
"""

import re
import json
from collections import OrderedDict
from urllib.parse import urlparse


class Sanitizer:
    """Replaces sensitive data with consistent, reversible placeholders."""

    def __init__(self, target_domain=None):
        self.target_domain = target_domain
        self._map = OrderedDict()       # placeholder → real value
        self._reverse = {}              # real value → placeholder
        self._counters = {}             # type → next index

        # Compiled patterns for detection
        self._ip_re = re.compile(
            r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
        )
        self._email_re = re.compile(
            r'\b([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})\b'
        )
        self._token_re = re.compile(
            r'(?i)((?:session|token|auth|cookie|jwt|bearer|api[_\-]?key|secret|password|passwd|pwd)'
            r'[=:\s]+\S{8,})'
        )
        self._path_re = re.compile(
            r'(/(?:var/www|home/\w+|opt|srv|etc|usr)/[^\s\'"<>]+)'
        )
        self._win_path_re = re.compile(
            r'([A-Z]:\\(?:inetpub|Users|Program Files)[^\s\'"<>]*)'
        )
        self._connstr_re = re.compile(
            r'(?i)((?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis|jdbc:[a-z]+)://[^\s\'"<>]+)'
        )
        self._aws_key_re = re.compile(r'(A[SK]IA[0-9A-Z]{16})')
        self._jwt_re = re.compile(
            r'(eyJ[A-Za-z0-9\-_=]+\.eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_.+/=]*)'
        )
        # Internal/infrastructure hostnames (common in leaked configs)
        self._internal_host_re = re.compile(
            r'\b([a-zA-Z0-9\-]+\.(?:internal|local|corp|intranet|private'
            r'|staging|dev|test|prod|infra)\b'
            r'(?:\.[a-zA-Z]{2,})?)'
        )
        # Hostname patterns like db-prod-01.something, cache-01.something
        self._infra_host_re = re.compile(
            r'\b((?:db|cache|redis|mongo|elastic|kibana|grafana|jenkins'
            r'|gitlab|jira|sentry|app|web|api|mail|smtp|proxy|lb|cdn'
            r'|queue|worker|node|master|slave|primary|replica'
            r')[a-zA-Z0-9\-]*\.[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})\b'
        )

        # Pre-register the target domain if provided
        if target_domain:
            self._register(target_domain, "DOMAIN")

    def _next_id(self, category):
        idx = self._counters.get(category, 0) + 1
        self._counters[category] = idx
        return idx

    def _register(self, real_value, category):
        """Register a real value and return its placeholder."""
        if real_value in self._reverse:
            return self._reverse[real_value]
        idx = self._next_id(category)
        placeholder = f"{category}_{idx}"
        self._map[placeholder] = real_value
        self._reverse[real_value] = placeholder
        return placeholder

    def sanitize_text(self, text):
        """Sanitize a block of text, replacing all sensitive values."""
        if not text:
            return text

        # Order matters — more specific patterns first to avoid partial matches

        # Connection strings (before IPs/domains, since they contain both)
        for match in self._connstr_re.finditer(text):
            val = match.group(1)
            placeholder = self._register(val, "CONNSTR")
            text = text.replace(val, placeholder)

        # JWTs
        for match in self._jwt_re.finditer(text):
            val = match.group(1)
            placeholder = self._register(val, "JWT")
            text = text.replace(val, placeholder)

        # AWS keys
        for match in self._aws_key_re.finditer(text):
            val = match.group(1)
            placeholder = self._register(val, "AWS_KEY")
            text = text.replace(val, placeholder)

        # Email addresses (before domain replacement so we catch full emails)
        for match in self._email_re.finditer(text):
            email = match.group(1)
            placeholder = self._register(email, "EMAIL")
            text = text.replace(email, placeholder)

        # Domains — sanitize the target domain and any subdomains
        if self.target_domain:
            # Match subdomains too: api.target.com, admin.target.com
            domain_re = re.compile(
                r'\b([a-zA-Z0-9\-]+\.)?' + re.escape(self.target_domain) + r'\b'
            )
            for match in domain_re.finditer(text):
                full = match.group(0)
                if full not in self._reverse:
                    sub = match.group(1) or ""
                    if sub:
                        placeholder = self._register(
                            full, f"SUBDOMAIN"
                        )
                    else:
                        placeholder = self._reverse.get(full)
                        if not placeholder:
                            placeholder = self._register(full, "DOMAIN")
                text = text.replace(full, self._reverse.get(full, full))

        # Internal/infrastructure hostnames
        for pattern in [self._internal_host_re, self._infra_host_re]:
            for match in pattern.finditer(text):
                host = match.group(1)
                if host not in self._reverse:
                    self._register(host, "INT_HOST")
                text = text.replace(host, self._reverse.get(host, host))

        # IPs
        for match in self._ip_re.finditer(text):
            ip = match.group(1)
            # Skip already-replaced or loopback
            if ip.startswith(("DOMAIN", "HOST", "SUBDOMAIN", "INT_HOST")) or ip == "127.0.0.1":
                continue
            placeholder = self._register(ip, "HOST")
            text = text.replace(ip, placeholder)

        # Server file paths
        for match in self._path_re.finditer(text):
            path = match.group(1)
            placeholder = self._register(path, "PATH")
            text = text.replace(path, placeholder)

        # Windows paths
        for match in self._win_path_re.finditer(text):
            path = match.group(1)
            placeholder = self._register(path, "WIN_PATH")
            text = text.replace(path, placeholder)

        return text

    def sanitize_url(self, url):
        """Sanitize a URL — replace domain/IP but preserve path structure."""
        if not url:
            return url
        try:
            parsed = urlparse(url)
            host = parsed.hostname or ""
            port_str = f":{parsed.port}" if parsed.port else ""

            if host:
                if host in self._reverse:
                    sanitized_host = self._reverse[host]
                else:
                    sanitized_host = self._register(host, "HOST")
                # Replace just the netloc, preserving scheme and path
                old_netloc = parsed.netloc
                new_netloc = sanitized_host + port_str
                return url.replace(old_netloc, new_netloc, 1)
        except Exception:
            pass
        return self.sanitize_text(url)

    def sanitize_headers(self, headers):
        """Sanitize HTTP headers — redact auth/session, preserve security headers."""
        if not headers:
            return headers

        sanitized = {}
        # Headers to fully redact (value is sensitive)
        redact_names = {
            "authorization", "cookie", "set-cookie", "x-api-key",
            "x-auth-token", "x-csrf-token", "x-xsrf-token",
        }
        # Headers to preserve as-is (useful for analysis)
        preserve_names = {
            "content-type", "content-length", "server", "x-powered-by",
            "x-frame-options", "x-content-type-options", "x-xss-protection",
            "content-security-policy", "strict-transport-security",
            "access-control-allow-origin", "access-control-allow-methods",
            "access-control-allow-headers", "referrer-policy",
            "permissions-policy", "cache-control", "pragma",
            "transfer-encoding", "vary", "location",
        }

        for name, value in headers.items():
            lower = name.lower()
            if lower in redact_names:
                sanitized[name] = "REDACTED"
            elif lower in preserve_names:
                # Preserve but sanitize any embedded domains/IPs
                sanitized[name] = self.sanitize_text(str(value))
            else:
                sanitized[name] = self.sanitize_text(str(value))

        return sanitized

    def sanitize_dict(self, data):
        """Recursively sanitize a dictionary."""
        if isinstance(data, dict):
            return {k: self.sanitize_dict(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self.sanitize_dict(item) for item in data]
        elif isinstance(data, str):
            return self.sanitize_text(data)
        return data

    def desanitize(self, text):
        """Replace placeholders back with real values."""
        if not text:
            return text
        # Replace longest placeholders first to avoid partial matches
        for placeholder in sorted(self._map.keys(), key=len, reverse=True):
            text = text.replace(placeholder, self._map[placeholder])
        return text

    def get_mapping(self):
        """Return the current placeholder→real mapping."""
        return dict(self._map)

    def save_mapping(self, path):
        """Save mapping to a JSON file (keep locally, never send to AI)."""
        with open(path, "w") as f:
            json.dump({
                "mapping": dict(self._map),
                "target_domain": self.target_domain,
            }, f, indent=2)

    @classmethod
    def load_mapping(cls, path):
        """Load a saved mapping for de-sanitization."""
        with open(path) as f:
            data = json.load(f)
        s = cls(target_domain=data.get("target_domain"))
        for placeholder, real in data["mapping"].items():
            s._map[placeholder] = real
            s._reverse[real] = placeholder
        return s
