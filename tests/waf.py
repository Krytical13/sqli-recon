"""
Simulated WAF + rate limiter middleware for the vulnerable test app.

Simulates real-world protections a scanner would encounter:
- Rate limiting (429 Too Many Requests) with per-IP tracking
- SQL injection pattern detection (403 Forbidden)
- Security headers on all responses
- Realistic error pages that mimic common WAF vendors
"""

import re
import time
import threading
from functools import wraps
from flask import request, Response, abort


# ---- Rate Limiter ----

class RateLimiter:
    """Token bucket rate limiter, per-IP."""

    def __init__(self, requests_per_minute=40, burst=10):
        self.rate = requests_per_minute / 60.0  # tokens per second
        self.burst = burst
        self._buckets = {}  # ip -> (tokens, last_time)
        self._lock = threading.Lock()

    def allow(self, ip):
        now = time.time()
        with self._lock:
            if ip not in self._buckets:
                self._buckets[ip] = (self.burst - 1, now)
                return True

            tokens, last_time = self._buckets[ip]
            elapsed = now - last_time
            tokens = min(self.burst, tokens + elapsed * self.rate)

            if tokens >= 1:
                self._buckets[ip] = (tokens - 1, now)
                return True
            else:
                self._buckets[ip] = (tokens, now)
                return False


# ---- WAF Pattern Detection ----

# Patterns inspired by ModSecurity CRS / Cloudflare WAF rules.
# These catch common SQLi payloads but NOT normal browsing.

WAF_PATTERNS = [
    # Union-based injection
    (re.compile(r"union\s+(all\s+)?select", re.I), "union-select"),
    # Boolean-based injection
    (re.compile(r"(\bor\b|\band\b)\s+[\d'\"]\s*[=<>]", re.I), "boolean-injection"),
    (re.compile(r"'\s*(or|and)\s+'", re.I), "quoted-boolean"),
    # Stacked queries
    (re.compile(r";\s*(select|insert|update|delete|drop|alter|create|exec)", re.I), "stacked-query"),
    # Comment injection
    (re.compile(r"(--|#|/\*)\s*$", re.I), "comment-terminator"),
    (re.compile(r"/\*.*?\*/", re.I), "inline-comment"),
    # Sleep / benchmark (time-based)
    (re.compile(r"(sleep|benchmark|waitfor\s+delay|pg_sleep)\s*\(", re.I), "time-based"),
    # Information extraction
    (re.compile(r"(information_schema|sys\.tables|sqlite_master|pg_catalog)", re.I), "schema-probe"),
    # Common payloads
    (re.compile(r"'\s*;\s*--", re.I), "quote-semicolon-comment"),
    (re.compile(r"1\s*=\s*1", re.I), "tautology"),
    (re.compile(r"'\s*=\s*'", re.I), "quote-equality"),
    # Hex encoding attempts
    (re.compile(r"0x[0-9a-f]{8,}", re.I), "hex-encoded"),
    # CHAR() encoding
    (re.compile(r"char\s*\(\s*\d+", re.I), "char-encoded"),
    # Concatenation tricks
    (re.compile(r"concat\s*\(", re.I), "concat-function"),
    # Extractvalue / UpdateXML (MySQL)
    (re.compile(r"(extractvalue|updatexml)\s*\(", re.I), "xml-function"),
]


def check_waf(value):
    """Check a string against WAF patterns. Returns (blocked, rule_name) or (False, None)."""
    if not value:
        return False, None
    for pattern, rule_name in WAF_PATTERNS:
        if pattern.search(value):
            return True, rule_name
    return False, None


def check_request_waf():
    """Check all parts of the current request against WAF rules."""
    # Check query string parameters
    for key, value in request.args.items():
        blocked, rule = check_waf(value)
        if blocked:
            return True, rule, f"query:{key}"
        blocked, rule = check_waf(key)
        if blocked:
            return True, rule, f"query-key:{key}"

    # Check form data
    if request.form:
        for key, value in request.form.items():
            blocked, rule = check_waf(value)
            if blocked:
                return True, rule, f"body:{key}"

    # Check JSON body
    if request.is_json:
        data = request.get_json(silent=True)
        if data and isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, str):
                    blocked, rule = check_waf(value)
                    if blocked:
                        return True, rule, f"json:{key}"

    # Check URL path (for path-based injection)
    blocked, rule = check_waf(request.path)
    if blocked:
        return True, rule, "path"

    # Check cookies
    for key, value in request.cookies.items():
        blocked, rule = check_waf(value)
        if blocked:
            return True, rule, f"cookie:{key}"

    # Check common injectable headers
    for header in ["Referer", "User-Agent", "X-Forwarded-For"]:
        value = request.headers.get(header, "")
        blocked, rule = check_waf(value)
        if blocked:
            return True, rule, f"header:{header}"

    return False, None, None


# ---- WAF Response Pages ----

WAF_BLOCK_PAGE = """<!DOCTYPE html>
<html>
<head><title>403 Forbidden</title></head>
<body>
<center><h1>403 Forbidden</h1></center>
<hr>
<center>Access Denied</center>
<p style="text-align:center;color:#666;font-size:12px">
Your request was blocked by the web application firewall.<br>
Rule: {rule_id}<br>
If you believe this is an error, contact the site administrator.<br>
Reference ID: {ref_id}
</p>
</body>
</html>"""

RATE_LIMIT_PAGE = """<!DOCTYPE html>
<html>
<head><title>429 Too Many Requests</title></head>
<body>
<center><h1>429 Too Many Requests</h1></center>
<hr>
<center>Rate limit exceeded. Please slow down.</center>
<p style="text-align:center;color:#666;font-size:12px">
You have exceeded the maximum request rate.<br>
Please wait before making additional requests.<br>
Retry-After: {retry_after} seconds
</p>
</body>
</html>"""


# ---- Flask Middleware Registration ----

def register_waf(app, requests_per_minute=40, burst=10, waf_enabled=True):
    """Register WAF + rate limiting middleware on a Flask app."""

    limiter = RateLimiter(requests_per_minute=requests_per_minute, burst=burst)
    stats = {"blocked": 0, "rate_limited": 0, "allowed": 0}

    @app.before_request
    def waf_middleware():
        ip = request.remote_addr or "127.0.0.1"

        # Rate limiting check
        if not limiter.allow(ip):
            stats["rate_limited"] += 1
            retry_after = 5
            resp = Response(
                RATE_LIMIT_PAGE.format(retry_after=retry_after),
                status=429,
                mimetype="text/html",
            )
            resp.headers["Retry-After"] = str(retry_after)
            return resp

        # WAF check
        if waf_enabled:
            blocked, rule, location = check_request_waf()
            if blocked:
                stats["blocked"] += 1
                import hashlib
                ref_id = hashlib.md5(
                    f"{time.time()}{ip}{rule}".encode()
                ).hexdigest()[:16]
                return Response(
                    WAF_BLOCK_PAGE.format(rule_id=rule, ref_id=ref_id),
                    status=403,
                    mimetype="text/html",
                )

        stats["allowed"] += 1

    @app.after_request
    def add_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Server"] = "nginx"  # Hide Flask
        response.headers.pop("X-Powered-By", None)
        return response

    @app.route("/waf-stats")
    def waf_stats():
        """Internal endpoint to check WAF statistics."""
        return {
            "blocked": stats["blocked"],
            "rate_limited": stats["rate_limited"],
            "allowed": stats["allowed"],
        }

    return stats
