"""Passive response analysis — greps every response for leaked secrets and info.

Patterns sourced from SecretFinder (m4ll0k), gf-patterns, and common
information disclosure signatures. No extra requests — just analyzes
what the crawler already fetched.
"""

import re
import logging
from urllib.parse import urlparse
from collections import defaultdict

log = logging.getLogger(__name__)


# ---- Pattern categories ----
# Each entry: (name, compiled_regex, severity)
# severity: "high" = credential/key, "medium" = internal info, "low" = interesting

PATTERNS = []


def _p(name, pattern, severity="medium", flags=re.I):
    """Helper to register a pattern."""
    PATTERNS.append((name, re.compile(pattern, flags), severity))


# -- API keys & tokens (from SecretFinder + additions) --
_p("AWS Access Key", r"A[SK]IA[0-9A-Z]{16}", "high", 0)
_p("AWS MWS Token", r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "high")
_p("AWS S3 URL", r"[a-zA-Z0-9_\-]+\.s3\.amazonaws\.com|s3://[a-zA-Z0-9_\-\.]+", "medium")
_p("Google API Key", r"AIza[0-9A-Za-z\-_]{35}", "high", 0)
_p("Google OAuth", r"ya29\.[0-9A-Za-z\-_]+", "high", 0)
_p("Firebase Token", r"AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}", "high", 0)
_p("Stripe Key", r"sk_live_[0-9a-zA-Z]{24}", "high", 0)
_p("Stripe Restricted", r"rk_live_[0-9a-zA-Z]{24}", "high", 0)
_p("Square Token", r"sqOatp-[0-9A-Za-z\-_]{22}", "high", 0)
_p("Mailgun Key", r"key-[0-9a-zA-Z]{32}", "high", 0)
_p("Twilio Key", r"SK[0-9a-fA-F]{32}", "high", 0)
_p("Twilio SID", r"AC[a-zA-Z0-9_\-]{32}", "medium", 0)
_p("Slack Token", r"xox[bpsa]-[a-zA-Z0-9\-]{10,}", "high", 0)
_p("GitHub Token", r"gh[ps]_[A-Za-z0-9_]{36}", "high", 0)
_p("Facebook Token", r"EAACEdEose0cBA[0-9A-Za-z]+", "high", 0)
_p("PayPal Braintree", r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}", "high", 0)
_p("Heroku API Key", r"[hH]eroku.*[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", "high")
_p("JWT", r"eyJ[A-Za-z0-9\-_=]+\.eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_.+/=]*", "medium", 0)

# -- Auth headers / credentials in source --
_p("Authorization Header", r"['\"](?:basic|bearer)\s+[a-zA-Z0-9=:_+/\-]{10,}['\"]", "high")
_p("Hardcoded Password", r"(?:password|passwd|pwd|secret)\s*[=:]\s*['\"][^'\"]{4,}['\"]", "high")
_p("API Key Assignment", r"(?:api[_\-]?key|apikey|api[_\-]?secret)\s*[=:]\s*['\"][a-zA-Z0-9_\-]{10,}['\"]", "high")
_p("Private Key", r"-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----", "high", 0)

# -- Database connection strings --
_p("MySQL Connection", r"mysql://[^\s'\"<>]+", "high")
_p("PostgreSQL Connection", r"postgres(?:ql)?://[^\s'\"<>]+", "high")
_p("MongoDB Connection", r"mongodb(?:\+srv)?://[^\s'\"<>]+", "high")
_p("Redis Connection", r"redis://[^\s'\"<>]+", "high")
_p("SQLite Path", r"sqlite:///[^\s'\"<>]+", "medium")
_p("JDBC Connection", r"jdbc:[a-z]+://[^\s'\"<>]+", "high")

# -- Internal infrastructure leaks --
_p("Internal IP (RFC1918)", r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b", "medium", 0)
_p("Email Address", r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b", "low", 0)
_p("Internal Hostname", r"\b(?:localhost|internal|staging|dev|test|admin|db|database|mysql|redis|mongo|elastic|kibana|grafana|jenkins|gitlab|jira)\.[a-zA-Z0-9.\-]+\b", "medium")

# -- Server/framework info disclosure --
_p("PHP Error", r"(?:Fatal error|Warning|Parse error|Notice):.*?in\s+/.+?\.php(?:\s+on\s+line\s+\d+)?", "medium")
_p("Stack Trace (Python)", r"Traceback \(most recent call last\)", "medium", 0)
_p("Stack Trace (Java)", r"(?:java|javax)\.[a-zA-Z.]+Exception", "medium", 0)
_p("Stack Trace (.NET)", r"System\.[A-Z][a-zA-Z]+Exception", "medium", 0)
_p("Debug Mode", r"(?:DEBUG|debug)\s*[=:]\s*(?:True|true|1|on)", "medium")
_p("Server Path Disclosure", r"(?:/var/www/|/home/\w+/|/opt/|/srv/|C:\\\\(?:inetpub|Users|Program Files))", "medium", 0)
_p("SQL Error (passive)", r"(?:SQL syntax|mysql_fetch|pg_query|ORA-\d{5}|sqlite3\.\w+Error)", "medium")

# -- Backup / sensitive files referenced --
_p("Backup File Reference", r"['\"][^'\"]*\.(?:bak|backup|old|orig|save|swp|tmp|dist|sql|dump|tar\.gz|zip)['\"]", "low")
_p("Config File Reference", r"['\"][^'\"]*(?:config|settings|env|htaccess|htpasswd|web\.config|\.env)['\"]", "low")
_p(".git Exposed", r"\.git/(?:HEAD|config|index|objects)", "high", 0)
_p(".env File", r"\.env(?:\.|['\"\s])", "medium")

# -- Interesting comments --
_p("TODO/FIXME/HACK", r"(?://|#|/\*)\s*(?:TODO|FIXME|HACK|XXX|BUG|SECURITY)\b[^\n]{0,100}", "low")
_p("Credentials in Comment", r"(?://|#|/\*)\s*(?:password|passwd|pwd|secret|key|token)\s*[:=]\s*\S+", "high")

# -- Deserialization attack surfaces --
# These detect serialized data formats in responses/hidden fields/cookies.
# Finding serialized data = potential deserialization vulnerability.
# Exploitation requires ysoserial (Java), phpggc (PHP), or manual crafting.

# Java serialized objects: base64-encoded magic bytes (0xACED0005 = rO0AB)
_p("Java Serialized Object (base64)", r"rO0AB[A-Za-z0-9+/=]{20,}", "high", 0)
# Java serialized objects: hex-encoded magic bytes
_p("Java Serialized Object (hex)", r"aced0005[0-9a-f]{16,}", "high")
# PHP serialized data: O:N:"ClassName":N:{...} or a:N:{s:N:...}
_p("PHP Serialized Data", r'(?:^|[=&;"\s])(?:O:\d+:"[A-Z]\w+":\d+:\{|a:\d+:\{(?:s:\d+:|i:\d+;))', "high")
# .NET ViewState — unencrypted/unsigned ViewState is exploitable via deserialization
_p(".NET ViewState", r'__VIEWSTATE[^>]*value="[A-Za-z0-9+/=]{50,}"', "high")
_p(".NET ViewState (MAC disabled)", r'__VIEWSTATEGENERATOR|enableviewstatemac\s*=\s*["\']?false', "high")
# Python serialized data (base64-encoded, detection only — not loading/executing anything)
_p("Python Serialized Data (base64)", r'gASV[A-Za-z0-9+/=]{20,}', "high", 0)
# Large base64 blobs in form fields/cookies — often serialized objects
_p("Large Base64 Blob (possible serialized)", r'(?:value|cookie|token|data|session)\s*[=:]\s*["\']?[A-Za-z0-9+/=]{200,}', "medium")


class PassiveAnalyzer:
    """Analyzes response bodies during crawl for leaked information."""

    def __init__(self):
        self.findings = defaultdict(list)  # {severity: [(name, match, url, context)]}
        self._seen = set()  # Dedup: (name, match_value)

    def analyze(self, url, text):
        """Scan a response body for secrets and information disclosure."""
        if not text:
            return

        # Only scan first 100KB per response
        text = text[:102400]

        for name, pattern, severity in PATTERNS:
            for match in pattern.finditer(text):
                value = match.group(0)[:120]  # Truncate long matches

                # Dedup
                dedup_key = (name, value[:50])
                if dedup_key in self._seen:
                    continue
                self._seen.add(dedup_key)

                # Get surrounding context
                start = max(0, match.start() - 30)
                end = min(len(text), match.end() + 30)
                context = text[start:end].replace("\n", " ").strip()

                self.findings[severity].append({
                    "type": name,
                    "value": value,
                    "url": url,
                    "context": context,
                })

    def has_findings(self):
        return any(self.findings.values())

    def summary(self):
        """Return counts by severity."""
        return {
            "high": len(self.findings.get("high", [])),
            "medium": len(self.findings.get("medium", [])),
            "low": len(self.findings.get("low", [])),
        }

    def all_findings(self):
        """Return all findings sorted by severity."""
        results = []
        for severity in ("high", "medium", "low"):
            for f in self.findings.get(severity, []):
                results.append({**f, "severity": severity})
        return results
