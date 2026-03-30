"""Intelligence modules — injection detection (SQLi, SSTI, command), tech fingerprinting, response analysis, GraphQL."""

import re
import json
import logging
from urllib.parse import urlparse, urljoin, urlencode, parse_qs

from sqli_recon.models import Endpoint, Parameter, ParamLocation, Source

log = logging.getLogger(__name__)


# ============================================================
# 1. Error-based SQLi pre-detection
# ============================================================

# Database error patterns — if any appear in the response after sending a
# single quote, the parameter is almost certainly injectable.
DB_ERROR_PATTERNS = [
    # MySQL
    (re.compile(r"You have an error in your SQL syntax", re.I), "MySQL"),
    (re.compile(r"mysql_fetch|mysql_num_rows|mysql_query", re.I), "MySQL"),
    (re.compile(r"Warning.*?\Wmysqli?_", re.I), "MySQL"),
    (re.compile(r"MySQLSyntaxErrorException", re.I), "MySQL"),
    # PostgreSQL
    (re.compile(r"ERROR:\s+syntax error at or near", re.I), "PostgreSQL"),
    (re.compile(r"pg_query|pg_exec|pg_connect", re.I), "PostgreSQL"),
    (re.compile(r"PSQLException", re.I), "PostgreSQL"),
    (re.compile(r"unterminated quoted string", re.I), "PostgreSQL"),
    # SQLite
    (re.compile(r"SQLite.*?(?:error|warning)", re.I), "SQLite"),
    (re.compile(r"sqlite3\.OperationalError", re.I), "SQLite"),
    (re.compile(r"unrecognized token", re.I), "SQLite"),
    (re.compile(r"near \".*?\": syntax error", re.I), "SQLite"),
    # Microsoft SQL Server
    (re.compile(r"Unclosed quotation mark", re.I), "MSSQL"),
    (re.compile(r"Microsoft.*?ODBC.*?Driver", re.I), "MSSQL"),
    (re.compile(r"mssql_query", re.I), "MSSQL"),
    (re.compile(r"SqlException", re.I), "MSSQL"),
    (re.compile(r"Incorrect syntax near", re.I), "MSSQL"),
    # Oracle
    (re.compile(r"ORA-\d{5}", re.I), "Oracle"),
    (re.compile(r"oracle.*?error|oracle.*?driver", re.I), "Oracle"),
    (re.compile(r"quoted string not properly terminated", re.I), "Oracle"),
    # Generic
    (re.compile(r"SQL syntax.*?error", re.I), "Unknown"),
    (re.compile(r"SQL.*?error.*?syntax", re.I), "Unknown"),
    (re.compile(r"database error", re.I), "Unknown"),
    (re.compile(r"SQLSTATE\[", re.I), "Unknown"),
    (re.compile(r"java\.sql\.SQLException", re.I), "Java/JDBC"),
    (re.compile(r"PDOException", re.I), "PHP/PDO"),
]


class ErrorDetector:
    """
    Sends a single quote to high-scoring parameters and checks for DB errors.

    This is NOT exploitation — it's the same as typing ' in a search box.
    If the app returns a database error, the parameter is confirmed injectable.
    """

    def __init__(self, client):
        self.client = client

    def test_findings(self, findings, min_score=0.3, max_workers=3, progress_callback=None):
        """
        Test high-scoring findings for error-based confirmation.
        Returns list of (finding, db_type) tuples for confirmed injectable params.
        """
        from concurrent.futures import ThreadPoolExecutor, as_completed

        candidates = [f for f in findings if f.score >= min_score]

        # Deduplicate — don't test the same endpoint+param twice
        tested = set()
        unique_candidates = []
        for f in candidates:
            key = (f.endpoint.base_url, f.endpoint.method, f.parameter.name)
            if key not in tested:
                tested.add(key)
                unique_candidates.append(f)

        confirmed = []
        done = [0]

        def _test_one(finding):
            db_type = self._test_param(finding)
            done[0] += 1
            if progress_callback and done[0] % 3 == 0:
                progress_callback(done[0], len(unique_candidates))
            return (finding, db_type) if db_type else None

        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(_test_one, f): f for f in unique_candidates}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    confirmed.append(result)

        if progress_callback:
            progress_callback(len(unique_candidates), len(unique_candidates))

        return confirmed

    def _test_param(self, finding):
        """Send a single quote and check for DB errors. Returns DB type or None."""
        resp = _send_probe(self.client, finding.endpoint, finding.parameter, "'")
        if resp is None:
            return None
        return _check_for_db_errors(resp.text)


# ============================================================
# 1b. SSTI (Server-Side Template Injection) Detection
# ============================================================

# SSTI probes — each is a (payload, expected_output) pair.
# If the expected output appears in the response, the template engine
# evaluated our expression = confirmed SSTI.
SSTI_PROBES = [
    # Math expression — works in Jinja2, Twig, Freemarker, Mako, Tornado, etc.
    ("{{7*7}}", "49"),
    ("${7*7}", "49"),
    ("#{7*7}", "49"),
    ("<%= 7*7 %>", "49"),
    # Jinja2 specific
    ("{{config}}", "<Config"),
    # Twig specific
    ("{{7*'7'}}", "7777777"),
]


class SSTIDetector:
    """
    Detects Server-Side Template Injection by sending math expressions
    and checking if the server evaluates them.

    Safe probes only — 7*7=49 is not exploitation.
    """

    def __init__(self, client):
        self.client = client

    def test_findings(self, findings, min_score=0.2, progress_callback=None):
        """Test findings for SSTI. Returns list of (finding, engine_hint)."""
        confirmed = []
        tested = set()

        candidates = [f for f in findings if f.score >= min_score]

        for i, finding in enumerate(candidates):
            if progress_callback and (i + 1) % 5 == 0:
                progress_callback(i + 1, len(candidates))

            key = (finding.endpoint.base_url, finding.endpoint.method, finding.parameter.name)
            if key in tested:
                continue
            tested.add(key)

            result = self._test_param(finding)
            if result:
                confirmed.append((finding, result))

        return confirmed

    def _test_param(self, finding):
        """Send SSTI probes to a parameter. Returns engine hint or None."""
        ep = finding.endpoint
        param = finding.parameter

        for payload, expected in SSTI_PROBES:
            resp = _send_probe(self.client, ep, param, payload)
            if resp is None:
                continue

            if expected in resp.text:
                # Determine which engine
                if "{{" in payload and "7*'7'" in payload:
                    return "Twig"
                elif "{{" in payload and "config" in payload:
                    return "Jinja2"
                elif "${" in payload:
                    return "Freemarker/Mako"
                elif "<%=" in payload:
                    return "ERB/JSP"
                return "Unknown template engine"

        return None


# ============================================================
# 1c. Command Injection Detection
# ============================================================

# Command injection probes — each checks for a known output pattern.
# These are safe: they run read-only commands that every OS has.
CMDI_PROBES = [
    # Output-based: inject a command whose output we can recognize
    ("; echo sqli_recon_cmdi_test", "sqli_recon_cmdi_test"),
    ("| echo sqli_recon_cmdi_test", "sqli_recon_cmdi_test"),
    ("` echo sqli_recon_cmdi_test`", "sqli_recon_cmdi_test"),
    ("$(echo sqli_recon_cmdi_test)", "sqli_recon_cmdi_test"),
    ("& echo sqli_recon_cmdi_test", "sqli_recon_cmdi_test"),  # Windows
]

# Time-based: sleep command — if response takes >5s longer than baseline, command ran
CMDI_TIME_PROBES = [
    "; sleep 5",
    "| sleep 5",
    "$(sleep 5)",
    "` sleep 5`",
    "& timeout /t 5",  # Windows
]


class CommandInjectionDetector:
    """
    Detects OS command injection by sending echo probes and checking
    if the output appears in the response, or by measuring response
    time with sleep commands.

    Safe probes only — echo and sleep are read-only.
    """

    def __init__(self, client):
        self.client = client

    def test_findings(self, findings, min_score=0.2, progress_callback=None):
        """Test findings for command injection. Returns list of (finding, method)."""
        confirmed = []
        tested = set()

        candidates = [f for f in findings if f.score >= min_score]

        for i, finding in enumerate(candidates):
            if progress_callback and (i + 1) % 5 == 0:
                progress_callback(i + 1, len(candidates))

            key = (finding.endpoint.base_url, finding.endpoint.method, finding.parameter.name)
            if key in tested:
                continue
            tested.add(key)

            result = self._test_param(finding)
            if result:
                confirmed.append((finding, result))

        return confirmed

    def _test_param(self, finding):
        """Send command injection probes. Returns detection method or None."""
        ep = finding.endpoint
        param = finding.parameter

        # Output-based detection
        for payload, expected in CMDI_PROBES:
            resp = _send_probe(self.client, ep, param, payload)
            if resp is None:
                continue
            if expected in resp.text:
                return "output-based"

        # Time-based detection — measure baseline first
        import time
        baseline_start = time.time()
        _send_probe(self.client, ep, param, "harmless_value")
        baseline_time = time.time() - baseline_start

        for payload in CMDI_TIME_PROBES:
            start = time.time()
            _send_probe(self.client, ep, param, payload)
            elapsed = time.time() - start

            # If response took 4+ seconds longer than baseline, sleep executed
            if elapsed > baseline_time + 4:
                return "time-based"

        return None


def _send_probe(client, endpoint, param, value):
    """Send a probe value to a specific parameter. Returns response or None."""
    from sqli_recon.models import _placeholder_value
    from urllib.parse import urlunparse

    try:
        if param.location == ParamLocation.QUERY:
            parsed = urlparse(endpoint.url)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            qs[param.name] = [value]
            probe_url = endpoint.base_url + "?" + urlencode(qs, doseq=True)
            return client.get(probe_url)

        elif param.location == ParamLocation.BODY:
            data = {}
            for p in endpoint.parameters:
                if p.location == ParamLocation.BODY:
                    data[p.name] = _placeholder_value(p)
            data[param.name] = value
            return client.post(endpoint.base_url, data=data)

        elif param.location == ParamLocation.JSON:
            body = {}
            for p in endpoint.parameters:
                if p.location == ParamLocation.JSON:
                    body[p.name] = _placeholder_value(p)
            body[param.name] = value
            return client.post(endpoint.base_url, json=body,
                               headers={"Content-Type": "application/json"})

        elif param.location == ParamLocation.PATH:
            if param.value and param.value in urlparse(endpoint.url).path:
                parsed = urlparse(endpoint.url)
                new_path = parsed.path.replace(param.value, value, 1)
                probe_url = urlunparse((parsed.scheme, parsed.netloc, new_path,
                                        parsed.params, parsed.query, ""))
                return client.get(probe_url)
    except Exception:
        pass
    return None


# Injectable headers — these are sometimes logged or used in SQL queries
INJECTABLE_HEADERS = [
    ("X-Forwarded-For", "127.0.0.1'"),
    ("Referer", "http://test.com/'"),
    ("X-Forwarded-Host", "test.com'"),
    ("X-Real-IP", "127.0.0.1'"),
    ("User-Agent", "Mozilla/5.0'"),
    ("X-Custom-IP-Authorization", "127.0.0.1'"),
]


class HeaderInjectionScanner:
    """
    Tests HTTP headers as injection surfaces.

    Some apps log User-Agent, X-Forwarded-For, or Referer to a database
    using string interpolation. Sending a single quote in these headers
    can trigger SQL errors if the backend is vulnerable.
    """

    def __init__(self, client):
        self.client = client

    def scan_url(self, url):
        """Test a single URL with injectable headers. Returns list of (header_name, db_type)."""
        results = []

        for header_name, probe_value in INJECTABLE_HEADERS:
            try:
                resp = self.client.get(url, headers={header_name: probe_value})
                if resp is None:
                    continue

                db_type = _check_for_db_errors(resp.text)
                if db_type:
                    results.append((header_name, db_type))
                    log.info(f"Header injection found: {header_name} on {url} ({db_type})")
            except Exception:
                continue

        return results

    def scan_endpoints(self, endpoints, progress_callback=None):
        """
        Test unique base URLs for header injection.
        Returns list of Endpoints with header params.
        """
        from sqli_recon.models import Endpoint, Parameter, ParamLocation, Source

        tested_urls = set()
        found_endpoints = []

        # Only test unique base URLs — headers apply site-wide
        urls_to_test = []
        for ep in endpoints:
            if ep.base_url not in tested_urls:
                tested_urls.add(ep.base_url)
                urls_to_test.append(ep.base_url)

        # Limit to 10 URLs max — header injection is site-wide, not per-endpoint
        urls_to_test = urls_to_test[:10]

        for i, url in enumerate(urls_to_test):
            if progress_callback and (i + 1) % 3 == 0:
                progress_callback(i + 1, len(urls_to_test))

            results = self.scan_url(url)
            for header_name, db_type in results:
                found_endpoints.append(Endpoint(
                    url=url,
                    method="GET",
                    parameters=[Parameter(
                        name=header_name,
                        location=ParamLocation.HEADER,
                        value=f"(injectable — {db_type})",
                        param_type="string",
                    )],
                    source=Source.CRAWL,
                ))

        return found_endpoints


def _check_for_db_errors(text):
    """Check response text for database error signatures. Returns DB type or None."""
    if not text:
        return None
    # Only check first 10KB to avoid scanning huge responses
    text = text[:10240]
    for pattern, db_type in DB_ERROR_PATTERNS:
        if pattern.search(text):
            return db_type
    return None


# ============================================================
# 2. Technology fingerprinting
# ============================================================

class TechFingerprint:
    """Identifies the backend technology stack from response characteristics."""

    def __init__(self):
        self.detected = {}  # tech_name -> confidence (0.0-1.0)
        self._checked = False

    def analyze_response(self, resp):
        """Analyze a single HTTP response for technology signals."""
        if resp is None:
            return

        headers = {k.lower(): v for k, v in resp.headers.items()}
        cookies = resp.cookies.get_dict()
        body = resp.text[:5000] if resp.text else ""
        url = resp.url

        # ---- Headers ----
        powered = headers.get("x-powered-by", "")
        server = headers.get("server", "")

        if re.search(r"PHP", powered, re.I):
            self._add("PHP", 0.9)
        if re.search(r"ASP\.NET", powered, re.I):
            self._add("ASP.NET", 0.9)
        if re.search(r"Express", powered, re.I):
            self._add("Node.js/Express", 0.8)
        if re.search(r"JSP|Servlet", powered, re.I):
            self._add("Java", 0.8)

        if re.search(r"Apache", server, re.I):
            self._add("Apache", 0.5)
        if re.search(r"nginx", server, re.I):
            self._add("nginx", 0.5)
        if re.search(r"IIS", server, re.I):
            self._add("IIS", 0.7)
            self._add("ASP.NET", 0.4)
        if re.search(r"openresty", server, re.I):
            self._add("OpenResty/Lua", 0.6)

        # Django
        if "csrfmiddlewaretoken" in body or headers.get("x-frame-options") == "DENY":
            self._add("Django", 0.3)

        # ---- Cookies ----
        cookie_names = set(cookies.keys())
        if "PHPSESSID" in cookie_names:
            self._add("PHP", 0.9)
        if "ASP.NET_SessionId" in cookie_names or "ASPSESSIONID" in str(cookie_names).upper():
            self._add("ASP.NET", 0.9)
        if "JSESSIONID" in cookie_names:
            self._add("Java", 0.9)
        if "connect.sid" in cookie_names:
            self._add("Node.js/Express", 0.7)
        if "rack.session" in cookie_names:
            self._add("Ruby/Rails", 0.8)
        if "_rails_session" in cookie_names or any("_session" in c and "rails" in c.lower() for c in cookie_names):
            self._add("Ruby/Rails", 0.8)
        if "csrftoken" in cookie_names and "sessionid" in cookie_names:
            self._add("Django", 0.8)
        if "laravel_session" in cookie_names:
            self._add("Laravel", 0.9)
            self._add("PHP", 0.6)

        # ---- URL patterns ----
        path = urlparse(url).path.lower()
        if path.endswith(".php"):
            self._add("PHP", 0.9)
        elif path.endswith(".asp") or path.endswith(".aspx"):
            self._add("ASP.NET", 0.9)
        elif path.endswith(".jsp") or path.endswith(".do"):
            self._add("Java", 0.8)
        elif path.endswith(".cgi") or path.endswith(".pl"):
            self._add("Perl/CGI", 0.7)

        # ---- HTML meta / body patterns ----
        if re.search(r"wp-content|wp-includes|wordpress", body, re.I):
            self._add("WordPress", 0.9)
            self._add("PHP", 0.7)
        if re.search(r"Drupal|drupal\.js", body, re.I):
            self._add("Drupal", 0.8)
            self._add("PHP", 0.7)
        if re.search(r"mybb|member\.php\?action|showthread\.php", body, re.I):
            self._add("MyBB", 0.8)
            self._add("PHP", 0.7)
        if re.search(r"phpBB|viewtopic\.php", body, re.I):
            self._add("phpBB", 0.8)
            self._add("PHP", 0.7)

        self._checked = True

    def _add(self, tech, confidence):
        """Add/update a tech detection. Keeps highest confidence."""
        current = self.detected.get(tech, 0)
        self.detected[tech] = max(current, confidence)

    def sqli_risk_modifier(self):
        """
        Returns a score modifier based on detected technologies.
        Higher for PHP/ASP (historically more SQLi), lower for
        frameworks with ORM defaults (Django, Rails, Laravel).
        """
        modifier = 0.0

        # High risk — languages/frameworks with historically more SQLi
        if self.detected.get("PHP", 0) > 0.5:
            modifier += 0.06
        if self.detected.get("ASP.NET", 0) > 0.5:
            modifier += 0.06
        if self.detected.get("Java", 0) > 0.5:
            modifier += 0.03
        if self.detected.get("WordPress", 0) > 0.5:
            modifier += 0.04
        if self.detected.get("MyBB", 0) > 0.5:
            modifier += 0.04

        # Lower risk — frameworks that default to parameterized queries
        if self.detected.get("Django", 0) > 0.5:
            modifier -= 0.05
        if self.detected.get("Ruby/Rails", 0) > 0.5:
            modifier -= 0.05
        if self.detected.get("Laravel", 0) > 0.5:
            modifier -= 0.03  # PHP but with ORM

        return modifier

    def summary(self):
        """Return detected technologies sorted by confidence."""
        return sorted(self.detected.items(), key=lambda x: -x[1])

    def priority_endpoints(self):
        """Return platform-specific high-value endpoints to inject into the crawl.

        These are endpoints known to be historically vulnerable or interesting
        for the detected platform. Injected early so they get crawled, analyzed,
        and tested even if the spider doesn't find links to them.
        """
        endpoints = []

        if self.detected.get("MyBB", 0) > 0.5:
            endpoints.extend([
                # Historically most exploited MyBB endpoints
                "/search.php",
                "/search.php?action=results",
                "/member.php?action=profile&uid=1",
                "/member.php?action=login",
                "/member.php?action=register",
                "/forumdisplay.php?fid=1",
                "/forumdisplay.php?fid=1&sortby=subject&order=asc",
                "/showthread.php?tid=1",
                "/showthread.php?tid=1&action=lastpost",
                "/online.php?sortby=username",
                "/newreply.php?tid=1",
                "/printthread.php?tid=1",
                "/misc.php?action=help",
                "/modcp.php",
                "/usercp.php",
                "/calendar.php",
                "/reputation.php?uid=1",
                "/private.php",
                "/xmlhttp.php",
            ])

        if self.detected.get("phpBB", 0) > 0.5:
            endpoints.extend([
                "/viewtopic.php?t=1",
                "/viewtopic.php?f=1&t=1",
                "/viewforum.php?f=1",
                "/memberlist.php?mode=viewprofile&u=1",
                "/memberlist.php?mode=searchuser",
                "/search.php",
                "/ucp.php?mode=login",
                "/posting.php",
                "/mcp.php",
            ])

        if self.detected.get("WordPress", 0) > 0.5:
            endpoints.extend([
                # REST API — often exposes data without auth
                "/wp-json/wp/v2/users",
                "/wp-json/wp/v2/posts",
                "/wp-json/wp/v2/pages",
                "/wp-json/wp/v2/categories",
                "/wp-json/wp/v2/tags",
                "/wp-json/wp/v2/comments",
                "/wp-json/wp/v2/media",
                "/wp-json/wp/v2/search?search=test",
                "/wp-json/",
                # Classic attack surfaces
                "/xmlrpc.php",
                "/wp-login.php",
                "/wp-admin/admin-ajax.php",
                "/wp-admin/admin-post.php",
                # Plugin/theme enumeration
                "/wp-content/plugins/",
                "/wp-content/themes/",
                "/?s=test",  # Search
                "/?p=1",     # Post by ID
                "/?page_id=1",
                "/?author=1",
                "/?cat=1",
            ])

        if self.detected.get("Drupal", 0) > 0.5:
            endpoints.extend([
                "/user/login",
                "/user/register",
                "/node/1",
                "/admin",
                "/jsonapi",
                "/jsonapi/node/article",
                "/?q=user/login",
                "/?q=node/1",
                "/rest/type/node/article",  # REST API
            ])

        if self.detected.get("ASP.NET", 0) > 0.5:
            endpoints.extend([
                "/default.aspx",
                "/login.aspx",
                "/search.aspx",
                "/admin/",
                "/api/",
                "/webforms/",
            ])

        if self.detected.get("Java", 0) > 0.5:
            endpoints.extend([
                "/login.jsp",
                "/search.jsp",
                "/admin/",
                "/api/",
                "/console/",
                "/manager/html",  # Tomcat manager
                "/status",        # Spring Boot actuator
                "/actuator",
                "/actuator/env",
                "/swagger-ui.html",
            ])

        return endpoints

    def scan_recommendations(self):
        """Return recommendations on which scan phases to run or skip.

        Returns dict with:
            skip_api_brute: bool — skip if platform-specific endpoints cover it
            skip_graphql: bool — skip if not a JS/API-heavy platform
            extra_depth: int — suggest extra crawl depth for deep platforms
        """
        rec = {
            "skip_api_brute": False,
            "skip_graphql": False,
            "extra_depth": 0,
        }

        # If we detected a specific CMS, its priority_endpoints cover the
        # important paths already — generic API brute adds noise
        if any(self.detected.get(cms, 0) > 0.5
               for cms in ["MyBB", "phpBB", "WordPress", "Drupal"]):
            rec["skip_api_brute"] = True

        # GraphQL is only relevant for modern JS-heavy apps
        if any(self.detected.get(t, 0) > 0.5
               for t in ["MyBB", "phpBB", "WordPress", "Drupal", "Perl/CGI"]):
            rec["skip_graphql"] = True

        # Forums have deep thread structures — extra depth helps
        if any(self.detected.get(t, 0) > 0.5 for t in ["MyBB", "phpBB"]):
            rec["extra_depth"] = 1

        return rec

    def sqlmap_flags(self):
        """Return recommended sqlmap flags based on detected technology."""
        flags = []
        notes = []

        # DBMS detection — tells sqlmap to skip testing other DB types
        if self.detected.get("MyBB", 0) > 0.5:
            flags.append("--dbms=MySQL")
            flags.append("--level=3")  # ORDER BY injection needs higher level
            flags.append("--risk=2")
            notes.append("MyBB detected: MySQL backend, level=3 for ORDER BY injection")
        elif self.detected.get("WordPress", 0) > 0.5:
            flags.append("--dbms=MySQL")
            notes.append("WordPress detected: MySQL backend")
        elif self.detected.get("phpBB", 0) > 0.5:
            flags.append("--dbms=MySQL")
            flags.append("--level=3")
            notes.append("phpBB detected: MySQL backend")
        elif self.detected.get("Drupal", 0) > 0.5:
            flags.append("--dbms=MySQL")
            notes.append("Drupal detected: MySQL backend (may also be PostgreSQL)")
        elif self.detected.get("ASP.NET", 0) > 0.5 or self.detected.get("IIS", 0) > 0.5:
            flags.append("--dbms=MSSQL")
            notes.append("ASP.NET/IIS detected: likely MSSQL backend")

        # Tamper scripts for common WAF bypasses
        if self.detected.get("MyBB", 0) > 0.5 or self.detected.get("phpBB", 0) > 0.5:
            flags.append("--tamper=space2comment")
            notes.append("Forum software: space2comment tamper for WAF bypass")
        if self.detected.get("WordPress", 0) > 0.5:
            flags.append("--tamper=space2comment,between")
            notes.append("WordPress: common WAF tamper scripts")
            notes.append("WordPress tip: plugins are the main attack surface — check /wp-content/plugins/ for installed plugins")
            notes.append("WordPress tip: try /wp-json/wp/v2/users to enumerate users without auth")

        return flags, notes

    def platform_recon_tips(self):
        """Return platform-specific recon tips for the terminal output."""
        tips = []
        if self.detected.get("WordPress", 0) > 0.5:
            tips.append("WordPress: SQLi most likely in plugins, not core. Identify plugins via /wp-content/plugins/ paths.")
            tips.append("WordPress: /wp-json/wp/v2/ endpoints often expose data without auth.")
            tips.append("WordPress: check for xmlrpc.php (brute force vector) and wp-login.php.")
        if self.detected.get("MyBB", 0) > 0.5:
            tips.append("MyBB: search.php (keywords param) is historically the most exploited endpoint.")
            tips.append("MyBB: ORDER BY injection via sortby/order params — needs sqlmap --level=3.")
            tips.append("MyBB: check for outdated plugins at /inc/plugins/.")
        if self.detected.get("phpBB", 0) > 0.5:
            tips.append("phpBB: viewtopic.php and memberlist.php are common injection targets.")
        if self.detected.get("Drupal", 0) > 0.5:
            tips.append("Drupal: check for Drupalgeddon (CVE-2018-7600) if version < 7.58 or 8.5.1.")
        if self.detected.get("ASP.NET", 0) > 0.5:
            tips.append("ASP.NET: check for ViewState deserialization and padding oracle vulnerabilities.")
        return tips


# ============================================================
# 3. Response content analysis
# ============================================================

class ResponseAnalyzer:
    """Analyzes response content to determine if an endpoint likely hits a database."""

    @staticmethod
    def looks_like_db_rows(resp):
        """
        Check if a response looks like database query results.
        Returns (is_db_like, reason) tuple.
        """
        if resp is None:
            return False, ""

        content_type = resp.headers.get("Content-Type", "")

        # JSON array of objects = very likely DB rows
        if "application/json" in content_type:
            try:
                data = resp.json()
                if isinstance(data, list) and len(data) >= 2:
                    # Check if items are objects with consistent keys
                    if all(isinstance(item, dict) for item in data[:5]):
                        keys = set(data[0].keys())
                        consistent = all(set(d.keys()) == keys for d in data[:5])
                        if consistent and len(keys) >= 2:
                            return True, f"JSON array of {len(data)} objects with consistent keys ({', '.join(sorted(keys)[:5])})"

                # Nested: {"results": [...], "data": [...], "items": [...]}
                if isinstance(data, dict):
                    for key in ("results", "data", "items", "rows", "records", "entries", "list", "objects"):
                        inner = data.get(key)
                        if isinstance(inner, list) and len(inner) >= 2:
                            if all(isinstance(item, dict) for item in inner[:5]):
                                return True, f"JSON .{key}[] array of {len(inner)} objects"
            except (ValueError, TypeError):
                pass

        # HTML table with multiple rows = might be DB output
        if "text/html" in content_type and resp.text:
            text = resp.text[:20000]
            tr_count = text.count("<tr")
            if tr_count >= 4:
                th_count = text.count("<th")
                if th_count >= 2:
                    return True, f"HTML table with {th_count} columns, {tr_count} rows"

        return False, ""


# ============================================================
# 4. GraphQL introspection
# ============================================================

INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields {
        name
        args {
          name
          type { name kind ofType { name kind } }
        }
      }
    }
  }
}
""".strip()

# Common GraphQL endpoint paths
GRAPHQL_PATHS = [
    "/graphql", "/graphiql", "/api/graphql", "/gql",
    "/v1/graphql", "/v2/graphql", "/query",
]


class GraphQLIntrospector:
    """Detects GraphQL endpoints and extracts all arguments via introspection."""

    def __init__(self, client, target_url):
        self.client = client
        self.target_url = target_url

    def discover_and_introspect(self, known_endpoints=None, progress_callback=None):
        """
        Try known GraphQL paths + any /graphql endpoints from crawling.
        Returns list of Endpoints with all discovered arguments.
        """
        endpoints = []
        parsed = urlparse(self.target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Combine known paths with any discovered endpoints
        paths_to_try = list(GRAPHQL_PATHS)
        if known_endpoints:
            for ep in known_endpoints:
                ep_path = urlparse(ep.url).path.lower()
                if "graphql" in ep_path or "gql" in ep_path:
                    paths_to_try.append(urlparse(ep.url).path)

        # Deduplicate
        paths_to_try = list(dict.fromkeys(paths_to_try))

        for i, path in enumerate(paths_to_try):
            if progress_callback and (i + 1) % 3 == 0:
                progress_callback(i + 1, len(paths_to_try))

            url = base + path
            result = self._try_introspection(url)
            if result:
                endpoints.extend(result)
                break  # Found it, don't need to try more paths

        return endpoints

    def _try_introspection(self, url):
        """Attempt GraphQL introspection at a URL. Returns list of Endpoints or None."""
        resp = self.client.post(
            url,
            json={"query": INTROSPECTION_QUERY},
            headers={"Content-Type": "application/json"},
        )
        if resp is None or resp.status_code != 200:
            return None

        try:
            data = resp.json()
        except (ValueError, TypeError):
            return None

        schema = data.get("data", {}).get("__schema")
        if not schema:
            return None

        log.info(f"GraphQL introspection succeeded at {url}")
        return self._parse_schema(url, schema)

    def _parse_schema(self, url, schema):
        """Extract all query/mutation arguments from a GraphQL schema."""
        endpoints = []
        query_type_name = schema.get("queryType", {}).get("name", "Query")
        mutation_type_name = (schema.get("mutationType") or {}).get("name", "Mutation")

        for type_def in schema.get("types", []):
            type_name = type_def.get("name", "")
            if type_name.startswith("__"):
                continue  # Skip introspection types

            is_query = type_name == query_type_name
            is_mutation = type_name == mutation_type_name
            if not is_query and not is_mutation:
                continue

            for field in type_def.get("fields", []):
                field_name = field.get("name", "")
                args = field.get("args", [])
                if not args:
                    continue

                params = []
                for arg in args:
                    arg_name = arg.get("name", "")
                    arg_type = arg.get("type", {})
                    # Determine param type
                    type_name_inner = _graphql_type_name(arg_type)
                    param_type = "numeric" if type_name_inner in ("Int", "Float", "ID") else "string"

                    params.append(Parameter(
                        name=arg_name,
                        location=ParamLocation.JSON,
                        value="",
                        param_type=param_type,
                    ))

                method = "POST"
                operation = "query" if is_query else "mutation"

                endpoints.append(Endpoint(
                    url=url,
                    method=method,
                    parameters=params,
                    content_type="application/json",
                    source=Source.CRAWL,
                    body_template=f'{{"query": "{operation} {{ {field_name}(...) {{ ... }} }}"}}',
                ))

        return endpoints


# ============================================================
# 5. Second-order SQLi hints
# ============================================================

# Store points: forms/endpoints where user input is saved to the database
STORE_INDICATORS = [
    # Form actions that save data
    re.compile(r"register|signup|sign.up|create.account", re.I),
    re.compile(r"profile|settings|preferences|account", re.I),
    re.compile(r"comment|reply|review|feedback|message|post", re.I),
    re.compile(r"submit|save|update|edit|modify", re.I),
    re.compile(r"upload|import|add|new|insert", re.I),
    re.compile(r"contact|support|ticket", re.I),
]

# Render points: pages where stored data gets displayed (potential trigger locations)
RENDER_INDICATORS = [
    re.compile(r"admin|dashboard|manage|moderate|panel", re.I),
    re.compile(r"report|log|audit|history|activity", re.I),
    re.compile(r"export|download|print|pdf|csv", re.I),
    re.compile(r"user.?list|member.?list|view.?all", re.I),
    re.compile(r"search.?results|listing|browse", re.I),
    re.compile(r"email|notification|digest|newsletter", re.I),
]

# Fields commonly stored in DB and later rendered elsewhere
STORABLE_PARAM_NAMES = re.compile(
    r"^(name|username|email|title|subject|message|comment|body|content|"
    r"description|bio|about|address|company|website|url|phone|"
    r"first.?name|last.?name|display.?name|nick|signature|"
    r"feedback|review|note|reason|text|input)$",
    re.I,
)


class SecondOrderAnalyzer:
    """
    Identifies potential second-order SQLi surfaces.

    Second-order SQLi: input is stored safely on write, but rendered
    unsafely when read. The injection payload goes into a registration
    form but triggers when an admin views the user list.

    This analyzer identifies:
    - Store points: endpoints where user data is saved
    - Render points: endpoints where stored data is displayed
    - Storable parameters: field names likely to be stored and re-rendered
    """

    @staticmethod
    def analyze(endpoints):
        """
        Analyze endpoints for second-order SQLi potential.
        Returns list of (store_endpoint, storable_params, likely_render_points) tuples.
        """
        from sqli_recon.models import ParamLocation

        store_points = []
        render_points = []

        for ep in endpoints:
            path = urlparse(ep.url).path.lower()
            url_lower = ep.url.lower()

            # Classify as store or render point
            is_store = (
                ep.method in ("POST", "PUT", "PATCH") and
                any(p.search(path) or p.search(url_lower) for p in STORE_INDICATORS)
            )
            is_render = any(p.search(path) or p.search(url_lower) for p in RENDER_INDICATORS)

            if is_store:
                # Find storable params
                storable = [
                    p for p in ep.parameters
                    if p.location in (ParamLocation.BODY, ParamLocation.JSON, ParamLocation.QUERY)
                    and STORABLE_PARAM_NAMES.match(p.name)
                ]
                if storable:
                    store_points.append((ep, storable))

            if is_render:
                render_points.append(ep)

        # Pair store points with likely render points
        results = []
        for store_ep, storable_params in store_points:
            # Find render points on the same site
            render_urls = [urlparse(r.url).path for r in render_points[:5]]
            results.append({
                "store_endpoint": store_ep.url,
                "store_method": store_ep.method,
                "storable_params": [p.name for p in storable_params],
                "likely_render_points": render_urls,
                "hint": (
                    f"Data entered via {store_ep.method} {urlparse(store_ep.url).path} "
                    f"(params: {', '.join(p.name for p in storable_params)}) "
                    f"may be rendered at: {', '.join(render_urls) if render_urls else 'admin/report pages'}"
                ),
            })

        return results


def _graphql_type_name(type_obj):
    """Extract the base type name from a GraphQL type (unwrapping NonNull/List)."""
    if not type_obj:
        return "String"
    name = type_obj.get("name")
    if name:
        return name
    of_type = type_obj.get("ofType")
    if of_type:
        return _graphql_type_name(of_type)
    return "String"
