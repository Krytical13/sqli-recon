"""
Information gathering scanner with optional sanitization.

Crawls a target, collects comprehensive recon data (responses, headers,
tech stack, JS endpoints, secrets, security posture), and packages it
into structured JSON — optionally sanitized for safe handoff to AI analysis.

Usage:
    recon-gather -u https://target.com
    recon-gather -u https://target.com --sanitize
    recon-gather -u https://target.com --sanitize --headless --tor
"""

import argparse
import json
import logging
import os
import re
import sys
import time
from collections import defaultdict
from urllib.parse import urlparse, parse_qs

from sqli_recon import __version__
from sqli_recon.http_client import HttpClient
from sqli_recon.crawler import Crawler
from sqli_recon.js_analyzer import JsAnalyzer
from sqli_recon.passive import PassiveAnalyzer
from sqli_recon.output import C
from sqli_recon.sanitizer import Sanitizer

log = logging.getLogger(__name__)


def banner():
    print(f"""{C.BOLD}{C.CYAN}
  ┌─────────────────────────────────────────┐
  │  recon_gather v{__version__:<25s}│
  │  Adaptive Web App Information Gathering │
  └─────────────────────────────────────────┘{C.RESET}
""")


def build_parser():
    p = argparse.ArgumentParser(
        prog="recon-gather",
        description="Adaptive web app information gathering with optional sanitization. "
                    "Collects comprehensive recon data and packages it for analysis.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  %(prog)s -u https://target.com                     # Full gather
  %(prog)s -u https://target.com --sanitize           # Sanitized output for AI
  %(prog)s -u https://target.com --sanitize --headless # Include SPA/JS analysis
  %(prog)s -u https://target.com --tor --sanitize     # Via Tor, sanitized
  %(prog)s -u https://target.com --cookie "s=abc"     # With auth
  %(prog)s -u https://target.com --sample-responses 5 # Collect 5 response samples per endpoint
        """,
    )

    p.add_argument("-u", "--url", required=True, help="Target URL")

    # Sanitization
    san = p.add_argument_group("sanitization")
    san.add_argument("--sanitize", action="store_true",
                     help="Produce sanitized output (strips IPs, domains, tokens, PII)")
    san.add_argument("--sanitize-only", type=str, metavar="FILE",
                     help="Sanitize an existing raw gather JSON file")
    san.add_argument("--desanitize", nargs=2, metavar=("FILE", "MAPPING"),
                     help="De-sanitize a file using a mapping (FILE MAPPING_FILE)")

    # Gathering scope
    gather = p.add_argument_group("gathering")
    gather.add_argument("--depth", type=int, default=3,
                        help="Max crawl depth (default: 3)")
    gather.add_argument("--max-pages", type=int, default=200,
                        help="Max pages to crawl (default: 200)")
    gather.add_argument("--scope", choices=["strict", "domain", "subdomain"],
                        default="domain", help="Crawl scope (default: domain)")
    gather.add_argument("--headless", action="store_true",
                        help="Use headless browser for JS-heavy SPAs")
    gather.add_argument("--sample-responses", type=int, default=3,
                        help="Number of response samples to collect per unique endpoint (default: 3)")
    gather.add_argument("--no-js", action="store_true",
                        help="Skip JavaScript file analysis")
    gather.add_argument("--no-passive", action="store_true",
                        help="Skip passive secret/leak scanning")
    gather.add_argument("--collect-bodies", action="store_true",
                        help="Include full response bodies (large output, but richer for analysis)")

    # Network
    net = p.add_argument_group("network")
    net.add_argument("--proxy", type=str, default=None,
                     help="Proxy URL")
    net.add_argument("--tor", action="store_true",
                     help="Route through Tor")
    net.add_argument("--timeout", type=int, default=30,
                     help="Request timeout (default: 30)")
    net.add_argument("--rate-limit", type=float, default=0.0,
                     help="Min seconds between requests (default: 0)")
    net.add_argument("--no-verify-ssl", action="store_true",
                     help="Disable SSL verification")
    net.add_argument("--user-agent", type=str, default=None)
    net.add_argument("--cookie", type=str, default=None,
                     help="Cookies (format: 'name=value; name2=value2')")
    net.add_argument("--header", action="append", default=[],
                     help="Extra header (format: 'Name: Value', repeatable)")
    net.add_argument("--login", type=str, default=None, metavar="USER:PASS",
                     help="Auto-login with credentials")

    # Output
    out = p.add_argument_group("output")
    out.add_argument("-o", "--output", type=str, default=None,
                     help="Output directory")
    out.add_argument("-q", "--quiet", action="store_true")
    out.add_argument("-v", "--verbose", action="store_true")

    return p


# ---------------------------------------------------------------------------
# Core gathering logic
# ---------------------------------------------------------------------------

class ReconGatherer:
    """Collects comprehensive recon data from a target web application."""

    def __init__(self, client, target_url, scope="domain", max_depth=3,
                 max_pages=200, sample_count=3, collect_bodies=False,
                 quiet=False):
        self.client = client
        self.target_url = target_url.rstrip("/")
        self.scope = scope
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.sample_count = sample_count
        self.collect_bodies = collect_bodies
        self.quiet = quiet

        self.parsed = urlparse(self.target_url)
        self.data = {
            "meta": {
                "target": self.target_url,
                "domain": self.parsed.netloc,
                "scan_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "tool": f"recon_gather v{__version__}",
            },
            "tech_stack": {},
            "security_headers": {},
            "endpoints": [],
            "js_endpoints": [],
            "forms": [],
            "response_samples": [],
            "secrets_and_leaks": [],
            "infrastructure": {},
            "attack_surface_summary": {},
        }

    def gather(self, do_js=True, do_headless=False, do_passive=True,
               proxy=None, verify_ssl=True):
        """Run all gathering phases. Returns the complete dataset."""

        # ---- Phase 1: Initial probe + tech fingerprinting ----
        self._log("PROBE", "Connecting to target...")
        probe = self.client.get(self.target_url)
        if probe is None:
            print(f"\n{C.RED}Error: Could not reach {self.target_url}{C.RESET}",
                  file=sys.stderr)
            sys.exit(1)

        self._log("PROBE", f"Target reachable ({probe.status_code})")
        self._analyze_probe(probe)

        # ---- Phase 2: Crawl ----
        self._log("CRAWL", "Spidering target...")
        passive = PassiveAnalyzer() if do_passive else None

        crawler = Crawler(
            client=self.client,
            target_url=self.target_url,
            max_depth=self.max_depth,
            max_pages=self.max_pages,
            scope=self.scope,
            passive_analyzer=passive,
        )

        def crawl_progress(done, queued):
            if not self.quiet:
                print(f"\r  {C.DIM}Pages: {done} crawled, {queued} queued{C.RESET}    ",
                      end="", flush=True)

        endpoints, js_urls = crawler.crawl(progress_callback=crawl_progress)
        if not self.quiet:
            print()

        self._log("CRAWL", f"Found {len(endpoints)} endpoints, {len(js_urls)} JS files")

        # Process crawled endpoints
        self._process_endpoints(endpoints)

        # ---- Phase 2b: Headless browser (SPAs) ----
        headless_endpoints = []
        if do_headless:
            headless_endpoints = self._run_headless(endpoints, proxy, verify_ssl)
            self._process_endpoints(headless_endpoints)

        # ---- Phase 3: JavaScript analysis ----
        if do_js and js_urls:
            self._log("JS", f"Analyzing {len(js_urls)} JavaScript files...")
            analyzer = JsAnalyzer(self.client, self.target_url)

            def js_progress(done, total):
                if not self.quiet:
                    print(f"\r  {C.DIM}Analyzed {done}/{total}{C.RESET}    ",
                          end="", flush=True)

            js_endpoints = analyzer.analyze(js_urls, progress_callback=js_progress)
            if not self.quiet:
                print()

            self._log("JS", f"Extracted {len(js_endpoints)} endpoints from JS")

            for ep in js_endpoints:
                self.data["js_endpoints"].append({
                    "url": ep.url,
                    "base_url": ep.base_url,
                    "method": ep.method,
                    "parameters": [
                        {"name": p.name, "location": p.location.value,
                         "value": p.value, "type": p.param_type}
                        for p in ep.parameters
                    ],
                    "content_type": ep.content_type,
                    "source": ep.source.value,
                    "body_template": ep.body_template,
                })

        # ---- Phase 4: Collect response samples ----
        all_eps = endpoints + headless_endpoints
        if all_eps:
            self._log("SAMPLE", f"Collecting response samples from {min(len(all_eps), self.sample_count * 10)} endpoints...")
            self._collect_response_samples(all_eps)

        # ---- Phase 5: Passive findings ----
        if passive and passive.has_findings():
            self._log("PASSIVE", "Processing leaked secrets/info...")
            self.data["secrets_and_leaks"] = passive.all_findings()
            ps = passive.summary()
            self._log("PASSIVE",
                      f"{ps['high']} high, {ps['medium']} medium, {ps['low']} low severity")

        # ---- Phase 6: Build attack surface summary ----
        self._build_summary(endpoints, headless_endpoints, js_urls)

        # ---- Network stats ----
        self.data["meta"]["network_stats"] = dict(self.client.stats)

        return self.data

    def _log(self, phase, msg):
        if not self.quiet:
            print(f"\n{C.BOLD}[{phase}]{C.RESET} {msg}", flush=True)

    def _analyze_probe(self, resp):
        """Extract tech stack and security posture from initial probe."""
        headers = dict(resp.headers)

        # Tech fingerprint using existing intelligence module
        from sqli_recon.intelligence import TechFingerprint
        tech = TechFingerprint()
        tech.analyze_response(resp)

        if tech.detected:
            self.data["tech_stack"] = {
                "detected": [
                    {"technology": name, "confidence": round(conf, 2)}
                    for name, conf in tech.summary()
                ],
                "sqli_risk_modifier": tech.sqli_risk_modifier(),
                "recommendations": tech.scan_recommendations(),
            }

        # Security headers analysis
        security_headers = {}
        checks = {
            "Strict-Transport-Security": {"present": False, "value": None,
                                          "issue": "Missing HSTS — no forced HTTPS"},
            "Content-Security-Policy": {"present": False, "value": None,
                                        "issue": "Missing CSP — XSS risk"},
            "X-Frame-Options": {"present": False, "value": None,
                                "issue": "Missing X-Frame-Options — clickjacking risk"},
            "X-Content-Type-Options": {"present": False, "value": None,
                                       "issue": "Missing X-Content-Type-Options — MIME sniffing"},
            "X-XSS-Protection": {"present": False, "value": None,
                                  "issue": "Missing X-XSS-Protection"},
            "Referrer-Policy": {"present": False, "value": None,
                                "issue": "Missing Referrer-Policy"},
            "Permissions-Policy": {"present": False, "value": None,
                                   "issue": "Missing Permissions-Policy"},
            "Access-Control-Allow-Origin": {"present": False, "value": None,
                                            "issue": None},
        }

        for header_name, info in checks.items():
            val = headers.get(header_name)
            if val:
                info["present"] = True
                info["value"] = val
                info["issue"] = None
                # Flag overly permissive CORS
                if header_name == "Access-Control-Allow-Origin" and val == "*":
                    info["issue"] = "Wildcard CORS — any origin can make requests"

        security_headers["checks"] = checks
        security_headers["server"] = headers.get("Server", "Not disclosed")
        security_headers["x_powered_by"] = headers.get("X-Powered-By", "Not disclosed")

        # Cookie security
        set_cookies = resp.headers.get("Set-Cookie", "")
        if set_cookies:
            cookie_issues = []
            if "httponly" not in set_cookies.lower():
                cookie_issues.append("Missing HttpOnly flag")
            if "secure" not in set_cookies.lower():
                cookie_issues.append("Missing Secure flag")
            if "samesite" not in set_cookies.lower():
                cookie_issues.append("Missing SameSite attribute")
            security_headers["cookie_issues"] = cookie_issues

        self.data["security_headers"] = security_headers
        self.data["infrastructure"]["response_headers"] = {
            k: v for k, v in headers.items()
        }

    def _process_endpoints(self, endpoints):
        """Convert Endpoint objects to serializable dicts."""
        for ep in endpoints:
            entry = {
                "url": ep.url,
                "base_url": ep.base_url,
                "method": ep.method,
                "parameters": [
                    {"name": p.name, "location": p.location.value,
                     "value": p.value, "type": p.param_type}
                    for p in ep.parameters
                ],
                "content_type": ep.content_type,
                "source": ep.source.value,
                "status_code": ep.status_code,
                "body_template": ep.body_template,
            }

            if ep.source.value == "form":
                self.data["forms"].append(entry)
            else:
                self.data["endpoints"].append(entry)

    def _run_headless(self, existing_endpoints, proxy, verify_ssl):
        """Run headless browser to capture SPA/XHR traffic."""
        try:
            from sqli_recon.headless import HeadlessCrawler, HAS_PLAYWRIGHT
            if not HAS_PLAYWRIGHT:
                raise ImportError
        except ImportError:
            self._log("HEADLESS",
                      f"{C.YELLOW}Skipped — playwright not installed{C.RESET}")
            return []

        self._log("HEADLESS", "Launching headless browser...")

        hc = HeadlessCrawler(
            target_url=self.target_url,
            max_pages=min(self.max_pages, 30),
            scope=self.scope,
            proxy=proxy,
            timeout=self.client.timeout,
            verify_ssl=verify_ssl,
        )

        urls = [self.target_url] + [
            e.url for e in existing_endpoints
            if e.source.value in ("crawl", "sitemap", "robots")
        ]
        seen = set()
        unique = []
        for u in urls:
            base = urlparse(u)._replace(query="", fragment="").geturl()
            if base not in seen:
                seen.add(base)
                unique.append(u)

        def progress(done, total):
            if not self.quiet:
                print(f"\r  {C.DIM}Rendered {done} pages{C.RESET}    ",
                      end="", flush=True)

        eps = hc.crawl(urls_to_visit=unique[:30], progress_callback=progress)
        if not self.quiet:
            print()
        self._log("HEADLESS",
                  f"Captured {len(eps)} endpoints from browser")
        return eps

    def _collect_response_samples(self, endpoints):
        """Collect actual response data from a sample of endpoints."""
        # Deduplicate by base_url + method
        seen = set()
        unique = []
        for ep in endpoints:
            key = (ep.base_url, ep.method)
            if key not in seen:
                seen.add(key)
                unique.append(ep)

        sampled = 0
        for ep in unique:
            if sampled >= self.sample_count * 10:
                break

            resp = self.client.get(ep.url) if ep.method == "GET" else None
            if resp is None:
                continue

            sample = {
                "url": ep.url,
                "method": ep.method,
                "status_code": resp.status_code,
                "response_time_ms": int(resp.elapsed.total_seconds() * 1000),
                "content_type": resp.headers.get("Content-Type", ""),
                "content_length": len(resp.content),
                "headers": dict(resp.headers),
            }

            if self.collect_bodies:
                # Truncate very large responses
                body = resp.text[:50000] if resp.text else ""
                sample["body"] = body
            else:
                # Include just a snippet for context
                snippet = resp.text[:2000] if resp.text else ""
                sample["body_snippet"] = snippet

            # Error detection — look for DB/framework errors in response
            error_indicators = self._detect_errors(resp.text[:5000] if resp.text else "")
            if error_indicators:
                sample["error_indicators"] = error_indicators

            self.data["response_samples"].append(sample)
            sampled += 1

        self._log("SAMPLE", f"Collected {sampled} response samples")

    def _detect_errors(self, text):
        """Quick check for framework/DB error patterns in response text."""
        if not text:
            return []

        indicators = []
        patterns = [
            (r"SQL syntax.*?error", "SQL error"),
            (r"mysql_fetch|mysql_query", "MySQL function exposed"),
            (r"pg_query|pg_exec", "PostgreSQL function exposed"),
            (r"ORA-\d{5}", "Oracle error"),
            (r"Unclosed quotation mark", "MSSQL error"),
            (r"sqlite3\.\w+Error", "SQLite error"),
            (r"Traceback \(most recent call last\)", "Python traceback"),
            (r"java\.\w+\.Exception", "Java exception"),
            (r"System\.\w+Exception", ".NET exception"),
            (r"Fatal error.*?\.php", "PHP fatal error"),
            (r"DEBUG\s*[=:]\s*(?:True|true|1)", "Debug mode enabled"),
            (r"stack\s*trace", "Stack trace exposed"),
        ]

        for pattern, label in patterns:
            if re.search(pattern, text, re.I):
                indicators.append(label)

        return indicators

    def _build_summary(self, crawl_endpoints, headless_endpoints, js_urls):
        """Build a high-level attack surface summary."""
        all_eps = list(self.data["endpoints"]) + list(self.data["js_endpoints"])

        # Parameter stats
        all_params = []
        for ep in all_eps:
            all_params.extend(ep.get("parameters", []))

        param_locations = defaultdict(int)
        param_types = defaultdict(int)
        for p in all_params:
            param_locations[p["location"]] += 1
            param_types[p["type"]] += 1

        # Endpoint method distribution
        methods = defaultdict(int)
        for ep in all_eps:
            methods[ep["method"]] += 1

        # Source distribution
        sources = defaultdict(int)
        for ep in all_eps:
            sources[ep.get("source", "unknown")] += 1

        # Unique paths
        paths = set()
        for ep in all_eps:
            parsed = urlparse(ep.get("url", ""))
            paths.add(parsed.path)

        # Auth-related endpoints
        auth_paths = [p for p in paths if any(
            kw in p.lower() for kw in
            ["login", "auth", "signin", "signup", "register", "oauth",
             "token", "session", "password", "reset", "forgot"]
        )]

        # API endpoints
        api_paths = [p for p in paths if any(
            kw in p.lower() for kw in
            ["/api/", "/rest/", "/v1/", "/v2/", "/v3/", "/graphql"]
        )]

        # File upload indicators
        upload_endpoints = [
            ep for ep in all_eps
            if any(kw in ep.get("url", "").lower()
                   for kw in ["upload", "import", "attach", "file"])
            or ep.get("content_type", "") == "multipart/form-data"
        ]

        self.data["attack_surface_summary"] = {
            "total_endpoints": len(all_eps),
            "total_forms": len(self.data["forms"]),
            "total_parameters": len(all_params),
            "unique_paths": len(paths),
            "js_files_analyzed": len(js_urls),
            "methods": dict(methods),
            "param_locations": dict(param_locations),
            "param_types": dict(param_types),
            "sources": dict(sources),
            "auth_endpoints": auth_paths,
            "api_endpoints": api_paths,
            "upload_endpoints": [ep.get("url") for ep in upload_endpoints],
            "secrets_found": len(self.data["secrets_and_leaks"]),
            "security_header_issues": sum(
                1 for v in self.data.get("security_headers", {}).get("checks", {}).values()
                if v.get("issue")
            ),
            "error_indicators_found": sum(
                1 for s in self.data["response_samples"]
                if s.get("error_indicators")
            ),
        }


# ---------------------------------------------------------------------------
# Output + sanitization
# ---------------------------------------------------------------------------

def save_output(data, output_dir, sanitize=False, quiet=False):
    """Save gather data to disk. Optionally produce sanitized version."""
    os.makedirs(output_dir, exist_ok=True)

    # Always save raw version locally
    raw_path = os.path.join(output_dir, "gather_raw.json")
    with open(raw_path, "w") as f:
        json.dump(data, f, indent=2, default=str)

    if not quiet:
        print(f"\n{C.BOLD}Output:{C.RESET}")
        print(f"  {C.CYAN}Raw data:{C.RESET}      {raw_path}")

    if sanitize:
        domain = data.get("meta", {}).get("domain", "")
        # Strip port for domain matching
        domain_clean = domain.split(":")[0] if domain else ""

        sanitizer = Sanitizer(target_domain=domain_clean)

        sanitized = sanitizer.sanitize_dict(data)

        # Save sanitized version
        san_path = os.path.join(output_dir, "gather_sanitized.json")
        with open(san_path, "w") as f:
            json.dump(sanitized, f, indent=2, default=str)

        # Save mapping (keep this LOCAL — never send with sanitized data)
        map_path = os.path.join(output_dir, "sanitize_mapping.json")
        sanitizer.save_mapping(map_path)

        if not quiet:
            print(f"  {C.CYAN}Sanitized:{C.RESET}     {san_path}")
            print(f"  {C.CYAN}Mapping:{C.RESET}       {map_path} {C.DIM}(keep local — do NOT share){C.RESET}")
            print(f"\n  {C.DIM}Sanitized {len(sanitizer.get_mapping())} sensitive values{C.RESET}")
            print(f"  {C.GREEN}Send gather_sanitized.json to AI for analysis.{C.RESET}")
            print(f"  {C.GREEN}Use --desanitize to map AI findings back to real values.{C.RESET}")

    # Print summary
    if not quiet:
        summary = data.get("attack_surface_summary", {})
        print(f"\n{C.BOLD}{'=' * 60}{C.RESET}")
        print(f"{C.BOLD}  Recon Gather Summary{C.RESET}")
        print(f"{C.BOLD}{'=' * 60}{C.RESET}")
        print(f"  Endpoints:      {summary.get('total_endpoints', 0)}")
        print(f"  Forms:          {summary.get('total_forms', 0)}")
        print(f"  Parameters:     {summary.get('total_parameters', 0)}")
        print(f"  Unique paths:   {summary.get('unique_paths', 0)}")
        print(f"  JS files:       {summary.get('js_files_analyzed', 0)}")
        print(f"  Auth endpoints: {len(summary.get('auth_endpoints', []))}")
        print(f"  API endpoints:  {len(summary.get('api_endpoints', []))}")

        secrets = summary.get("secrets_found", 0)
        if secrets:
            print(f"  {C.RED}Secrets/leaks:  {secrets}{C.RESET}")

        header_issues = summary.get("security_header_issues", 0)
        if header_issues:
            print(f"  {C.YELLOW}Header issues:  {header_issues}{C.RESET}")

        errors = summary.get("error_indicators_found", 0)
        if errors:
            print(f"  {C.RED}Error leaks:    {errors}{C.RESET}")

        print(f"{C.BOLD}{'=' * 60}{C.RESET}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = build_parser()
    args = parser.parse_args()

    # ---- Handle utility modes ----

    # Sanitize an existing file
    if args.sanitize_only:
        with open(args.sanitize_only) as f:
            data = json.load(f)
        out_dir = os.path.dirname(args.sanitize_only) or "."
        save_output(data, out_dir, sanitize=True, quiet=args.quiet)
        return

    # De-sanitize
    if args.desanitize:
        san_file, map_file = args.desanitize
        sanitizer = Sanitizer.load_mapping(map_file)
        with open(san_file) as f:
            text = f.read()
        desanitized = sanitizer.desanitize(text)
        out_path = san_file.replace("sanitized", "desanitized")
        if out_path == san_file:
            out_path = san_file + ".desanitized"
        with open(out_path, "w") as f:
            f.write(desanitized)
        print(f"De-sanitized output: {out_path}")
        return

    # Logging
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG,
                            format="%(levelname)s %(name)s: %(message)s")
    elif not args.quiet:
        logging.basicConfig(level=logging.WARNING)
    else:
        logging.basicConfig(level=logging.ERROR)

    if not args.quiet:
        banner()

    # Validate URL
    parsed = urlparse(args.url)
    if not parsed.scheme or not parsed.netloc:
        print(f"{C.RED}Error: Invalid URL. Include scheme (http:// or https://){C.RESET}",
              file=sys.stderr)
        sys.exit(1)

    # ---- Network config ----
    proxy = args.proxy
    timeout = args.timeout
    rate_limit = args.rate_limit
    verify_ssl = not args.no_verify_ssl

    if args.tor:
        if timeout == 30:
            timeout = 60
        if rate_limit == 0.0:
            rate_limit = 1.0
        verify_ssl = False

        if not proxy:
            from sqli_recon.cli import _detect_tor_socks
            socks_proxy = _detect_tor_socks()
            if socks_proxy:
                proxy = socks_proxy

        if not args.quiet:
            print(f"  {C.CYAN}Tor mode:{C.RESET} proxy={proxy or 'system'}, "
                  f"timeout={timeout}s, rate_limit={rate_limit}s")

    # Parse cookies/headers
    cookies = {}
    if args.cookie:
        for pair in args.cookie.split(";"):
            pair = pair.strip()
            if "=" in pair:
                k, v = pair.split("=", 1)
                cookies[k.strip()] = v.strip()

    headers = {}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()

    # Build HTTP client
    client = HttpClient(
        proxy=proxy,
        timeout=timeout,
        user_agent=args.user_agent,
        cookies=cookies or None,
        headers=headers or None,
        verify_ssl=verify_ssl,
        rate_limit=rate_limit,
    )

    # ---- Auth ----
    if args.login:
        from sqli_recon.auth import SessionManager
        import getpass
        if ":" in args.login:
            username, password = args.login.split(":", 1)
        else:
            username = args.login
            password = getpass.getpass(f"Password for {username}: ")

        creds = {"username": username, "password": password}
        session_mgr = SessionManager(client, args.url, creds)

        if not args.quiet:
            print(f"  Attempting login as '{username}'...")

        if session_mgr.auto_login():
            client._session_mgr = session_mgr
            if not args.quiet:
                print(f"  {C.GREEN}Login successful{C.RESET}")
        else:
            if not args.quiet:
                print(f"  {C.YELLOW}Login failed — continuing unauthenticated{C.RESET}")

    # ---- Output directory ----
    if args.output:
        output_dir = args.output
    else:
        safe_host = parsed.netloc.replace(":", "_").replace(".", "-")
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        output_dir = f"recon_gather_{safe_host}_{timestamp}"

    if not args.quiet:
        print(f"  {C.BOLD}Target:{C.RESET}     {args.url}")
        print(f"  {C.BOLD}Scope:{C.RESET}      {args.scope}")
        print(f"  {C.BOLD}Sanitize:{C.RESET}   {'yes' if args.sanitize else 'no'}")
        print(f"  {C.BOLD}Output:{C.RESET}     {output_dir}")

    # ---- Run gather ----
    gatherer = ReconGatherer(
        client=client,
        target_url=args.url,
        scope=args.scope,
        max_depth=args.depth,
        max_pages=args.max_pages,
        sample_count=args.sample_responses,
        collect_bodies=args.collect_bodies,
        quiet=args.quiet,
    )

    start = time.time()
    data = gatherer.gather(
        do_js=not args.no_js,
        do_headless=args.headless,
        do_passive=not args.no_passive,
        proxy=proxy,
        verify_ssl=verify_ssl,
    )
    elapsed = time.time() - start
    data["meta"]["duration_seconds"] = round(elapsed, 1)

    if not args.quiet:
        print(f"\n  Completed in {elapsed:.1f}s")

    # ---- Save output ----
    save_output(data, output_dir, sanitize=args.sanitize, quiet=args.quiet)


if __name__ == "__main__":
    main()
