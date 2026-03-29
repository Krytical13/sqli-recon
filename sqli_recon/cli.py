"""CLI entry point and orchestration for sqli_recon."""

import argparse
import logging
import os
import sys
import time
from urllib.parse import urlparse

from sqli_recon import __version__
from sqli_recon.http_client import HttpClient
from sqli_recon.crawler import Crawler
from sqli_recon.js_analyzer import JsAnalyzer
from sqli_recon.param_finder import ParamFinder
from sqli_recon.classifier import Classifier
from sqli_recon.output import OutputGenerator, C
from sqli_recon.wordlists import API_PATHS


def banner():
    print(f"""{C.BOLD}{C.CYAN}
  ┌─────────────────────────────────────────┐
  │  sqli_recon v{__version__:<28s}│
  │  Active SQLi Surface Discovery          │
  └─────────────────────────────────────────┘{C.RESET}
""")


def log_phase(name):
    print(f"\n{C.BOLD}[{name}]{C.RESET} ", end="", flush=True)


def log_status(msg):
    print(f"{msg}", flush=True)


def log_progress(current, total):
    print(f"\r  {C.DIM}{current}/{total}{C.RESET}", end="", flush=True)


def build_parser():
    p = argparse.ArgumentParser(
        prog="sqli_recon",
        description="Active SQL injection surface discovery tool. "
                    "Crawls a target, analyzes JS, discovers hidden parameters, "
                    "and generates sqlmap-ready output.\n\n"
                    "The default scan runs everything: crawl, JS analysis, API brute-force,\n"
                    "and hidden parameter fuzzing. Use --quick for fast recon only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  %(prog)s -u https://target.com                   # Full scan (default)
  %(prog)s -u https://target.com --quick            # Fast: crawl + JS only
  %(prog)s -u https://target.com --tor              # Full scan via Tor
  %(prog)s -u http://example.onion --tor            # Tor hidden service
  %(prog)s -u https://target.com -o ./results       # Custom output dir
  %(prog)s -u https://target.com --headless         # Also use headless browser
  %(prog)s -u https://target.com --no-fuzz          # Skip param fuzzing
  %(prog)s -u https://target.com --cookie "s=abc"   # With auth cookie
        """,
    )

    # Target
    p.add_argument("-u", "--url", required=True,
                   help="Target URL to scan")

    # Presets
    p.add_argument("--quick", action="store_true",
                   help="Fast scan: crawl + JS analysis only (no fuzzing, no API brute)")

    # Crawling
    p.add_argument("--depth", type=int, default=3,
                   help="Maximum crawl depth (default: 3)")
    p.add_argument("--max-pages", type=int, default=200,
                   help="Maximum pages to crawl (default: 200)")
    p.add_argument("--scope", choices=["strict", "domain", "subdomain"], default="domain",
                   help="Crawl scope (default: domain)")

    # Feature opt-out (all ON by default)
    features = p.add_argument_group("feature toggles (all enabled by default)")
    features.add_argument("--no-fuzz", action="store_true",
                          help="Skip hidden parameter fuzzing")
    features.add_argument("--no-brute-api", action="store_true",
                          help="Skip API path brute-forcing")
    features.add_argument("--no-js", action="store_true",
                          help="Skip JavaScript file analysis")
    features.add_argument("--headless", action="store_true",
                          help="Also use headless browser for JS-heavy SPAs (requires Playwright)")
    features.add_argument("--fuzz-methods", action="store_true",
                          help="Also test HTTP methods (POST/PUT/DELETE) on GET endpoints")
    # Backwards compat: old --fuzz / --brute-api / --skip-js are silently accepted
    features.add_argument("--fuzz", action="store_true", help=argparse.SUPPRESS)
    features.add_argument("--brute-api", action="store_true", help=argparse.SUPPRESS)
    features.add_argument("--skip-js", action="store_true", help=argparse.SUPPRESS)

    # Network
    net = p.add_argument_group("network")
    net.add_argument("--proxy", type=str, default=None,
                     help="Proxy URL (e.g., http://127.0.0.1:8080)")
    net.add_argument("--tor", action="store_true",
                     help="Route through Tor (auto-detects SOCKS port, or uses system Tor on Whonix)")
    net.add_argument("--timeout", type=int, default=30,
                     help="Request timeout in seconds (default: 30)")
    net.add_argument("--rate-limit", type=float, default=0.0,
                     help="Min seconds between requests (default: 0)")
    net.add_argument("--no-verify-ssl", action="store_true",
                     help="Disable SSL certificate verification")
    net.add_argument("--user-agent", type=str, default=None,
                     help="Custom User-Agent string")
    net.add_argument("--login", type=str, default=None, metavar="USER:PASS",
                     help="Auto-login with credentials (format: 'username:password')")
    net.add_argument("--cookie", type=str, default=None,
                     help="Cookies (format: 'name=value; name2=value2')")
    net.add_argument("--header", action="append", default=[],
                     help="Extra header (format: 'Name: Value', repeatable)")

    # Output
    out = p.add_argument_group("output")
    out.add_argument("-o", "--output", type=str, default=None,
                     help="Output directory (default: ./sqli_recon_output)")
    out.add_argument("--resume", action="store_true",
                     help="Resume a previously interrupted scan (requires same -o directory)")
    out.add_argument("--json-only", action="store_true",
                     help="JSON report to stdout only (no files, no colors)")
    out.add_argument("--min-score", type=float, default=0.0,
                     help="Only show findings above this score (0.0-1.0)")
    out.add_argument("--top", type=int, default=50,
                     help="Show top N findings in terminal (default: 50)")
    out.add_argument("-v", "--verbose", action="store_true",
                     help="Debug logging")
    out.add_argument("-q", "--quiet", action="store_true",
                     help="Minimal output")

    return p


def parse_cookies(cookie_str):
    cookies = {}
    if cookie_str:
        for pair in cookie_str.split(";"):
            pair = pair.strip()
            if "=" in pair:
                k, v = pair.split("=", 1)
                cookies[k.strip()] = v.strip()
    return cookies


def parse_headers(header_list):
    headers = {}
    for h in header_list:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
    return headers


def main():
    parser = build_parser()
    args = parser.parse_args()

    # ---- Resolve feature flags ----
    # Default: everything ON. --quick or --no-X to opt out.
    # Backwards compat: old --fuzz, --brute-api are no-ops (already on).
    if args.quick:
        do_fuzz = False
        do_brute_api = False
        do_fuzz_methods = False
    else:
        do_fuzz = not args.no_fuzz
        do_brute_api = not args.no_brute_api
        do_fuzz_methods = args.fuzz_methods

    do_js = not args.no_js and not getattr(args, "skip_js", False)
    do_headless = args.headless

    # Logging
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG, format="%(levelname)s %(name)s: %(message)s")
    elif not args.quiet:
        logging.basicConfig(level=logging.WARNING)
    else:
        logging.basicConfig(level=logging.ERROR)

    if not args.json_only and not args.quiet:
        banner()

    # Validate URL
    parsed = urlparse(args.url)
    if not parsed.scheme or not parsed.netloc:
        print(f"{C.RED}Error: Invalid URL. Include scheme (http:// or https://){C.RESET}", file=sys.stderr)
        sys.exit(1)

    # ---- Network config ----
    proxy = args.proxy
    timeout = args.timeout
    rate_limit = args.rate_limit
    verify_ssl = not args.no_verify_ssl
    tor_mode = False

    if args.tor:
        tor_mode = True
        if timeout == 30:
            timeout = 60
        if rate_limit == 0.0:
            rate_limit = 1.0
        verify_ssl = False

        if proxy:
            tor_routing = f"proxy={proxy}"
        else:
            socks_proxy = _detect_tor_socks()
            if socks_proxy:
                proxy = socks_proxy
                tor_routing = f"proxy={proxy}"
            else:
                tor_routing = "system-level (no SOCKS proxy needed)"

        if not args.quiet and not args.json_only:
            print(f"  {C.CYAN}Tor mode:{C.RESET} {tor_routing}, timeout={timeout}s, "
                  f"rate_limit={rate_limit}s, ssl_verify=off")

    # Output directory — unique per target by default to avoid conflicts
    if args.output:
        output_dir = args.output
    else:
        # Generate a name from the target: scheme_host_timestamp
        safe_host = parsed.netloc.replace(":", "_").replace(".", "-")
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        output_dir = f"sqli_recon_{safe_host}_{timestamp}"

    # Print config
    if not args.quiet and not args.json_only:
        print(f"  {C.BOLD}Target:{C.RESET}     {args.url}")
        print(f"  {C.BOLD}Scope:{C.RESET}      {args.scope}")
        print(f"  {C.BOLD}Depth:{C.RESET}      {args.depth}")
        print(f"  {C.BOLD}Max pages:{C.RESET}  {args.max_pages}")
        if proxy and not tor_mode:
            print(f"  {C.BOLD}Proxy:{C.RESET}     {proxy}")
        features = ["crawl"]
        if do_js:
            features.append("js-analysis")
        if do_headless:
            features.append("headless")
        if do_brute_api:
            features.append("api-brute")
        if do_fuzz:
            features.append("param-fuzz")
        if do_fuzz_methods:
            features.append("method-fuzz")
        mode = "quick" if args.quick else "full"
        print(f"  {C.BOLD}Mode:{C.RESET}      {mode}")
        print(f"  {C.BOLD}Features:{C.RESET}   {', '.join(features)}")
        print(f"  {C.BOLD}Output:{C.RESET}     {output_dir}")

    # Initialize HTTP client
    client = HttpClient(
        proxy=proxy,
        timeout=timeout,
        user_agent=args.user_agent,
        cookies=parse_cookies(args.cookie) if args.cookie else None,
        headers=parse_headers(args.header) if args.header else None,
        verify_ssl=verify_ssl,
        rate_limit=rate_limit,
    )

    # Verify target is reachable
    if not args.quiet and not args.json_only:
        log_phase("PROBE")
    probe = client.get(args.url)
    if probe is None:
        print(f"\n{C.RED}Error: Could not reach {args.url}{C.RESET}", file=sys.stderr)
        if args.tor:
            print(f"{C.YELLOW}Hint: Is Tor running? (sudo systemctl start tor){C.RESET}", file=sys.stderr)
        sys.exit(1)
    # Tech fingerprint from probe response
    from sqli_recon.intelligence import TechFingerprint, ResponseAnalyzer, ErrorDetector, GraphQLIntrospector
    tech_fp = TechFingerprint()
    tech_fp.analyze_response(probe)

    if not args.quiet and not args.json_only:
        log_status(f"Target reachable ({probe.status_code})")
        if tech_fp.detected:
            techs = ", ".join(f"{t} ({c:.0%})" for t, c in tech_fp.summary()[:4])
            print(f"  {C.DIM}Tech: {techs}{C.RESET}")

    # ---- Auth: auto-login if credentials provided ----
    from sqli_recon.auth import SessionManager
    credentials = None
    session_mgr = None

    if args.login:
        if ":" not in args.login:
            print(f"{C.RED}Error: --login format is username:password{C.RESET}", file=sys.stderr)
            sys.exit(1)
        username, password = args.login.split(":", 1)
        credentials = {"username": username, "password": password}

        session_mgr = SessionManager(client, args.url, credentials)

        if not args.quiet and not args.json_only:
            log_phase("AUTH")
            log_status(f"Attempting auto-login as '{username}'...")

        if session_mgr.auto_login():
            if not args.quiet and not args.json_only:
                print(f"  {C.GREEN}Login successful — scanning as authenticated user{C.RESET}")
        else:
            if not args.quiet and not args.json_only:
                print(f"  {C.YELLOW}Login failed — continuing as unauthenticated{C.RESET}")
                print(f"  {C.DIM}Try --cookie with manually obtained session cookies instead{C.RESET}")

    all_endpoints = []
    js_urls = []
    start_time = time.time()
    resume_phase = None

    # Resume from checkpoint if requested
    from sqli_recon.checkpoint import save_checkpoint, load_checkpoint, clear_checkpoint
    if args.resume:
        ckpt = load_checkpoint(output_dir)
        if ckpt:
            resume_phase, all_endpoints, js_urls, ckpt_meta = ckpt
            if not args.quiet and not args.json_only:
                print(f"  {C.CYAN}Resuming from phase: {resume_phase} "
                      f"({len(all_endpoints)} endpoints loaded){C.RESET}")
        else:
            if not args.quiet and not args.json_only:
                print(f"  {C.DIM}No checkpoint found — starting fresh{C.RESET}")

    # Get platform-aware scan recommendations
    scan_rec = tech_fp.scan_recommendations()
    priority_paths = tech_fp.priority_endpoints()

    if priority_paths and not args.quiet and not args.json_only:
        top_platform = tech_fp.summary()[0][0] if tech_fp.summary() else "Unknown"
        print(f"  {C.CYAN}{top_platform} detected:{C.RESET} {len(priority_paths)} platform-specific endpoints queued")
        if scan_rec["skip_api_brute"] and do_brute_api:
            print(f"  {C.DIM}Skipping generic API brute — platform endpoints cover it{C.RESET}")
            do_brute_api = False
        if scan_rec["skip_graphql"]:
            print(f"  {C.DIM}Skipping GraphQL — not typical for this platform{C.RESET}")

    # Apply extra depth for deep platforms (forums)
    crawl_depth = args.depth + scan_rec.get("extra_depth", 0)

    # ---- Phase 1: Active Crawl ----
    if not args.quiet and not args.json_only:
        log_phase("CRAWL")
        if resume_phase:
            log_status(f"Resumed — {len(all_endpoints)} endpoints from checkpoint")
        else:
            log_status("Spidering target site...")

    if not resume_phase:
        crawler = Crawler(
            client=client,
            target_url=args.url,
            max_depth=crawl_depth,
            max_pages=args.max_pages,
            scope=args.scope,
        )

        seed_urls = [f"{parsed.scheme}://{parsed.netloc}{path}" for path in priority_paths]

        def crawl_progress(done, queued):
            if not args.quiet and not args.json_only:
                print(f"\r  {C.DIM}Pages: {done} crawled, {queued} queued{C.RESET}    ", end="", flush=True)

        endpoints, js_urls = crawler.crawl(progress_callback=crawl_progress, seed_urls=seed_urls)
        all_endpoints.extend(endpoints)

        if not args.quiet and not args.json_only:
            forms = sum(1 for e in endpoints if e.source.value == "form")
            print(f"\r  Found {len(endpoints)} endpoints, {forms} forms, {len(js_urls)} JS files           ")

        # Save checkpoint after crawl
        save_checkpoint(output_dir, "crawl_done", all_endpoints, js_urls)

    captcha_abort = client.stats["captchas"] >= 5
    if captcha_abort and not args.quiet and not args.json_only:
        print(f"\n  {C.RED}{C.BOLD}CAPTCHA wall hit — crawl aborted early.{C.RESET}")
        print(f"  {C.YELLOW}Saving partial results. To get full coverage:{C.RESET}")
        print(f"  {C.YELLOW}  1. Open the site in Tor Browser, solve the CAPTCHA{C.RESET}")
        print(f"  {C.YELLOW}  2. Copy all cookies from DevTools (Network tab → any request → Cookie header){C.RESET}")
        print(f"  {C.YELLOW}  3. Re-run: ./scan -u {args.url} --cookie \"paste_cookies_here\"{C.RESET}")
        if not args.tor:
            print(f"  {C.YELLOW}  Or try: --headless (real browser can pass JS challenges){C.RESET}")
        print()

    # ---- Phase 1b: Headless Browser Crawl (optional) ----
    if do_headless:
        try:
            from sqli_recon.headless import HeadlessCrawler, HAS_PLAYWRIGHT
            if not HAS_PLAYWRIGHT:
                raise ImportError("playwright not installed")

            if not args.quiet and not args.json_only:
                log_phase("HEADLESS")
                log_status("Launching headless browser to capture XHR/fetch calls...")

            headless = HeadlessCrawler(
                target_url=args.url,
                max_pages=min(args.max_pages, 30),  # Cap headless pages (slow)
                scope=args.scope,
                proxy=proxy,
                timeout=timeout,
                verify_ssl=verify_ssl,
            )

            # Visit pages the HTTP crawler found, plus the target
            urls_for_headless = [args.url] + [
                e.url for e in endpoints
                if e.source.value in ("crawl", "sitemap", "robots")
            ]
            # Deduplicate
            seen_urls = set()
            unique_urls = []
            for u in urls_for_headless:
                base = urlparse(u)._replace(query="", fragment="").geturl()
                if base not in seen_urls:
                    seen_urls.add(base)
                    unique_urls.append(u)

            def headless_progress(done, total):
                if not args.quiet and not args.json_only:
                    print(f"\r  {C.DIM}Rendered {done} pages, {total} queued{C.RESET}    ",
                          end="", flush=True)

            headless_endpoints = headless.crawl(
                urls_to_visit=unique_urls[:30],
                progress_callback=headless_progress,
            )
            all_endpoints.extend(headless_endpoints)

            if not args.quiet and not args.json_only:
                xhr_count = sum(1 for e in headless_endpoints
                                if e.content_type and "json" in e.content_type)
                print(f"\r  Captured {len(headless_endpoints)} endpoints "
                      f"({xhr_count} XHR/fetch API calls)           ")

        except ImportError:
            if not args.quiet and not args.json_only:
                log_phase("HEADLESS")
                log_status(f"{C.YELLOW}Skipped — playwright not installed. "
                           f"Install with: pip install playwright && playwright install chromium{C.RESET}")

    # ---- Phase 2: API Path Brute-Force ----
    if do_brute_api:
        if not args.quiet and not args.json_only:
            log_phase("API BRUTE")
            log_status("Testing common API paths...")

        from concurrent.futures import ThreadPoolExecutor, as_completed
        from sqli_recon.models import Source
        api_found = [0]
        done_count = [0]

        def _test_api_path(path):
            url = f"{parsed.scheme}://{parsed.netloc}{path}"
            resp = client.get(url)
            done_count[0] += 1
            if resp is not None and resp.status_code not in (404, 403, 500, 502, 503):
                return _url_to_endpoint(url, resp, Source.API_BRUTE)
            return None

        with ThreadPoolExecutor(max_workers=5) as pool:
            futures = {pool.submit(_test_api_path, p): p for p in API_PATHS}
            for future in as_completed(futures):
                ep = future.result()
                if ep:
                    all_endpoints.append(ep)
                    api_found[0] += 1

        if not args.quiet and not args.json_only:
            print(f"\r  Discovered {api_found[0]} live API endpoints from {len(API_PATHS)} tested           ")

    # ---- Phase 3: JavaScript Analysis ----
    if do_js and js_urls:
        if not args.quiet and not args.json_only:
            log_phase("JS ANALYSIS")
            log_status(f"Analyzing {len(js_urls)} JavaScript files...")

        analyzer = JsAnalyzer(client, args.url)

        def js_progress(done, total):
            if not args.quiet and not args.json_only:
                print(f"\r  {C.DIM}Analyzed {done}/{total} files{C.RESET}    ", end="", flush=True)

        js_endpoints = analyzer.analyze(js_urls, progress_callback=js_progress)
        all_endpoints.extend(js_endpoints)

        if not args.quiet and not args.json_only:
            print(f"\r  Extracted {len(js_endpoints)} additional endpoints from JS           ")

    # ---- Phase 4: Hidden Parameter Fuzzing ----
    if do_fuzz:
        if not args.quiet and not args.json_only:
            log_phase("PARAM FUZZ")
            log_status(f"Fuzzing {len(all_endpoints)} endpoints for hidden parameters...")

        finder = ParamFinder(client)

        def fuzz_progress(done, total):
            if not args.quiet and not args.json_only:
                print(f"\r  {C.DIM}Fuzzed {done}/{total} endpoints{C.RESET}    ", end="", flush=True)

        fuzz_results = finder.discover(all_endpoints, progress_callback=fuzz_progress)

        if not args.quiet and not args.json_only:
            new_params = sum(len(e.parameters) for e in fuzz_results) - sum(
                len(e.parameters) for e in all_endpoints if e in fuzz_results)
            print(f"\r  Discovered {len(fuzz_results)} endpoints with hidden parameters           ")

        # Add fuzz results alongside originals (don't replace — different sources
        # may have found different params on the same base URL)
        all_endpoints.extend(fuzz_results)

    # ---- Phase 5: HTTP Method Discovery ----
    if do_fuzz_methods:
        if not args.quiet and not args.json_only:
            log_phase("METHOD FUZZ")
            log_status(f"Testing HTTP methods on {len(all_endpoints)} endpoints...")

        finder = ParamFinder(client)
        method_results = finder.discover_methods(all_endpoints)
        all_endpoints.extend(method_results)

        if not args.quiet and not args.json_only:
            print(f"  Found {len(method_results)} additional method variants")

    # ---- Phase 5b: Header Injection Scan ----
    if all_endpoints and not captcha_abort:
        from sqli_recon.intelligence import HeaderInjectionScanner
        header_scanner = HeaderInjectionScanner(client)
        header_eps = header_scanner.scan_endpoints(all_endpoints)
        if header_eps:
            all_endpoints.extend(header_eps)
            if not args.quiet and not args.json_only:
                log_phase("HEADERS")
                for ep in header_eps:
                    hdr = ep.parameters[0].name
                    val = ep.parameters[0].value
                    log_status(f"{C.RED}Injectable header: {hdr} on {ep.base_url} {val}{C.RESET}")

    # ---- Phase 6: GraphQL Introspection ----
    if not scan_rec.get("skip_graphql"):
        gql = GraphQLIntrospector(client, args.url)
        gql_endpoints = gql.discover_and_introspect(known_endpoints=all_endpoints)
        if gql_endpoints:
            all_endpoints.extend(gql_endpoints)
            if not args.quiet and not args.json_only:
                log_phase("GRAPHQL")
                args_count = sum(len(e.parameters) for e in gql_endpoints)
                log_status(f"Introspection succeeded — {len(gql_endpoints)} operations, "
                           f"{args_count} arguments discovered")

    # ---- Phase 7: Response Analysis ----
    # Check endpoints that returned data during crawl for DB-row patterns
    db_like_urls = set()
    for ep in all_endpoints:
        if ep.status_code and ep.status_code == 200 and ep.method == "GET":
            resp = client.get(ep.url)
            if resp:
                tech_fp.analyze_response(resp)  # Also feed more pages to tech fingerprint
                is_db, reason = ResponseAnalyzer.looks_like_db_rows(resp)
                if is_db:
                    db_like_urls.add(ep.base_url)
                    ep.response_headers["_db_like"] = reason
            # Only check a handful to avoid excess requests
            if len(db_like_urls) >= 5:
                break

    # ---- Phase 8: Classification ----
    if not args.quiet and not args.json_only:
        log_phase("CLASSIFY")
        log_status(f"Scoring {sum(len(e.parameters) for e in all_endpoints)} parameters "
                   f"across {len(all_endpoints)} endpoints...")

    # Apply tech fingerprint modifier to classifier
    tech_modifier = tech_fp.sqli_risk_modifier()
    classifier = Classifier()
    findings = classifier.classify(all_endpoints, tech_modifier=tech_modifier,
                                    db_like_urls=db_like_urls)

    # Apply minimum score filter
    if args.min_score > 0:
        findings = [f for f in findings if f.score >= args.min_score]

    # ---- Phase 9: Error-based pre-detection ----
    if not args.quiet and not args.json_only:
        log_phase("ERROR DETECT")
        log_status("Probing high-value params for DB error responses...")

    confirmed = []
    if captcha_abort:
        if not args.quiet and not args.json_only:
            print(f"  {C.DIM}Skipped — CAPTCHA wall would block probes{C.RESET}")
    else:
        detector = ErrorDetector(client)

        def error_progress(done, total):
            if not args.quiet and not args.json_only:
                print(f"\r  {C.DIM}Tested {done}/{total} params{C.RESET}    ", end="", flush=True)

        confirmed = detector.test_findings(findings, min_score=0.3, progress_callback=error_progress)

    if confirmed:
        # Promote confirmed findings to HIGH with DB type info
        confirmed_keys = {}
        for finding, db_type in confirmed:
            key = (finding.endpoint.base_url, finding.parameter.name)
            confirmed_keys[key] = db_type

        for f in findings:
            key = (f.endpoint.base_url, f.parameter.name)
            if key in confirmed_keys:
                db_type = confirmed_keys[key]
                f.score = max(f.score, 0.90)
                f.reasons.insert(0, f"CONFIRMED: DB error detected ({db_type}) — injectable")

        # Re-sort after score changes
        findings.sort(key=lambda f: (-f.score, f.parameter.name))

    if not args.quiet and not args.json_only:
        if confirmed:
            print(f"\r  {C.RED}{C.BOLD}{len(confirmed)} CONFIRMED injectable params{C.RESET}          ")
        else:
            print(f"\r  No DB errors triggered (params may still be injectable via blind techniques)          ")

    elapsed = time.time() - start_time

    if not args.quiet and not args.json_only:
        print(f"  Completed in {elapsed:.1f}s")
        if tech_fp.detected:
            techs = ", ".join(f"{t}" for t, c in tech_fp.summary()[:5])
            print(f"  {C.DIM}Stack: {techs} (modifier: {tech_modifier:+.2f}){C.RESET}")

    # ---- Network stats ----
    if not args.quiet and not args.json_only:
        s = client.stats
        if s["waf_blocks"] > 0 or s["rate_limited"] > 0 or s["captchas"] > 0:
            log_phase("NETWORK")
            log_status(
                f"{s['requests']} requests, "
                f"{s['success']} OK, "
                f"{s['waf_blocks']} WAF blocks, "
                f"{s['rate_limited']} rate-limited, "
                f"{s['captchas']} CAPTCHAs, "
                f"{s['timeouts']} timeouts, "
                f"{s['errors']} errors"
            )
            if s["captchas"] > 0:
                print(f"  {C.YELLOW}CAPTCHA challenges detected — {s['captchas']} responses were challenge pages.{C.RESET}")
                print(f"  {C.YELLOW}Those pages were excluded from analysis. Results may be incomplete.{C.RESET}")
                print(f"  {C.YELLOW}Try: --headless (real browser can pass JS challenges), or --rate-limit 3{C.RESET}")
            if s["waf_blocks"] > 0:
                print(f"  {C.YELLOW}WAF detected — parameter fuzzing may have triggered blocks.{C.RESET}")
                print(f"  {C.YELLOW}Use --rate-limit to slow down, or review WAF-blocked requests.{C.RESET}")
            if s["rate_limited"] > 0:
                print(f"  {C.YELLOW}Rate limiting detected — adaptive backoff was applied.{C.RESET}")
                if client._adaptive_delay > 0:
                    print(f"  {C.DIM}Final adaptive delay: {client._adaptive_delay:.1f}s{C.RESET}")

    # ---- Phase 7: Output ----
    if args.json_only:
        # JSON-only mode: output to stdout
        import json
        report = {
            "findings": [
                {
                    "score": round(f.score, 3),
                    "risk": f.risk_level,
                    "method": f.endpoint.method,
                    "url": f.endpoint.url,
                    "parameter": f.parameter.name,
                    "location": f.parameter.location.value,
                    "type": f.parameter.param_type,
                    "source": f.endpoint.source.value,
                    "reasons": f.reasons,
                }
                for f in findings
            ]
        }
        print(json.dumps(report, indent=2))
        return

    # Get tech-aware sqlmap flags
    sqlmap_extra_flags, sqlmap_notes = tech_fp.sqlmap_flags()

    # Generate output files
    output_gen = OutputGenerator(findings, output_dir, sqlmap_extra_flags=sqlmap_extra_flags,
                                 sqlmap_notes=sqlmap_notes)
    result = output_gen.generate_all()

    # Generate HTML report
    from sqli_recon.report import generate_html_report
    html_path = generate_html_report(
        findings, output_dir,
        tech_summary=tech_fp.summary() if tech_fp.detected else None,
        sqlmap_notes=sqlmap_notes,
        stats=client.stats,
    )

    # Clear checkpoint — scan completed successfully
    clear_checkpoint(output_dir)

    # Print terminal summary
    output_gen.print_summary(max_rows=args.top)
    output_gen.print_top_reasons(top_n=min(10, len(findings)))

    # Second-order SQLi hints
    from sqli_recon.intelligence import SecondOrderAnalyzer
    second_order = SecondOrderAnalyzer.analyze(all_endpoints)
    if second_order and not args.quiet and not args.json_only:
        print(f"\n{C.BOLD}Second-order SQLi hints ({len(second_order)}):{C.RESET}")
        for hint in second_order[:5]:
            print(f"  {C.YELLOW}{hint['hint']}{C.RESET}")

    # Platform-specific recon tips
    platform_tips = tech_fp.platform_recon_tips()
    if platform_tips and not args.quiet:
        print(f"\n{C.BOLD}Platform tips:{C.RESET}")
        for tip in platform_tips:
            print(f"  {C.YELLOW}{tip}{C.RESET}")

    # Print output file locations
    if result:
        print(f"\n{C.BOLD}Output files:{C.RESET}")
        print(f"  {C.CYAN}sqlmap URLs:{C.RESET}     {result['urls_file']} ({result['urls_count']} URLs)")
        print(f"  {C.CYAN}Request files:{C.RESET}   {result['requests_dir']}/ ({result['requests_count']} files)")
        print(f"  {C.CYAN}JSON report:{C.RESET}    {result['report_file']}")
        print(f"  {C.CYAN}HTML report:{C.RESET}    {html_path}")
        print(f"  {C.CYAN}sqlmap commands:{C.RESET} {result['commands_file']}")

        # Quick-start hints — show the right command for what was found
        if findings:
            from sqli_recon.models import ParamLocation
            has_get = any(f.parameter.location in (ParamLocation.QUERY, ParamLocation.PATH) for f in findings)
            has_post = any(f.parameter.location in (ParamLocation.BODY, ParamLocation.JSON) for f in findings)

            extra = " ".join(sqlmap_extra_flags) if sqlmap_extra_flags else ""
            if sqlmap_notes and not args.quiet:
                print(f"\n{C.BOLD}sqlmap optimization:{C.RESET}")
                for note in sqlmap_notes:
                    print(f"  {C.DIM}{note}{C.RESET}")

            print(f"\n{C.BOLD}Quick start:{C.RESET}")
            if has_get and result['urls_count'] > 0:
                cmd = f"sqlmap -m {result['urls_file']} --batch --smart"
                if extra:
                    cmd += f" {extra}"
                print(f"  {C.GREEN}{cmd}{C.RESET}")
            if has_post:
                # Find the top POST finding and suggest its request file
                top_post = next((f for f in findings if f.parameter.location in (ParamLocation.BODY, ParamLocation.JSON)), None)
                if top_post:
                    idx = findings.index(top_post)
                    import os
                    req_files = sorted(f for f in os.listdir(result['requests_dir']) if f.startswith(f"{idx+1:03d}_"))
                    if req_files:
                        req_path = os.path.join(result['requests_dir'], req_files[0])
                        p_flag = f" -p {top_post.parameter.name}" if top_post.parameter.location == ParamLocation.JSON else ""
                        print(f"  {C.GREEN}sqlmap -r \"{req_path}\"{p_flag} --batch --level=2{C.RESET}")
            if not has_get and not has_post:
                print(f"  {C.DIM}No actionable findings for sqlmap.{C.RESET}")
            print(f"  {C.DIM}See {result['commands_file']} for all suggested commands{C.RESET}")


def _url_to_endpoint(url, response, source):
    """Helper to create an Endpoint from a URL + response."""
    from sqli_recon.models import Endpoint, Parameter, ParamLocation
    from urllib.parse import parse_qs

    parsed = urlparse(url)
    params = []
    if parsed.query:
        qs = parse_qs(parsed.query, keep_blank_values=True)
        for name, values in qs.items():
            value = values[0] if values else ""
            params.append(Parameter(name=name, location=ParamLocation.QUERY, value=value))

    return Endpoint(
        url=url,
        method="GET",
        parameters=params,
        source=source,
        status_code=response.status_code,
        response_headers=dict(response.headers),
    )


def _detect_tor_socks():
    """Auto-detect a local Tor SOCKS port. Returns proxy URL or None."""
    import socket
    # Common Tor SOCKS ports: 9050 (system Tor), 9150 (Tor Browser)
    for port in [9050, 9150]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect(("127.0.0.1", port))
            s.close()
            return f"socks5h://127.0.0.1:{port}"
        except (ConnectionRefusedError, OSError):
            continue
    return None


if __name__ == "__main__":
    main()
