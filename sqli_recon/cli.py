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
    net.add_argument("--cookie", type=str, default=None,
                     help="Cookies (format: 'name=value; name2=value2')")
    net.add_argument("--header", action="append", default=[],
                     help="Extra header (format: 'Name: Value', repeatable)")

    # Output
    out = p.add_argument_group("output")
    out.add_argument("-o", "--output", type=str, default=None,
                     help="Output directory (default: ./sqli_recon_output)")
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

    # Output directory
    output_dir = args.output or "sqli_recon_output"

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
    if not args.quiet and not args.json_only:
        log_status(f"Target reachable ({probe.status_code})")

    all_endpoints = []
    start_time = time.time()

    # ---- Phase 1: Active Crawl ----
    if not args.quiet and not args.json_only:
        log_phase("CRAWL")
        log_status("Spidering target site...")

    crawler = Crawler(
        client=client,
        target_url=args.url,
        max_depth=args.depth,
        max_pages=args.max_pages,
        scope=args.scope,
    )

    def crawl_progress(done, queued):
        if not args.quiet and not args.json_only:
            print(f"\r  {C.DIM}Pages: {done} crawled, {queued} queued{C.RESET}    ", end="", flush=True)

    endpoints, js_urls = crawler.crawl(progress_callback=crawl_progress)
    all_endpoints.extend(endpoints)

    if not args.quiet and not args.json_only:
        forms = sum(1 for e in endpoints if e.source.value == "form")
        print(f"\r  Found {len(endpoints)} endpoints, {forms} forms, {len(js_urls)} JS files           ")

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

        api_found = 0
        for i, path in enumerate(API_PATHS):
            url = f"{parsed.scheme}://{parsed.netloc}{path}"
            resp = client.get(url)
            if resp is not None and resp.status_code not in (404, 403, 500, 502, 503):
                from sqli_recon.models import Source
                ep = _url_to_endpoint(url, resp, Source.API_BRUTE)
                all_endpoints.append(ep)
                api_found += 1

            if not args.quiet and not args.json_only and (i + 1) % 10 == 0:
                print(f"\r  {C.DIM}Tested {i+1}/{len(API_PATHS)} paths, found {api_found}{C.RESET}    ",
                      end="", flush=True)

        if not args.quiet and not args.json_only:
            print(f"\r  Discovered {api_found} live API endpoints from {len(API_PATHS)} tested           ")

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

    # ---- Phase 6: Classification ----
    if not args.quiet and not args.json_only:
        log_phase("CLASSIFY")
        log_status(f"Scoring {sum(len(e.parameters) for e in all_endpoints)} parameters "
                   f"across {len(all_endpoints)} endpoints...")

    classifier = Classifier()
    findings = classifier.classify(all_endpoints)

    # Apply minimum score filter
    if args.min_score > 0:
        findings = [f for f in findings if f.score >= args.min_score]

    elapsed = time.time() - start_time

    if not args.quiet and not args.json_only:
        print(f"  Completed in {elapsed:.1f}s")

    # ---- Network stats ----
    if not args.quiet and not args.json_only:
        s = client.stats
        if s["waf_blocks"] > 0 or s["rate_limited"] > 0:
            log_phase("NETWORK")
            log_status(
                f"{s['requests']} requests, "
                f"{s['success']} OK, "
                f"{s['waf_blocks']} WAF blocks, "
                f"{s['rate_limited']} rate-limited, "
                f"{s['timeouts']} timeouts, "
                f"{s['errors']} errors"
            )
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

    # Generate output files
    output_gen = OutputGenerator(findings, output_dir)
    result = output_gen.generate_all()

    # Print terminal summary
    output_gen.print_summary(max_rows=args.top)
    output_gen.print_top_reasons(top_n=min(10, len(findings)))

    # Print output file locations
    if result:
        print(f"\n{C.BOLD}Output files:{C.RESET}")
        print(f"  {C.CYAN}sqlmap URLs:{C.RESET}     {result['urls_file']} ({result['urls_count']} URLs)")
        print(f"  {C.CYAN}Request files:{C.RESET}   {result['requests_dir']}/ ({result['requests_count']} files)")
        print(f"  {C.CYAN}JSON report:{C.RESET}    {result['report_file']}")
        print(f"  {C.CYAN}sqlmap commands:{C.RESET} {result['commands_file']}")

        # Quick-start hints — show the right command for what was found
        if findings:
            from sqli_recon.models import ParamLocation
            has_get = any(f.parameter.location in (ParamLocation.QUERY, ParamLocation.PATH) for f in findings)
            has_post = any(f.parameter.location in (ParamLocation.BODY, ParamLocation.JSON) for f in findings)

            print(f"\n{C.BOLD}Quick start:{C.RESET}")
            if has_get and result['urls_count'] > 0:
                print(f"  {C.GREEN}sqlmap -m {result['urls_file']} --batch --smart{C.RESET}")
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
