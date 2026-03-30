"""CLI entry point for infra_map."""

import argparse
import logging
import os
import sys
import time

import requests

from infra_map import __version__
from infra_map.graph import InfraGraph, NodeType
from infra_map.mapper import Mapper
from infra_map.output import C, print_tree, print_summary, write_json, write_domains, write_ips


def banner():
    print(f"""{C.BOLD}{C.CYAN}
  ┌─────────────────────────────────────────┐
  │  infra_map v{__version__:<28s}│
  │  Recursive Infrastructure Mapper        │
  └─────────────────────────────────────────┘{C.RESET}
""")


def build_parser():
    p = argparse.ArgumentParser(
        prog="infra_map",
        description="Recursively maps domain/IP/cert/org relationships using only free, "
                    "no-auth public data sources. No API keys needed.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  %(prog)s example.com                      # Map from a domain
  %(prog)s 93.184.216.34                    # Map from an IP
  %(prog)s example.com --depth 3            # Deeper recursion
  %(prog)s example.com --tor                # Route lookups through Tor
  %(prog)s example.com -o ./results         # Save output files

data sources (all free, no API keys):
  crt.sh           Certificate Transparency logs
  DNS              A/AAAA/MX/NS/CNAME/PTR + zone transfer attempts
  HackerTarget     Reverse IP lookup + host search (100/day)
  Wayback Machine  Historical subdomains from web archives
  BGPView          ASN and IP prefix lookups
  WHOIS            Registrant organization and email

optional API sources (keys in ~/.config/infra_map/keys.conf):
  Shodan           Host info, certs, banners, domains per IP
  Censys           Deep cert search, DNS names, host services
        """,
    )

    p.add_argument("--setup-keys", action="store_true",
                   help="Create API key config file at ~/.config/infra_map/keys.conf and exit")

    p.add_argument("target", nargs="?", default=None,
                   help="Seed domain or IP address to start mapping from")
    p.add_argument("--depth", type=int, default=2,
                   help="Maximum recursion depth (default: 2, higher = slower but broader)")
    p.add_argument("--rate-limit", type=float, default=1.5,
                   help="Seconds between API requests (default: 1.5)")

    p.add_argument("--no-whois", action="store_true", help="Skip WHOIS lookups")
    p.add_argument("--no-wayback", action="store_true", help="Skip Wayback Machine")
    p.add_argument("--probe", action="store_true",
                   help="Live-probe all discovered domains (HTTP status, CDN detection, tech fingerprint)")
    p.add_argument("--scan", action="store_true",
                   help="Auto-feed live non-CDN domains into sqli_recon scanner after mapping")

    net = p.add_argument_group("network")
    net.add_argument("--tor", action="store_true",
                     help="Route all lookups through Tor")
    net.add_argument("--proxy", type=str, default=None,
                     help="Proxy URL for HTTP requests")
    net.add_argument("--timeout", type=int, default=30,
                     help="Request timeout in seconds (default: 30)")

    out = p.add_argument_group("output")
    out.add_argument("-o", "--output", type=str, default=None,
                     help="Output directory for results")
    out.add_argument("--json-only", action="store_true",
                     help="JSON output to stdout only")
    out.add_argument("-v", "--verbose", action="store_true",
                     help="Debug logging")
    out.add_argument("-q", "--quiet", action="store_true",
                     help="Minimal output")

    return p


def _detect_tor_socks():
    import socket
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


def _is_ip(value):
    import socket
    try:
        socket.inet_aton(value)
        return True
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, value)
        return True
    except OSError:
        return False


def main():
    parser = build_parser()
    args = parser.parse_args()

    # --setup-keys: create config template and exit
    if args.setup_keys:
        from infra_map.config import setup_config
        path = setup_config()
        print(f"Config file created: {path}")
        print(f"Edit it to add your API keys (Shodan, Censys).")
        print(f"Keys are optional — everything works without them.")
        return

    if not args.target:
        parser.error("target is required (domain or IP)")

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG, format="%(levelname)s %(name)s: %(message)s")
    elif not args.quiet:
        logging.basicConfig(level=logging.WARNING)
    else:
        logging.basicConfig(level=logging.ERROR)

    if not args.json_only and not args.quiet:
        banner()

    # Setup HTTP session
    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    session.verify = False

    proxy = args.proxy
    rate_limit = args.rate_limit
    timeout = args.timeout

    if args.tor:
        proxy = proxy or _detect_tor_socks()
        if proxy:
            if not args.quiet and not args.json_only:
                print(f"  {C.CYAN}Tor mode:{C.RESET} proxy={proxy}")
        else:
            if not args.quiet and not args.json_only:
                print(f"  {C.CYAN}Tor mode:{C.RESET} system-level (no SOCKS proxy needed)")
        if timeout == 30:
            timeout = 60
        if rate_limit == 1.5:
            rate_limit = 2.0

    if proxy:
        session.proxies = {"http": proxy, "https": proxy}

    # Determine seed type
    target = args.target.strip().lower()
    if _is_ip(target):
        seed_type = NodeType.IP
    else:
        # Strip protocol if provided
        target = target.replace("https://", "").replace("http://", "").split("/")[0]
        seed_type = NodeType.DOMAIN

    # Load API keys (optional)
    from infra_map.config import load_keys, has_any_keys
    api_keys = load_keys()

    # Initialize graph with seed
    graph = InfraGraph()
    seed = graph.add_node(seed_type, target, depth=0, source="seed")

    if not args.quiet and not args.json_only:
        type_label = "domain" if seed_type == NodeType.DOMAIN else "IP"
        print(f"  {C.BOLD}Seed:{C.RESET}      {target} ({type_label})")
        print(f"  {C.BOLD}Depth:{C.RESET}     {args.depth}")
        print(f"  {C.BOLD}Rate:{C.RESET}      {rate_limit}s between requests")

        free_sources = ["crt.sh", "dns", "hackertarget", "bgpview"]
        if not args.no_wayback:
            free_sources.append("wayback")
        if not args.no_whois:
            free_sources.append("whois")
        print(f"  {C.BOLD}Sources:{C.RESET}   {', '.join(free_sources)}")

        api_sources = []
        if api_keys.get("shodan"):
            api_sources.append("shodan")
        if api_keys.get("censys"):
            api_sources.append("censys")
        if api_sources:
            print(f"  {C.BOLD}API:{C.RESET}       {C.GREEN}{', '.join(api_sources)}{C.RESET}")
        else:
            print(f"  {C.BOLD}API:{C.RESET}       {C.DIM}none (add keys to ~/.config/infra_map/keys.conf){C.RESET}")

    # Run mapper
    mapper = Mapper(
        session=session,
        graph=graph,
        max_depth=args.depth,
        rate_limit=rate_limit,
        skip_whois=args.no_whois,
        skip_wayback=args.no_wayback,
        api_keys=api_keys,
    )

    start_time = time.time()

    def progress(node, current, total, iteration):
        if not args.quiet and not args.json_only:
            color = TYPE_COLORS.get(node.type, "")
            icon = TYPE_ICONS.get(node.type, "???")
            print(f"\r  {C.DIM}[depth {iteration}] {current}/{total} "
                  f"{color}[{icon}]{C.RESET} {C.DIM}{node.value}{C.RESET}          ",
                  end="", flush=True)

    from infra_map.output import TYPE_COLORS, TYPE_ICONS
    mapper.run(progress_callback=progress)

    elapsed = time.time() - start_time

    if not args.quiet and not args.json_only:
        api_note = f", {mapper._api_calls} API calls used" if mapper._api_calls > 0 else ""
        print(f"\r  Completed in {elapsed:.1f}s{api_note}{' ' * 30}")

    # Output
    if args.json_only:
        import json
        print(json.dumps(graph.to_json(), indent=2))
        return

    # Tree view
    if not args.quiet:
        print(f"\n{C.BOLD}Relationship tree:{C.RESET}")
        print_tree(graph, seed.id)
        print_summary(graph)

    # Auto-generate output dir if not specified
    output_dir = args.output
    if not output_dir and not args.json_only:
        safe_target = target.replace(":", "_").replace(".", "-").replace("/", "")
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        output_dir = f"infra_map_{safe_target}_{timestamp}"

    # ---- Probe discovered domains ----
    probe_results = {}
    all_domains = sorted(set(n.value for n in graph.nodes_by_type(NodeType.DOMAIN)))

    if (args.probe or args.scan) and all_domains:
        from infra_map.probe import DomainProbe

        if not args.quiet and not args.json_only:
            log_phase = lambda n: print(f"\n{C.BOLD}[{n}]{C.RESET} ", end="", flush=True)
            log_phase("PROBE")
            print(f"Checking {len(all_domains)} domains for liveness, CDN, parking...")

        prober = DomainProbe(session, timeout=timeout)

        def probe_progress(done, total):
            if not args.quiet and not args.json_only:
                print(f"\r  {C.DIM}Probed {done}/{total}{C.RESET}    ", end="", flush=True)

        probe_results = prober.probe_domains(all_domains, progress_callback=probe_progress)

        # Categorize results
        live = [d for d, r in probe_results.items() if r["status"] == "live" and not r["parked"]]
        cdn_domains = [d for d, r in probe_results.items() if r["cdn"]]
        parked = [d for d, r in probe_results.items() if r["parked"]]
        dead = [d for d, r in probe_results.items() if r["status"] in ("dns_failed", "http_failed")]
        scannable = [d for d, r in probe_results.items() if r["scannable"]]

        # Shared hosting detection — group by IP
        ip_to_domains = {}
        for d, r in probe_results.items():
            if r["ip"]:
                ip_to_domains.setdefault(r["ip"], []).append(d)
        shared_ips = {ip: domains for ip, domains in ip_to_domains.items() if len(domains) >= 2}

        if not args.quiet and not args.json_only:
            print(f"\r  {C.GREEN}{len(live)} live{C.RESET}, "
                  f"{C.CYAN}{len(cdn_domains)} CDN-proxied{C.RESET}, "
                  f"{C.YELLOW}{len(parked)} parked{C.RESET}, "
                  f"{C.DIM}{len(dead)} dead{C.RESET}, "
                  f"{C.GREEN}{len(scannable)} scannable{C.RESET}           ")

            if shared_ips:
                print(f"\n{C.BOLD}Shared hosting ({len(shared_ips)} IPs with multiple domains):{C.RESET}")
                for ip, domains in sorted(shared_ips.items(), key=lambda x: -len(x[1]))[:5]:
                    print(f"  {C.CYAN}{ip}{C.RESET} → {', '.join(domains[:5])}"
                          f"{'...' if len(domains) > 5 else ''}")

            if parked:
                print(f"\n{C.BOLD}Parked/expired ({len(parked)}):{C.RESET} {C.YELLOW}potential takeover candidates{C.RESET}")
                for d in parked[:5]:
                    title = probe_results[d].get("title", "")
                    print(f"  {C.YELLOW}{d}{C.RESET}{f' — {title}' if title else ''}")
                if len(parked) > 5:
                    print(f"  {C.DIM}...and {len(parked) - 5} more{C.RESET}")

            if dead:
                print(f"\n{C.BOLD}Dead/unreachable ({len(dead)}):{C.RESET} {C.DIM}dangling DNS?{C.RESET}")
                for d in dead[:5]:
                    print(f"  {C.DIM}{d}{C.RESET}")
                if len(dead) > 5:
                    print(f"  {C.DIM}...and {len(dead) - 5} more{C.RESET}")

    # ---- Save files ----
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

        json_path = os.path.join(output_dir, "graph.json")
        write_json(graph, json_path)

        domains_path = os.path.join(output_dir, "domains.txt")
        domain_count = write_domains(graph, domains_path)

        ips_path = os.path.join(output_dir, "ips.txt")
        ip_count = write_ips(graph, ips_path)

        # Save probe results if available
        if probe_results:
            import json as json_mod
            probe_path = os.path.join(output_dir, "probe_results.json")
            with open(probe_path, "w") as pf:
                json_mod.dump(probe_results, pf, indent=2)

            # Save scannable domains separately
            scannable_path = os.path.join(output_dir, "scannable.txt")
            scannable_domains = [d for d, r in probe_results.items() if r["scannable"]]
            with open(scannable_path, "w") as sf:
                sf.write("\n".join(sorted(scannable_domains)) + "\n" if scannable_domains else "")

        print(f"\n{C.BOLD}Output:{C.RESET}")
        print(f"  {C.CYAN}Graph:{C.RESET}       {json_path}")
        print(f"  {C.CYAN}Domains:{C.RESET}     {domains_path} ({domain_count} total)")
        if probe_results:
            print(f"  {C.CYAN}Probe:{C.RESET}       {probe_path}")
            print(f"  {C.CYAN}Scannable:{C.RESET}   {scannable_path} ({len(scannable_domains)} domains)")
        print(f"  {C.CYAN}IPs:{C.RESET}         {ips_path} ({ip_count} IPs)")

    # ---- Auto-scan if requested ----
    if args.scan and probe_results:
        scannable_domains = [d for d, r in probe_results.items() if r["scannable"]]
        if scannable_domains:
            if not args.quiet and not args.json_only:
                print(f"\n{C.BOLD}Auto-scanning {len(scannable_domains)} scannable domains...{C.RESET}")

            scan_output_base = output_dir or "."
            for i, domain in enumerate(scannable_domains):
                scheme = "https" if probe_results[domain]["http_code"] else "http"
                scan_url = f"{scheme}://{domain}"
                scan_dir = os.path.join(scan_output_base, f"scan_{domain.replace('.', '-')}")

                if not args.quiet and not args.json_only:
                    tech = ", ".join(probe_results[domain].get("tech", [])) or "unknown"
                    print(f"\n  [{i+1}/{len(scannable_domains)}] {C.GREEN}{scan_url}{C.RESET} ({tech})")

                scan_args = ["python", "-m", "sqli_recon", "-u", scan_url, "--quick", "-o", scan_dir]
                if args.tor:
                    scan_args.append("--tor")
                if proxy:
                    scan_args.extend(["--proxy", proxy])

                import subprocess
                subprocess.run(scan_args, timeout=300, capture_output=not args.verbose)
        else:
            if not args.quiet and not args.json_only:
                print(f"\n{C.YELLOW}No scannable domains found (all CDN-proxied, parked, or dead){C.RESET}")
    elif not args.scan and not args.json_only and probe_results:
        scannable_domains = [d for d, r in probe_results.items() if r["scannable"]]
        if scannable_domains and output_dir:
            print(f"\n{C.BOLD}Scan scannable domains:{C.RESET}")
            print(f"  {C.GREEN}while read d; do ./scan -u \"http://$d\" --quick; done < {os.path.join(output_dir, 'scannable.txt')}{C.RESET}")
    elif not probe_results and not args.json_only and output_dir:
        print(f"\n{C.BOLD}Next steps:{C.RESET}")
        print(f"  {C.GREEN}./map {target} --probe{C.RESET}           # check which domains are live")
        print(f"  {C.GREEN}./map {target} --probe --scan{C.RESET}    # probe + auto-scan live ones")


if __name__ == "__main__":
    main()
