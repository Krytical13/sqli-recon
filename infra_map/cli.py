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
        if api_keys.get("censys_id") and api_keys.get("censys_secret"):
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

    # Save files
    if args.output:
        os.makedirs(args.output, exist_ok=True)

        json_path = os.path.join(args.output, "graph.json")
        write_json(graph, json_path)

        domains_path = os.path.join(args.output, "domains.txt")
        domain_count = write_domains(graph, domains_path)

        ips_path = os.path.join(args.output, "ips.txt")
        ip_count = write_ips(graph, ips_path)

        print(f"\n{C.BOLD}Output files:{C.RESET}")
        print(f"  {C.CYAN}Graph:{C.RESET}     {json_path}")
        print(f"  {C.CYAN}Domains:{C.RESET}   {domains_path} ({domain_count} domains)")
        print(f"  {C.CYAN}IPs:{C.RESET}       {ips_path} ({ip_count} IPs)")

        # Hint: feed domains into sqli_recon
        if domain_count > 0:
            print(f"\n{C.BOLD}Next step — scan discovered domains:{C.RESET}")
            print(f"  {C.GREEN}while read d; do ./scan -u \"http://$d\" --quick; done < {domains_path}{C.RESET}")


if __name__ == "__main__":
    main()
