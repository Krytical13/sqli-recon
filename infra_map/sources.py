"""Data sources — all free, no API keys, no accounts required."""

import re
import json
import socket
import logging
import subprocess
from urllib.parse import quote_plus

import requests

from infra_map.graph import InfraGraph, NodeType, EdgeType

log = logging.getLogger(__name__)


class SourceBase:
    """Base class for data sources."""

    name = "base"

    def __init__(self, session: requests.Session, graph: InfraGraph):
        self.session = session
        self.graph = graph
        self.timeout = 30

    def _get(self, url, **kwargs):
        kwargs.setdefault("timeout", self.timeout)
        try:
            resp = self.session.get(url, **kwargs)
            if resp.status_code == 200:
                return resp
            log.debug(f"{self.name}: {url} returned {resp.status_code}")
        except requests.RequestException as e:
            log.debug(f"{self.name}: {url} failed: {e}")
        return None


class CrtSh(SourceBase):
    """Certificate Transparency log search via crt.sh. No auth needed."""

    name = "crt.sh"

    def search_domain(self, domain, depth):
        """Find all domains that share a certificate with this domain."""
        resp = self._get(f"https://crt.sh/?q=%.{domain}&output=json")
        if resp is None:
            # Try exact match
            resp = self._get(f"https://crt.sh/?q={domain}&output=json")
        if resp is None:
            return

        try:
            entries = resp.json()
        except (ValueError, TypeError):
            return

        seen_domains = set()
        for entry in entries:
            name_value = entry.get("name_value", "")
            for line in name_value.splitlines():
                d = line.strip().lower()
                if d.startswith("*."):
                    d = d[2:]
                if d and d != domain and _is_valid_domain(d) and d not in seen_domains:
                    seen_domains.add(d)
                    self.graph.add_node(NodeType.DOMAIN, d, depth=depth + 1, source=self.name)
                    self.graph.add_edge(
                        NodeType.DOMAIN, domain,
                        NodeType.DOMAIN, d,
                        EdgeType.SHARES_CERT, self.name,
                    )

            # Track cert issuer org
            issuer = entry.get("issuer_name", "")
            org_match = re.search(r"O=([^,/]+)", issuer)
            if org_match:
                org = org_match.group(1).strip()
                cert_id = entry.get("serial_number", "")[:16]
                if cert_id:
                    self.graph.add_node(NodeType.CERT, cert_id, depth=depth + 1,
                                        source=self.name,
                                        metadata={"issuer_org": org})

    def search_org(self, org_name, depth):
        """Search CT logs by organization name."""
        resp = self._get(f"https://crt.sh/?O={quote_plus(org_name)}&output=json")
        if resp is None:
            return

        try:
            entries = resp.json()
        except (ValueError, TypeError):
            return

        seen = set()
        for entry in entries:
            for line in entry.get("name_value", "").splitlines():
                d = line.strip().lower()
                if d.startswith("*."):
                    d = d[2:]
                if d and _is_valid_domain(d) and d not in seen:
                    seen.add(d)
                    self.graph.add_node(NodeType.DOMAIN, d, depth=depth + 1, source=self.name)
                    self.graph.add_edge(
                        NodeType.ORG, org_name,
                        NodeType.DOMAIN, d,
                        EdgeType.REGISTERED_BY, self.name,
                    )


class DNSResolver(SourceBase):
    """Standard DNS resolution. No external service needed."""

    name = "dns"

    def resolve_domain(self, domain, depth):
        """Resolve a domain to IP addresses."""
        for qtype in ["A", "AAAA"]:
            try:
                if qtype == "A":
                    results = socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)
                else:
                    results = socket.getaddrinfo(domain, None, socket.AF_INET6, socket.SOCK_STREAM)

                for result in results:
                    ip = result[4][0]
                    if ip and not ip.startswith("127.") and ip != "::1":
                        self.graph.add_node(NodeType.IP, ip, depth=depth + 1, source=self.name)
                        self.graph.add_edge(
                            NodeType.DOMAIN, domain,
                            NodeType.IP, ip,
                            EdgeType.RESOLVES_TO, self.name,
                        )
            except (socket.gaierror, OSError):
                pass

    def reverse_dns(self, ip, depth):
        """Reverse DNS lookup on an IP."""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            if hostname and _is_valid_domain(hostname):
                self.graph.add_node(NodeType.DOMAIN, hostname, depth=depth + 1, source=self.name)
                self.graph.add_edge(
                    NodeType.IP, ip,
                    NodeType.DOMAIN, hostname,
                    EdgeType.REVERSE_DNS, self.name,
                )
        except (socket.herror, socket.gaierror, OSError):
            pass

    def get_records(self, domain, depth):
        """Get MX, NS, TXT records for additional infrastructure info."""
        for rtype in ["MX", "NS", "CNAME"]:
            try:
                output = subprocess.run(
                    ["dig", "+short", rtype, domain],
                    capture_output=True, text=True, timeout=10,
                )
                for line in output.stdout.strip().splitlines():
                    line = line.strip().rstrip(".")
                    # MX records have priority prefix
                    if rtype == "MX" and " " in line:
                        line = line.split()[-1].rstrip(".")
                    if line and _is_valid_domain(line) and line != domain:
                        self.graph.add_node(NodeType.DOMAIN, line, depth=depth + 1,
                                            source=self.name,
                                            metadata={"record_type": rtype})
                        self.graph.add_edge(
                            NodeType.DOMAIN, domain,
                            NodeType.DOMAIN, line,
                            EdgeType.RESOLVES_TO, f"{self.name}:{rtype}",
                        )
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

    def try_zone_transfer(self, domain, depth):
        """Attempt DNS zone transfer (AXFR). Usually fails but free to try."""
        # Get nameservers first
        try:
            output = subprocess.run(
                ["dig", "+short", "NS", domain],
                capture_output=True, text=True, timeout=10,
            )
            nameservers = [ns.strip().rstrip(".") for ns in output.stdout.strip().splitlines() if ns.strip()]
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return

        for ns in nameservers[:2]:  # Only try first 2
            try:
                output = subprocess.run(
                    ["dig", "AXFR", domain, f"@{ns}"],
                    capture_output=True, text=True, timeout=15,
                )
                if "Transfer failed" in output.stdout or "REFUSED" in output.stdout:
                    continue

                for line in output.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 5 and parts[3] in ("A", "AAAA", "CNAME"):
                        name = parts[0].rstrip(".")
                        value = parts[4].rstrip(".")
                        if _is_valid_domain(name) and name != domain:
                            self.graph.add_node(NodeType.DOMAIN, name, depth=depth + 1,
                                                source=f"{self.name}:AXFR")
                            self.graph.add_edge(
                                NodeType.DOMAIN, domain,
                                NodeType.DOMAIN, name,
                                EdgeType.RESOLVES_TO, f"{self.name}:AXFR",
                            )
                log.info(f"Zone transfer succeeded on {domain} via {ns}")
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass


class HackerTarget(SourceBase):
    """HackerTarget.com free API — reverse IP lookup. No auth, 100/day limit."""

    name = "hackertarget"

    def reverse_ip(self, ip, depth):
        """Find other domains hosted on the same IP."""
        resp = self._get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}")
        if resp is None:
            return
        text = resp.text.strip()
        if "error" in text.lower() or "no records" in text.lower() or "API count" in text:
            return

        for line in text.splitlines():
            d = line.strip().lower()
            if d and _is_valid_domain(d):
                self.graph.add_node(NodeType.DOMAIN, d, depth=depth + 1, source=self.name)
                self.graph.add_edge(
                    NodeType.IP, ip,
                    NodeType.DOMAIN, d,
                    EdgeType.SAME_HOST, self.name,
                )

    def hostsearch(self, domain, depth):
        """Find subdomains via HackerTarget host search."""
        resp = self._get(f"https://api.hackertarget.com/hostsearch/?q={domain}")
        if resp is None:
            return
        text = resp.text.strip()
        if "error" in text.lower() or "API count" in text:
            return

        for line in text.splitlines():
            parts = line.split(",")
            if len(parts) >= 2:
                d = parts[0].strip().lower()
                ip = parts[1].strip()
                if d and _is_valid_domain(d) and d != domain:
                    self.graph.add_node(NodeType.DOMAIN, d, depth=depth + 1, source=self.name)
                    self.graph.add_edge(
                        NodeType.DOMAIN, domain,
                        NodeType.DOMAIN, d,
                        EdgeType.RESOLVES_TO, self.name,
                    )
                    if ip and _is_valid_ip(ip):
                        self.graph.add_node(NodeType.IP, ip, depth=depth + 1, source=self.name)
                        self.graph.add_edge(
                            NodeType.DOMAIN, d,
                            NodeType.IP, ip,
                            EdgeType.RESOLVES_TO, self.name,
                        )


class WaybackMachine(SourceBase):
    """Wayback Machine CDX API — find historical subdomains. No auth needed."""

    name = "wayback"

    def search_domain(self, domain, depth):
        """Find subdomains from archived URLs."""
        resp = self._get(
            f"https://web.archive.org/cdx/search/cdx"
            f"?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit=500",
            timeout=45,
        )
        if resp is None:
            return

        try:
            rows = resp.json()
        except (ValueError, TypeError):
            return

        seen = set()
        for row in rows[1:]:  # Skip header row
            if not row:
                continue
            url = row[0] if isinstance(row, list) else row
            # Extract domain from URL
            match = re.match(r"https?://([^/:]+)", url)
            if match:
                d = match.group(1).lower()
                if d and d != domain and _is_valid_domain(d) and d not in seen:
                    seen.add(d)
                    self.graph.add_node(NodeType.DOMAIN, d, depth=depth + 1, source=self.name)
                    self.graph.add_edge(
                        NodeType.DOMAIN, domain,
                        NodeType.DOMAIN, d,
                        EdgeType.HISTORICAL, self.name,
                    )


class BGPView(SourceBase):
    """BGPView API — ASN and prefix lookups. No auth needed."""

    name = "bgpview"

    def lookup_ip(self, ip, depth):
        """Find ASN and org for an IP."""
        resp = self._get(f"https://api.bgpview.io/ip/{ip}")
        if resp is None:
            return

        try:
            data = resp.json().get("data", {})
        except (ValueError, TypeError):
            return

        prefixes = data.get("prefixes", [])
        for prefix_info in prefixes:
            asn_info = prefix_info.get("asn", {})
            asn = asn_info.get("asn")
            org = asn_info.get("description", "") or asn_info.get("name", "")

            if asn:
                asn_str = str(asn)
                self.graph.add_node(NodeType.ASN, asn_str, depth=depth + 1,
                                    source=self.name, metadata={"org": org})
                self.graph.add_edge(
                    NodeType.IP, ip,
                    NodeType.ASN, asn_str,
                    EdgeType.BELONGS_TO_ASN, self.name,
                )
                if org:
                    self.graph.add_node(NodeType.ORG, org, depth=depth + 1, source=self.name)
                    self.graph.add_edge(
                        NodeType.ASN, asn_str,
                        NodeType.ORG, org,
                        EdgeType.ASN_OWNED_BY, self.name,
                    )

    def lookup_asn_prefixes(self, asn, depth):
        """Find all IP prefixes for an ASN."""
        resp = self._get(f"https://api.bgpview.io/asn/{asn}/prefixes")
        if resp is None:
            return

        try:
            data = resp.json().get("data", {})
        except (ValueError, TypeError):
            return

        for prefix_list in [data.get("ipv4_prefixes", []), data.get("ipv6_prefixes", [])]:
            for prefix_info in prefix_list:
                prefix = prefix_info.get("prefix", "")
                if prefix:
                    # Store prefix as metadata on the ASN node, don't expand individual IPs
                    asn_node = self.graph.nodes.get(f"asn:{asn}")
                    if asn_node:
                        prefixes = asn_node.metadata.setdefault("prefixes", [])
                        if prefix not in prefixes:
                            prefixes.append(prefix)


class Whois(SourceBase):
    """WHOIS lookup via command line. No external service needed."""

    name = "whois"

    def lookup_domain(self, domain, depth):
        """Extract registrant info from WHOIS."""
        try:
            output = subprocess.run(
                ["whois", domain],
                capture_output=True, text=True, timeout=15,
            )
            text = output.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return

        # Extract organization
        for pattern in [
            r"Registrant Organization:\s*(.+)",
            r"org-name:\s*(.+)",
            r"Organization:\s*(.+)",
            r"Registrant:\s*(.+)",
        ]:
            match = re.search(pattern, text, re.I)
            if match:
                org = match.group(1).strip()
                if org and len(org) > 2 and org.lower() not in {"redacted", "data protected", "not disclosed"}:
                    self.graph.add_node(NodeType.ORG, org, depth=depth + 1, source=self.name)
                    self.graph.add_edge(
                        NodeType.DOMAIN, domain,
                        NodeType.ORG, org,
                        EdgeType.WHOIS_ORG, self.name,
                    )
                break

        # Extract registrant email
        for pattern in [
            r"Registrant Email:\s*(\S+@\S+)",
            r"e-mail:\s*(\S+@\S+)",
        ]:
            match = re.search(pattern, text, re.I)
            if match:
                email = match.group(1).strip().lower()
                if email and "@" in email and "redacted" not in email and "privacy" not in email:
                    self.graph.add_node(NodeType.EMAIL, email, depth=depth + 1, source=self.name)
                    self.graph.add_edge(
                        NodeType.DOMAIN, domain,
                        NodeType.EMAIL, email,
                        EdgeType.REGISTERED_BY, self.name,
                    )
                break

        # Extract nameservers
        for match in re.finditer(r"Name Server:\s*(\S+)", text, re.I):
            ns = match.group(1).strip().lower().rstrip(".")
            if ns and _is_valid_domain(ns):
                ns_domain = ".".join(ns.split(".")[-2:])
                if ns_domain != domain:
                    self.graph.add_node(NodeType.DOMAIN, ns, depth=depth + 1,
                                        source=self.name, metadata={"role": "nameserver"})


# ---- Helpers ----

def _is_valid_domain(d):
    """Basic domain validation."""
    if not d or len(d) < 4 or len(d) > 253:
        return False
    if not re.match(r'^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)*\.[a-z]{2,}$', d):
        return False
    # Filter out CDN/cloud/generic domains that create noise
    noise = {
        "cloudflare.com", "cloudfront.net", "amazonaws.com", "azure.com",
        "azurewebsites.net", "googleusercontent.com", "googleapis.com",
        "fastly.net", "akamai.net", "akamaiedge.net", "edgekey.net",
        "incapdns.net", "sucuri.net",
    }
    for n in noise:
        if d.endswith(f".{n}") or d == n:
            return False
    return True


def _is_valid_ip(ip):
    """Check if string is a valid IP."""
    try:
        socket.inet_aton(ip)
        return not ip.startswith("127.") and not ip.startswith("0.")
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, ip)
        return ip != "::1"
    except OSError:
        return False
