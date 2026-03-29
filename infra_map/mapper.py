"""Recursive expansion engine — follows relationships until the graph stops growing."""

import time
import logging

from infra_map.graph import InfraGraph, NodeType
from infra_map.sources import (
    CrtSh, DNSResolver, HackerTarget, WaybackMachine, BGPView, Whois,
)

log = logging.getLogger(__name__)


class Mapper:
    """
    Recursive infrastructure mapper.

    Starting from a seed (domain or IP), queries free public sources,
    discovers new entities, and recursively expands until max_depth
    or no new nodes are found.
    """

    def __init__(self, session, graph: InfraGraph, max_depth=2, rate_limit=1.0,
                 skip_whois=False, skip_wayback=False):
        self.graph = graph
        self.max_depth = max_depth
        self.rate_limit = rate_limit
        self._last_request = 0.0

        # Initialize sources
        self.crtsh = CrtSh(session, graph)
        self.dns = DNSResolver(session, graph)
        self.hackertarget = HackerTarget(session, graph)
        self.wayback = WaybackMachine(session, graph) if not skip_wayback else None
        self.bgpview = BGPView(session, graph)
        self.whois = Whois(session, graph) if not skip_whois else None

    def _wait(self):
        elapsed = time.time() - self._last_request
        if elapsed < self.rate_limit:
            time.sleep(self.rate_limit - elapsed)
        self._last_request = time.time()

    def run(self, progress_callback=None):
        """
        Expand all unexpanded nodes up to max_depth.
        Repeats until no new unexpanded nodes remain.
        """
        iteration = 0
        while True:
            unexpanded = self.graph.unexpanded_nodes(max_depth=self.max_depth)
            if not unexpanded:
                break

            iteration += 1
            nodes_before = len(self.graph.nodes)

            for i, node in enumerate(unexpanded):
                if progress_callback:
                    progress_callback(node, i + 1, len(unexpanded), iteration)

                self._expand_node(node)
                self.graph.mark_expanded(node.id)

            nodes_after = len(self.graph.nodes)
            new_nodes = nodes_after - nodes_before

            if new_nodes == 0:
                break  # No new discoveries, done

    def _expand_node(self, node):
        """Expand a single node by querying all relevant sources."""
        if node.type == NodeType.DOMAIN:
            self._expand_domain(node)
        elif node.type == NodeType.IP:
            self._expand_ip(node)
        elif node.type == NodeType.ORG:
            self._expand_org(node)
        elif node.type == NodeType.ASN:
            self._expand_asn(node)
        # EMAIL nodes — could search crt.sh by email but usually low value

    def _expand_domain(self, node):
        domain = node.value
        depth = node.depth

        # DNS resolution (fast, always do)
        self.dns.resolve_domain(domain, depth)
        self._wait()

        # DNS records (MX, NS, CNAME)
        self.dns.get_records(domain, depth)
        self._wait()

        # Zone transfer attempt (usually fails, but free)
        self.dns.try_zone_transfer(domain, depth)
        self._wait()

        # Certificate Transparency — the big one
        self.crtsh.search_domain(domain, depth)
        self._wait()

        # HackerTarget host search (subdomains)
        self.hackertarget.hostsearch(domain, depth)
        self._wait()

        # Wayback Machine (historical subdomains)
        if self.wayback:
            self.wayback.search_domain(domain, depth)
            self._wait()

        # WHOIS (registrant info)
        if self.whois:
            self.whois.lookup_domain(domain, depth)
            self._wait()

    def _expand_ip(self, node):
        ip = node.value
        depth = node.depth

        # Reverse DNS
        self.dns.reverse_dns(ip, depth)
        self._wait()

        # Reverse IP lookup (other domains on same host)
        self.hackertarget.reverse_ip(ip, depth)
        self._wait()

        # ASN / org lookup
        self.bgpview.lookup_ip(ip, depth)
        self._wait()

    def _expand_org(self, node):
        org = node.value
        depth = node.depth

        # Search CT logs by organization name
        self.crtsh.search_org(org, depth)
        self._wait()

    def _expand_asn(self, node):
        asn = node.value
        depth = node.depth

        # Get all prefixes for this ASN
        self.bgpview.lookup_asn_prefixes(asn, depth)
        self._wait()
