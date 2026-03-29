"""Output formatters — tree view, JSON export, CSV."""

import json
import os
from collections import defaultdict

from infra_map.graph import InfraGraph, NodeType, EdgeType


# ANSI colors
class C:
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    CYAN = "\033[96m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


TYPE_COLORS = {
    NodeType.DOMAIN: C.GREEN,
    NodeType.IP: C.CYAN,
    NodeType.ORG: C.YELLOW,
    NodeType.ASN: C.BLUE,
    NodeType.EMAIL: C.MAGENTA,
    NodeType.CERT: C.DIM,
}

TYPE_ICONS = {
    NodeType.DOMAIN: "DOM",
    NodeType.IP: " IP",
    NodeType.ORG: "ORG",
    NodeType.ASN: "ASN",
    NodeType.EMAIL: " @ ",
    NodeType.CERT: "CRT",
}


def print_tree(graph: InfraGraph, seed_id: str):
    """Print a tree view starting from the seed node."""
    if seed_id not in graph.nodes:
        print("  (no results)")
        return

    printed = set()
    _print_node(graph, seed_id, "", True, printed, max_depth=6)


def _print_node(graph, node_id, prefix, is_last, printed, max_depth, current_depth=0):
    if current_depth > max_depth or node_id in printed:
        return
    printed.add(node_id)

    node = graph.nodes.get(node_id)
    if not node:
        return

    connector = "└── " if is_last else "├── "
    color = TYPE_COLORS.get(node.type, "")
    icon = TYPE_ICONS.get(node.type, "???")

    sources = f" {C.DIM}[{', '.join(sorted(node.sources))}]{C.RESET}" if node.sources else ""
    meta_str = ""
    if node.metadata:
        interesting = {k: v for k, v in node.metadata.items()
                       if k not in ("prefixes",) and v}
        if interesting:
            meta_str = f" {C.DIM}({', '.join(f'{k}={v}' for k, v in interesting.items())}){C.RESET}"

    print(f"{prefix}{connector}{color}[{icon}]{C.RESET} {C.BOLD}{node.value}{C.RESET}{sources}{meta_str}")

    # Find children (nodes connected via outgoing edges)
    children = []
    for edge in graph.edges:
        if edge.source_id == node_id and edge.target_id not in printed:
            children.append(edge.target_id)
        elif edge.target_id == node_id and edge.source_id not in printed:
            children.append(edge.source_id)

    # Deduplicate and sort
    seen = set()
    unique_children = []
    for child_id in children:
        if child_id not in seen:
            seen.add(child_id)
            unique_children.append(child_id)

    # Sort: domains first, then IPs, then orgs, then rest
    type_order = {NodeType.DOMAIN: 0, NodeType.IP: 1, NodeType.ORG: 2,
                  NodeType.ASN: 3, NodeType.EMAIL: 4, NodeType.CERT: 5}
    unique_children.sort(key=lambda cid: (
        type_order.get(graph.nodes[cid].type, 9) if cid in graph.nodes else 9,
        graph.nodes[cid].value if cid in graph.nodes else "",
    ))

    child_prefix = prefix + ("    " if is_last else "│   ")
    for i, child_id in enumerate(unique_children):
        is_child_last = (i == len(unique_children) - 1)
        _print_node(graph, child_id, child_prefix, is_child_last, printed,
                     max_depth, current_depth + 1)


def print_summary(graph: InfraGraph):
    """Print a summary of what was found."""
    stats = graph.stats()

    print(f"\n{C.BOLD}{'=' * 60}{C.RESET}")
    print(f"{C.BOLD}  Infrastructure Map Summary{C.RESET}")
    print(f"{C.BOLD}{'=' * 60}{C.RESET}")

    for ntype, count in sorted(stats["by_type"].items()):
        nt = NodeType(ntype)
        color = TYPE_COLORS.get(nt, "")
        icon = TYPE_ICONS.get(nt, "???")
        print(f"  {color}[{icon}]{C.RESET} {ntype:<10} {count}")

    print(f"  {'─' * 30}")
    print(f"  Total nodes: {stats['total_nodes']}")
    print(f"  Total edges: {stats['total_edges']}")
    print(f"{C.BOLD}{'=' * 60}{C.RESET}")

    # List all domains found
    domains = graph.nodes_by_type(NodeType.DOMAIN)
    if domains:
        print(f"\n{C.BOLD}Domains ({len(domains)}):{C.RESET}")
        for d in sorted(domains, key=lambda n: n.value):
            sources = f" {C.DIM}[{', '.join(sorted(d.sources))}]{C.RESET}"
            print(f"  {C.GREEN}{d.value}{C.RESET}{sources}")

    # List all IPs found
    ips = graph.nodes_by_type(NodeType.IP)
    if ips:
        print(f"\n{C.BOLD}IPs ({len(ips)}):{C.RESET}")
        for ip_node in sorted(ips, key=lambda n: n.value):
            # Show which domains point to this IP
            domains_on_ip = []
            for edge in graph.edges:
                if edge.target_id == ip_node.id and edge.type == EdgeType.RESOLVES_TO:
                    src = graph.nodes.get(edge.source_id)
                    if src and src.type == NodeType.DOMAIN:
                        domains_on_ip.append(src.value)
            domain_hint = f" {C.DIM}({', '.join(domains_on_ip[:5])}){C.RESET}" if domains_on_ip else ""
            print(f"  {C.CYAN}{ip_node.value}{C.RESET}{domain_hint}")

    # List orgs
    orgs = graph.nodes_by_type(NodeType.ORG)
    if orgs:
        print(f"\n{C.BOLD}Organizations ({len(orgs)}):{C.RESET}")
        for o in sorted(orgs, key=lambda n: n.value):
            print(f"  {C.YELLOW}{o.value}{C.RESET}")


def write_json(graph: InfraGraph, path: str):
    """Write full graph as JSON."""
    with open(path, "w") as f:
        json.dump(graph.to_json(), f, indent=2)


def write_domains(graph: InfraGraph, path: str):
    """Write all discovered domains to a text file (one per line)."""
    domains = sorted(set(n.value for n in graph.nodes_by_type(NodeType.DOMAIN)))
    with open(path, "w") as f:
        f.write("\n".join(domains) + "\n" if domains else "")
    return len(domains)


def write_ips(graph: InfraGraph, path: str):
    """Write all discovered IPs to a text file."""
    ips = sorted(set(n.value for n in graph.nodes_by_type(NodeType.IP)))
    with open(path, "w") as f:
        f.write("\n".join(ips) + "\n" if ips else "")
    return len(ips)
