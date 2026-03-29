"""Entity graph — tracks nodes (domains, IPs, orgs) and edges (relationships)."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Set, Optional
import json


class NodeType(str, Enum):
    DOMAIN = "domain"
    IP = "ip"
    ORG = "org"
    ASN = "asn"
    EMAIL = "email"
    CERT = "cert"


class EdgeType(str, Enum):
    RESOLVES_TO = "resolves_to"          # domain → IP
    REVERSE_DNS = "reverse_dns"          # IP → domain
    HAS_CERT = "has_cert"               # domain → cert
    CERT_COVERS = "cert_covers"          # cert → domain (SAN)
    REGISTERED_BY = "registered_by"      # domain → org/email
    BELONGS_TO_ASN = "belongs_to_asn"    # IP → ASN
    ASN_OWNED_BY = "asn_owned_by"        # ASN → org
    SAME_HOST = "same_host"             # domain → domain (same IP)
    SHARES_CERT = "shares_cert"          # domain → domain (same cert)
    WHOIS_ORG = "whois_org"             # domain → org
    HISTORICAL = "historical"            # domain found in archives


@dataclass
class Node:
    id: str           # Unique key: "domain:example.com", "ip:1.2.3.4"
    type: NodeType
    value: str        # The actual domain/IP/org string
    depth: int = 0    # Depth from seed
    sources: Set[str] = field(default_factory=set)
    metadata: dict = field(default_factory=dict)

    def __hash__(self):
        return hash(self.id)

    def __eq__(self, other):
        return isinstance(other, Node) and self.id == other.id


@dataclass
class Edge:
    source_id: str
    target_id: str
    type: EdgeType
    discovered_by: str = ""  # Which data source found this

    def __hash__(self):
        return hash((self.source_id, self.target_id, self.type))

    def __eq__(self, other):
        return (isinstance(other, Edge) and
                self.source_id == other.source_id and
                self.target_id == other.target_id and
                self.type == other.type)


class InfraGraph:
    """Graph of infrastructure relationships."""

    def __init__(self):
        self.nodes: Dict[str, Node] = {}
        self.edges: Set[Edge] = set()
        self._expanded: Set[str] = set()  # Node IDs already expanded

    def add_node(self, node_type: NodeType, value: str, depth: int = 0,
                 source: str = "", metadata: dict = None) -> Node:
        nid = f"{node_type.value}:{value}"
        if nid in self.nodes:
            node = self.nodes[nid]
            if source:
                node.sources.add(source)
            if metadata:
                node.metadata.update(metadata)
            return node

        node = Node(
            id=nid, type=node_type, value=value, depth=depth,
            sources={source} if source else set(),
            metadata=metadata or {},
        )
        self.nodes[nid] = node
        return node

    def add_edge(self, source_type: NodeType, source_value: str,
                 target_type: NodeType, target_value: str,
                 edge_type: EdgeType, discovered_by: str = "") -> Edge:
        src_id = f"{source_type.value}:{source_value}"
        tgt_id = f"{target_type.value}:{target_value}"
        edge = Edge(src_id, tgt_id, edge_type, discovered_by)
        self.edges.add(edge)
        return edge

    def mark_expanded(self, node_id: str):
        self._expanded.add(node_id)

    def is_expanded(self, node_id: str) -> bool:
        return node_id in self._expanded

    def unexpanded_nodes(self, max_depth: int = None) -> List[Node]:
        """Get nodes that haven't been expanded yet."""
        nodes = []
        for node in self.nodes.values():
            if node.id not in self._expanded:
                if max_depth is None or node.depth <= max_depth:
                    nodes.append(node)
        return nodes

    def get_neighbors(self, node_id: str) -> List[Node]:
        """Get all nodes connected to a given node."""
        neighbor_ids = set()
        for edge in self.edges:
            if edge.source_id == node_id:
                neighbor_ids.add(edge.target_id)
            elif edge.target_id == node_id:
                neighbor_ids.add(edge.source_id)
        return [self.nodes[nid] for nid in neighbor_ids if nid in self.nodes]

    def nodes_by_type(self, node_type: NodeType) -> List[Node]:
        return [n for n in self.nodes.values() if n.type == node_type]

    def stats(self) -> dict:
        type_counts = {}
        for node in self.nodes.values():
            type_counts[node.type.value] = type_counts.get(node.type.value, 0) + 1
        return {
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "expanded": len(self._expanded),
            "by_type": type_counts,
        }

    def to_json(self) -> dict:
        return {
            "nodes": [
                {
                    "id": n.id,
                    "type": n.type.value,
                    "value": n.value,
                    "depth": n.depth,
                    "sources": sorted(n.sources),
                    "metadata": n.metadata,
                }
                for n in sorted(self.nodes.values(), key=lambda n: (n.depth, n.type.value, n.value))
            ],
            "edges": [
                {
                    "source": e.source_id,
                    "target": e.target_id,
                    "type": e.type.value,
                    "discovered_by": e.discovered_by,
                }
                for e in sorted(self.edges, key=lambda e: (e.source_id, e.target_id))
            ],
            "stats": self.stats(),
        }
