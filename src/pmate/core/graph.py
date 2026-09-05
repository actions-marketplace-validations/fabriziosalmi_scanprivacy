"""The findings graph.

Node and edge types are a closed vocabulary on purpose: a consumer can rely on
them, and a new rule cannot silently invent a semantic relation. Labels here
are neutral — proper nouns, hosts, identifiers — never translated prose. A
renderer that wants human labels joins the graph with the findings it already
has in hand.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

NODE_TYPES = (
    "site",  # the scanned origin
    "page",  # a URL actually loaded
    "host",  # a network endpoint the browser contacted
    "vendor",  # the legal entity behind one or more hosts
    "cookie",  # a cookie set on first visit
    "storage",  # a localStorage / sessionStorage / IndexedDB entry
    "document",  # a legal document found and read
    "obligation",  # the provision a finding hangs from (reference key)
    "finding",  # a rule that fired
    "remediation",  # the fix attached to a finding
)

EDGE_TYPES = (
    "loads",  # page -> host
    "operated_by",  # host / cookie -> vendor
    "transfers_to",  # site -> vendor
    "sets",  # site -> cookie / storage
    "publishes",  # site -> page / document
    "declares",  # document -> vendor
    "evidences",  # any node -> finding
    "violates",  # finding -> obligation
    "fixed_by",  # finding -> remediation
)


@dataclass(slots=True)
class Node:
    id: str
    type: str
    label: str
    attrs: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Edge:
    src: str
    dst: str
    type: str
    attrs: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Graph:
    nodes: list[Node] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)
    _index: dict[str, Node] = field(default_factory=dict, repr=False)
    _seen_edges: set[tuple[str, str, str]] = field(default_factory=set, repr=False)

    def node(self, id: str, type: str, label: str, **attrs: Any) -> str:
        if type not in NODE_TYPES:
            raise ValueError(f"unknown node type: {type}")
        existing = self._index.get(id)
        if existing is None:
            node = Node(id=id, type=type, label=label, attrs=attrs)
            self._index[id] = node
            self.nodes.append(node)
        elif attrs:  # merge late-arriving attributes
            existing.attrs.update({k: v for k, v in attrs.items() if v is not None})
        return id

    def has(self, id: str) -> bool:
        return id in self._index

    def edge(self, src: str, dst: str, type: str, **attrs: Any) -> None:
        if type not in EDGE_TYPES:
            raise ValueError(f"unknown edge type: {type}")
        key = (src, dst, type)
        if key in self._seen_edges:
            return
        self._seen_edges.add(key)
        self.edges.append(Edge(src=src, dst=dst, type=type, attrs=attrs))

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [asdict(n) for n in self.nodes],
            "edges": [asdict(e) for e in self.edges],
        }


def to_mermaid(graph: Graph, labels: dict[str, str] | None = None, max_nodes: int = 60) -> str:
    """A readable projection for humans; the JSON stays the source of truth.

    `labels` overrides neutral node labels with rendered ones (finding titles in
    the reader's language), so the diagram matches the report around it.
    """
    labels = labels or {}
    shapes = {
        "site": ("([", "])"),
        "page": ("[", "]"),
        "host": ("(", ")"),
        "vendor": ("[[", "]]"),
        "cookie": ("[/", "/]"),
        "storage": ("[/", "/]"),
        "document": ("[(", ")]"),
        "finding": ("{{", "}}"),
        "obligation": (">", "]"),
        "remediation": ("[", "]"),
    }
    lines = ["graph LR"]
    kept = graph.nodes[:max_nodes]
    keep_ids = {n.id for n in kept}
    ids = {}
    for i, node in enumerate(kept):
        ids[node.id] = f"n{i}"
        open_, close = shapes.get(node.type, ("[", "]"))
        label = labels.get(node.id, node.label).replace('"', "'")[:60]
        lines.append(f'  {ids[node.id]}{open_}"{label}"{close}')
    for edge in graph.edges:
        if edge.src in keep_ids and edge.dst in keep_ids:
            lines.append(f"  {ids[edge.src]} -->|{edge.type}| {ids[edge.dst]}")
    return "\n".join(lines)
