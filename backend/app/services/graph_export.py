"""Property-graph export of a recap graph, shaped for Neo4j-style loaders.

Nodes carry a label (their kind) and flat properties; relationships carry a
type and the plugin that produced the link. Neo4j relationship types are
upper snake case by convention, so `resolves_to` becomes `RESOLVES_TO`.

The shape is the generic property-graph one (nodes + relationships by id). It
has not been loaded into a live Neo4j or BloodHound instance, and BloodHound
expects its own schema, so this is a source for a loader script, not an
import file for either tool.
"""

from __future__ import annotations

import re
from typing import Any

FORMAT = "property-graph-v1"
_NON_ALNUM = re.compile(r"[^A-Za-z0-9]+")


def _label(kind: str) -> str:
    """Neo4j node labels are conventionally PascalCase."""
    parts = [part for part in _NON_ALNUM.split(kind) if part]
    return "".join(part[:1].upper() + part[1:] for part in parts) or "Entity"


def _rel_type(relation: str) -> str:
    return "_".join(part.upper() for part in _NON_ALNUM.split(relation) if part) or "RELATED_TO"


def _scalar_properties(data: dict[str, Any]) -> dict[str, Any]:
    """Neo4j properties must be scalars or homogeneous lists of them."""
    props: dict[str, Any] = {}
    for key, value in data.items():
        is_scalar = isinstance(value, (str, int, float, bool))
        is_text_list = isinstance(value, list) and all(isinstance(item, str) for item in value)
        if is_scalar or is_text_list:
            props[key] = value
    return props


def to_property_graph(graph: dict[str, Any]) -> dict[str, Any]:
    """Convert `Graph.as_dict()` into nodes and relationships."""
    nodes = [
        {
            "id": node["id"],
            "labels": [_label(str(node["kind"]))],
            "properties": {
                **_scalar_properties(node.get("data") or {}),
                "name": node["label"],
            },
        }
        for node in graph.get("nodes", [])
    ]
    known = {node["id"] for node in nodes}
    relationships = [
        {
            "id": f"r{index}",
            "from": edge["source"],
            "to": edge["target"],
            "type": _rel_type(str(edge["relation"])),
            "properties": {"plugin": edge["plugin"]} if edge.get("plugin") else {},
        }
        for index, edge in enumerate(graph.get("edges", []))
        if edge["source"] in known and edge["target"] in known
    ]
    return {
        "format": FORMAT,
        "alpha": True,
        "root": graph.get("root"),
        "truncated": bool(graph.get("truncated")),
        "nodes": nodes,
        "relationships": relationships,
    }
