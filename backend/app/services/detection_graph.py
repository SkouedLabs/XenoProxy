"""Detection graph of one investigation: what each source found, and what it led to.

Built from the same stored reports as the recap, with no provider call. Every analyzer
and pivot is a node, so a finding is reached through the source that produced it:

    domain --analysed_by--> dns --resolves_to--> ip --analysed_by--> shodan_internetdb
                                                 ip --exposes--> port 443

Each node gets a `layer` (hops from the observable it started from) and a `via` pointing
at the edge that first reached it, so the chain from the root can be read back. Nodes
that no edge reaches are left out rather than drawn adrift.
"""

from __future__ import annotations

from collections import deque
from typing import Any

from app.models.job import Job
from app.services import recap

MAX_TEXT = 300
_Adjacency = dict[str, list[tuple[str, dict[str, Any]]]]


def _scalars(data: dict[str, Any]) -> dict[str, Any]:
    props: dict[str, Any] = {}
    for key, value in data.items():
        if isinstance(value, bool | int | float):
            props[key] = value
        elif isinstance(value, str):
            props[key] = value[:MAX_TEXT]
    return props


def _walk(
    queue: deque[str],
    reached: dict[str, tuple[int, dict[str, Any] | None]],
    adjacency: _Adjacency,
) -> None:
    while queue:
        current = queue.popleft()
        depth = reached[current][0]
        for neighbour, edge in adjacency.get(current, []):
            if neighbour in reached:
                continue
            via = {"from": current, "relation": edge["relation"], "plugin": edge["plugin"]}
            reached[neighbour] = (depth + 1, via)
            queue.append(neighbour)


def provenance(graph: recap.Graph) -> dict[str, tuple[int, dict[str, Any] | None]]:
    """Layer and arrival edge of every node reachable from the root."""
    if graph.root is None:
        return {}
    outgoing: _Adjacency = {}
    either_way: _Adjacency = {}
    for edge in graph.edges.values():
        outgoing.setdefault(edge["source"], []).append((edge["target"], edge))
        either_way.setdefault(edge["source"], []).append((edge["target"], edge))
        either_way.setdefault(edge["target"], []).append((edge["source"], edge))

    # Follow the way the data flowed first; that is the reading a reader expects.
    reached: dict[str, tuple[int, dict[str, Any] | None]] = {graph.root: (0, None)}
    _walk(deque([graph.root]), reached, outgoing)
    # Then anything only connected the other way round, such as a certificate's issuer.
    seeds = sorted(reached, key=lambda node_id: reached[node_id][0])
    _walk(deque(seeds), reached, either_way)
    return reached


def build(root: Job, jobs: list[Job]) -> dict[str, Any]:
    graph = recap.build_graph(root, jobs, with_analyzers=True)
    reached = provenance(graph)
    nodes = [
        {
            "id": node["id"],
            "kind": node["kind"],
            "label": node["label"],
            "layer": reached[node["id"]][0],
            "via": reached[node["id"]][1],
            "data": _scalars(node["data"]),
        }
        for node in graph.nodes.values()
        if node["id"] in reached
    ]
    edges = [
        {
            "source": edge["source"],
            "target": edge["target"],
            "relation": edge["relation"],
            "plugin": edge["plugin"],
        }
        for edge in graph.edges.values()
        if edge["source"] in reached and edge["target"] in reached
    ]
    return {
        "format": "detection-graph-v1",
        "alpha": True,
        "root": graph.root,
        "truncated": graph.truncated,
        "nodes": nodes,
        "edges": edges,
    }
