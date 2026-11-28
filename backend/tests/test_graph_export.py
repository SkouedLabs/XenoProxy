"""Property-graph export of a recap graph."""

from __future__ import annotations

from app.services.graph_export import to_property_graph

_GRAPH = {
    "root": "ip:1.2.3.4",
    "truncated": False,
    "nodes": [
        {"id": "ip:1.2.3.4", "kind": "ip", "label": "1.2.3.4", "data": {"asn": 64496}},
        {"id": "domain:a.example", "kind": "domain", "label": "a.example", "data": {}},
        {
            "id": "cert:1",
            "kind": "certificate",
            "label": "c",
            "data": {"names": ["a", "b"], "x": {}},
        },
    ],
    "edges": [
        {
            "source": "domain:a.example",
            "target": "ip:1.2.3.4",
            "relation": "resolves_to",
            "plugin": "dns",
        },
        {"source": "ip:1.2.3.4", "target": "ghost", "relation": "hosts", "plugin": "x"},
    ],
}


def test_nodes_get_pascal_labels_and_scalar_properties() -> None:
    out = to_property_graph(_GRAPH)
    ip, _, cert = out["nodes"]
    assert ip["labels"] == ["Ip"]
    assert ip["properties"] == {"asn": 64496, "name": "1.2.3.4"}
    assert cert["properties"]["names"] == ["a", "b"]
    assert "x" not in cert["properties"]


def test_relationships_use_upper_snake_types_and_drop_dangling_edges() -> None:
    out = to_property_graph(_GRAPH)
    assert len(out["relationships"]) == 1
    rel = out["relationships"][0]
    assert rel["type"] == "RESOLVES_TO"
    assert rel["from"] == "domain:a.example"
    assert rel["properties"] == {"plugin": "dns"}


def test_export_is_flagged_alpha_and_keeps_root() -> None:
    out = to_property_graph(_GRAPH)
    assert out["alpha"] is True
    assert out["root"] == "ip:1.2.3.4"
