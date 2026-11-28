"""The detection graph keeps the route a finding took, and stays off the recap's default view."""

from __future__ import annotations

import uuid
from types import SimpleNamespace

from app.models.job import ObservableType, ReportStatus
from app.services import detection_graph
from app.services.recap import build_graph


def _report(
    value: str,
    kind: ObservableType,
    plugin: str,
    status: ReportStatus = ReportStatus.SUCCESS,
    summary: dict | None = None,
    raw: dict | None = None,
    plugin_type: str = "analyzer",
) -> SimpleNamespace:
    return SimpleNamespace(
        plugin_name=plugin,
        plugin_type=plugin_type,
        status=status,
        observable_value=value,
        observable_type=kind,
        summary_data=summary or {},
        raw_output=raw,
        errors=None,
    )


def _job(
    value: str,
    kind: ObservableType,
    reports: list[SimpleNamespace],
    parent: SimpleNamespace | None = None,
    pivot: str | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        id=uuid.uuid4(),
        observable_value=value,
        observable_type=kind,
        parent_job_id=parent.id if parent else None,
        pivot_name=pivot,
        reports=reports,
        status="success",
        verdict="unknown",
        tlp="amber",
        tags=[],
        requested_by_name="user",
        created_at=None,
        finished_at=None,
    )


def _by_id(graph: dict) -> dict[str, dict]:
    return {node["id"]: node for node in graph["nodes"]}


def test_a_pivoted_ip_is_reached_through_the_dns_lookup_that_found_it() -> None:
    dns = _report(
        "evil.example.com",
        ObservableType.DOMAIN,
        "dns",
        raw={"records": {"A": ["203.0.113.7"]}},
    )
    root = _job("evil.example.com", ObservableType.DOMAIN, [dns])
    shodan = _report(
        "203.0.113.7",
        ObservableType.IP,
        "shodan_internetdb",
        summary={"open_ports": [443], "asn": "AS64500"},
    )
    child = _job("203.0.113.7", ObservableType.IP, [shodan], parent=root, pivot="domain_to_ip")

    graph = detection_graph.build(root, [root, child])
    nodes = _by_id(graph)

    assert nodes["analyzer:dns@domain:evil.example.com"]["layer"] == 1
    ip = nodes["ip:203.0.113.7"]
    assert ip["layer"] == 2
    assert ip["via"] == {
        "from": "analyzer:dns@domain:evil.example.com",
        "relation": "resolves_to",
        "plugin": "dns",
    }
    # The pivot that created the child job is a node too, so both routes are visible.
    assert "pivot:domain_to_ip@domain:evil.example.com" in nodes
    # What the child's own analyzer found hangs off the IP, one hop further.
    assert nodes["port:443"]["layer"] == 4
    assert nodes["port:443"]["via"]["plugin"] == "shodan_internetdb"


def test_a_hash_gets_detections_and_tags_but_no_network_facts() -> None:
    vt = _report(
        "a" * 64,
        ObservableType.HASH,
        "virustotal",
        summary={
            "verdict": "malicious",
            "tags": ["trojan"],
            "detections": [
                {"engine": "Sophos", "result": "Mal/Gen", "category": "malicious"},
            ],
        },
    )
    bazaar = _report(
        "a" * 64,
        ObservableType.HASH,
        "malwarebazaar",
        status=ReportStatus.FAILED,
    )
    root = _job("a" * 64, ObservableType.HASH, [vt, bazaar])

    graph = detection_graph.build(root, [root])
    nodes = _by_id(graph)
    kinds = {node["kind"] for node in graph["nodes"]}

    assert "detection" in kinds and "tag" in kinds
    assert not kinds & {"ip", "asn", "cve", "port", "country"}
    assert nodes["detection:sophos:mal/gen"]["label"] == "Mal/Gen (Sophos)"
    failed = nodes["analyzer:malwarebazaar@hash:" + "a" * 64]
    assert failed["data"]["status"] == ReportStatus.FAILED.value
    assert failed["data"]["verdict"] == "unknown"
    # A failed source finds nothing: its only relation is the one to the observable.
    outgoing = [edge for edge in graph["edges"] if edge["source"] == failed["id"]]
    assert outgoing == []


def test_connectors_are_not_drawn_as_sources() -> None:
    export = _report(
        "203.0.113.7",
        ObservableType.IP,
        "opencti_export",
        summary={"countries": ["DE"]},
        plugin_type="connector",
    )
    root = _job("203.0.113.7", ObservableType.IP, [export])

    nodes = _by_id(detection_graph.build(root, [root]))

    assert not [node for node in nodes.values() if node["kind"] == "analyzer"]
    assert "country:DE" not in nodes


def test_the_recap_graph_is_unchanged_by_default() -> None:
    dns = _report(
        "evil.example.com",
        ObservableType.DOMAIN,
        "dns",
        raw={"records": {"A": ["203.0.113.7"]}},
    )
    root = _job("evil.example.com", ObservableType.DOMAIN, [dns])

    plain = build_graph(root, [root])

    assert all(node["kind"] != "analyzer" for node in plain.nodes.values())
    assert ("domain:evil.example.com", "ip:203.0.113.7", "resolves_to") in plain.edges


def test_nodes_no_edge_reaches_are_left_out() -> None:
    lonely = _report(
        "203.0.113.7",
        ObservableType.IP,
        "ipinfo",
        summary={"country": "DE"},
    )
    root = _job("203.0.113.7", ObservableType.IP, [lonely])
    other = _job("198.51.100.1", ObservableType.IP, [])

    graph = detection_graph.build(root, [root, other])

    assert "ip:198.51.100.1" not in _by_id(graph)
