"""The recap turns stored summaries into facts and a relation graph."""

from __future__ import annotations

import uuid
from types import SimpleNamespace

from app.models.job import ObservableType, ReportStatus
from app.services.recap import build_graph, build_recap


def _report(
    value: str,
    kind: ObservableType = ObservableType.IP,
    status: ReportStatus = ReportStatus.SUCCESS,
    plugin: str = "ipinfo",
    summary: dict | None = None,
    raw: dict | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        plugin_name=plugin,
        plugin_type="analyzer",
        status=status,
        observable_value=value,
        observable_type=kind,
        summary_data=summary or {},
        raw_output=raw,
    )


def _job(
    value: str,
    reports: list[SimpleNamespace],
    kind: ObservableType = ObservableType.IP,
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


def _relations(graph) -> set[tuple[str, str, str]]:
    return set(graph.edges)


def test_location_and_network_ownership_become_nodes() -> None:
    summary = {
        "asn": "AS13335",
        "organisation": "Cloudflare",
        "country": "au",
        "extra": {"city": "Sydney", "region": "NSW"},
    }
    job = _job("1.1.1.1", [_report("1.1.1.1", summary=summary)])
    graph = build_graph(job, [job])

    assert ("ip:1.1.1.1", "asn:AS13335", "announced_by") in _relations(graph)
    assert ("ip:1.1.1.1", "country:AU", "located_in") in _relations(graph)
    assert graph.labels("city") == ["Sydney, NSW, au"]


def test_a_pivot_links_the_parent_observable_to_the_child() -> None:
    parent = _job("http://bad.example/x", [], ObservableType.URL)
    child = _job("bad.example", [], ObservableType.DOMAIN, parent, "url_to_domain")
    graph = build_graph(parent, [parent, child])

    assert (
        "url:http://bad.example/x",
        "domain:bad.example",
        "url_to_domain",
    ) in _relations(graph)
    assert graph.root == "url:http://bad.example/x"


def test_certificate_names_and_issuers_are_linked() -> None:
    raw = {
        "names": ["a.example.com.", "A.example.com"],
        "issuers": ["Let's Encrypt"],
        "certificates": [{"id": 42, "common_name": "a.example.com", "issuer_name": "LE"}],
    }
    job = _job(
        "example.com",
        [_report("example.com", ObservableType.DOMAIN, plugin="crtsh", raw=raw)],
        ObservableType.DOMAIN,
    )
    graph = build_graph(job, [job])

    assert graph.targets("certified_as") == ["a.example.com"]
    assert graph.labels("certificate") == ["a.example.com"]
    assert graph.labels("issuer") == ["LE", "Let's Encrypt"]


def test_the_same_fact_from_two_sources_is_one_edge() -> None:
    summary = {"country": "FR"}
    job = _job(
        "9.9.9.9",
        [_report("9.9.9.9", summary=summary), _report("9.9.9.9", plugin="shodan", summary=summary)],
    )
    graph = build_graph(job, [job])

    assert len([key for key in graph.edges if key[2] == "located_in"]) == 1


def test_a_failed_report_contributes_nothing() -> None:
    job = _job(
        "8.8.8.8",
        [_report("8.8.8.8", status=ReportStatus.FAILED, summary={"country": "US"})],
    )
    graph = build_graph(job, [job])

    assert graph.labels("country") == []


def test_the_graph_is_bounded() -> None:
    ports = list(range(1, 600))
    job = _job("1.2.3.4", [_report("1.2.3.4", summary={"open_ports": ports})])
    graph = build_graph(job, [job])

    assert graph.truncated is True
    assert len(graph.nodes) <= 400


def test_the_recap_groups_facts_by_kind() -> None:
    summary = {
        "asn": "13335",
        "country": "AU",
        "open_ports": [443, 80],
        "cves": ["cve-2024-1"],
        "technologies": ["nginx"],
        "hostnames": ["one.one.one.one."],
    }
    job = _job("1.1.1.1", [_report("1.1.1.1", summary=summary)])
    recap = build_recap(job, [job])

    assert recap["network"]["ports"] == ["80", "443"]
    assert recap["network"]["cves"] == ["CVE-2024-1"]
    assert recap["network"]["domains"] == ["one.one.one.one"]
    assert recap["network"]["asns"] == ["AS13335"]
    assert recap["subject"]["reports"] == 1
