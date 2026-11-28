"""Investigation recap: one job tree, read as facts and as a relation graph.

The facts come from the normalised summaries the plugins already stored, so a
recap never calls a provider and costs no API quota. Each finished report
contributes nodes (an address, an AS, a country, a certificate, a registrar...)
and typed edges between them; the recap is then a view over those nodes.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

from app.models.job import Job, PluginReport, ReportStatus
from app.services import xeno_score

MAX_NODES = 400
MAX_EDGES = 1200
MAX_CERTIFICATES = 50
MAX_TAGS_PER_REPORT = 12
MAX_DETECTIONS_PER_REPORT = 30


def _key(value: str) -> str:
    return value.strip().lower()


def _host(value: object) -> str:
    return str(value).strip().rstrip(".").lower()


def _as_list(value: object) -> list[Any]:
    if isinstance(value, list):
        return value
    return [value] if value else []


def _port_order(label: str) -> tuple[int, str]:
    return (int(label), "") if label.isdigit() else (1 << 30, label)


@dataclass
class Graph:
    """Nodes keyed by `kind:value`, edges keyed by their endpoints and relation."""

    root: str | None = None
    nodes: dict[str, dict[str, Any]] = field(default_factory=dict)
    edges: dict[tuple[str, str, str], dict[str, Any]] = field(default_factory=dict)
    truncated: bool = False
    # Detection view only. Analyzers and pivots become nodes of their own, so every
    # finding is reached through the source that produced it and the chain reads back.
    with_analyzers: bool = False
    _anchor: tuple[str, str] | None = field(default=None, repr=False)

    def node(self, kind: str, value: str, label: str | None = None, **data: Any) -> str | None:
        node_id = f"{kind}:{value}"
        existing = self.nodes.get(node_id)
        if existing is None:
            if len(self.nodes) >= MAX_NODES:
                self.truncated = True
                return None
            existing = {"id": node_id, "kind": kind, "label": label or value, "data": {}}
            self.nodes[node_id] = existing
        existing["data"].update({key: val for key, val in data.items() if val is not None})
        return node_id

    def link(
        self, source: str | None, target: str | None, relation: str, plugin: str | None = None
    ) -> None:
        anchor = self._anchor
        if anchor is not None and plugin and source == anchor[0]:
            # A finding of the analyzer being read: subject -> analyzer -> finding.
            self.put(source, anchor[1], "analysed_by", plugin)
            source = anchor[1]
        self.put(source, target, relation, plugin)

    def put(
        self, source: str | None, target: str | None, relation: str, plugin: str | None = None
    ) -> None:
        if source is None or target is None or source == target:
            return
        key = (source, target, relation)
        if key in self.edges:
            return
        if len(self.edges) >= MAX_EDGES:
            self.truncated = True
            return
        self.edges[key] = {
            "source": source,
            "target": target,
            "relation": relation,
            "plugin": plugin,
        }

    def labels(self, kind: str) -> list[str]:
        found = {node["label"] for node in self.nodes.values() if node["kind"] == kind}
        return sorted(found, key=str.lower)

    def targets(self, relation: str) -> list[str]:
        return sorted(
            {
                self.nodes[target]["label"]
                for (_, target, rel) in self.edges
                if rel == relation and target in self.nodes
            },
            key=str.lower,
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "root": self.root,
            "nodes": list(self.nodes.values()),
            "edges": list(self.edges.values()),
            "truncated": self.truncated,
        }


def build_graph(root: Job, jobs: list[Job], with_analyzers: bool = False) -> Graph:
    """Graph of the observables of every job in the tree, linked by pivot lineage.

    With `with_analyzers`, each analyzer and each pivot is a node of its own (the
    detection view). Without it, findings hang directly off the observable.
    """
    graph = Graph(with_analyzers=with_analyzers)
    observable_of: dict[uuid.UUID, str | None] = {}
    for job in jobs:
        observable_of[job.id] = graph.node(
            job.observable_type.value, _key(job.observable_value), job.observable_value
        )
    graph.root = observable_of.get(root.id)

    for job in jobs:
        if job.parent_job_id in observable_of:
            _link_pivot(
                graph,
                observable_of[job.parent_job_id],
                observable_of[job.id],
                job.pivot_name or "pivot",
            )
        for report in job.reports:
            if with_analyzers:
                if report.plugin_type == "analyzer":
                    _add_report(graph, report)
            elif report.status is ReportStatus.SUCCESS:
                _add_report(graph, report)
    return graph


def _link_pivot(graph: Graph, parent: str | None, child: str | None, name: str) -> None:
    if not graph.with_analyzers:
        graph.link(parent, child, name, name)
        return
    pivot = graph.node("pivot", f"{name}@{parent}", name)
    graph.put(parent, pivot, "spawned", name)
    graph.put(pivot, child, name, name)


def _text(value: object) -> str:
    return str(getattr(value, "value", value))


def _add_report(graph: Graph, report: PluginReport) -> None:
    subject = graph.node(
        report.observable_type.value, _key(report.observable_value), report.observable_value
    )
    summary: dict[str, Any] = report.summary_data or {}
    extra: dict[str, Any] = summary.get("extra") or {}
    raw: dict[str, Any] = report.raw_output or {}
    plugin = report.plugin_name
    if not graph.with_analyzers:
        _add_findings(graph, subject, summary, extra, raw, plugin)
        return

    analyzer = _add_analyzer(graph, subject, report, summary)
    if analyzer is None or report.status is not ReportStatus.SUCCESS:
        return
    graph._anchor = (subject, analyzer)
    try:
        _add_findings(graph, subject, summary, extra, raw, plugin)
        _add_facets(graph, analyzer, summary, plugin)
    finally:
        graph._anchor = None


def _add_analyzer(
    graph: Graph, subject: str | None, report: PluginReport, summary: dict[str, Any]
) -> str | None:
    """One node per analyzer per observable: what it was asked, and what it concluded."""
    if subject is None:
        return None
    headline = summary.get("headline")
    score = summary.get("score")
    reason = getattr(report, "errors", None)
    node = graph.node(
        "analyzer",
        f"{report.plugin_name}@{subject}",
        report.plugin_name,
        verdict=summary.get("verdict") or "unknown",
        status=_text(report.status),
        headline=str(headline)[:240] if headline else None,
        score=score if isinstance(score, int) else None,
        reason=str(reason)[:240] if reason else None,
    )
    graph.put(subject, node, "analysed_by", report.plugin_name)
    return node


def _add_facets(graph: Graph, analyzer: str | None, summary: dict[str, Any], plugin: str) -> None:
    """What the analyzer tagged and which engines flagged it, as nodes of their own."""
    for tag in _as_list(summary.get("tags"))[:MAX_TAGS_PER_REPORT]:
        text = str(tag).strip()
        if text:
            graph.put(analyzer, graph.node("tag", _key(text), text), "tagged", plugin)
    for entry in _as_list(summary.get("detections"))[:MAX_DETECTIONS_PER_REPORT]:
        if not isinstance(entry, dict):
            continue
        engine = str(entry.get("engine") or "").strip()
        result = str(entry.get("result") or "").strip()
        if not engine:
            continue
        node = graph.node(
            "detection",
            _key(f"{engine}:{result}"),
            f"{result or 'flagged'} ({engine})",
            engine=engine,
            category=entry.get("category"),
        )
        graph.put(analyzer, node, "flagged_as", plugin)


def _add_findings(
    graph: Graph,
    subject: str | None,
    summary: dict[str, Any],
    extra: dict[str, Any],
    raw: dict[str, Any],
    plugin: str,
) -> None:
    _add_location(graph, subject, summary, extra, plugin)
    _add_services(graph, subject, summary, plugin)
    _add_names(graph, subject, summary, extra, raw, plugin)
    _add_certificates(graph, subject, extra, raw, plugin)
    _add_registration(graph, subject, extra, plugin)


def _link_asn(
    graph: Graph, subject: str | None, number: object, organisation: str | None, plugin: str
) -> None:
    text = str(number).strip().upper()
    if not text:
        return
    asn = text if text.startswith("AS") else f"AS{text}"
    label = f"{asn} {organisation}" if organisation else asn
    node = graph.node("asn", asn, label, organisation=organisation)
    graph.link(subject, node, "announced_by", plugin)


def _add_location(
    graph: Graph,
    subject: str | None,
    summary: dict[str, Any],
    extra: dict[str, Any],
    plugin: str,
) -> None:
    if summary.get("asn"):
        organisation = summary.get("organisation")
        _link_asn(graph, subject, summary["asn"], organisation, plugin)
    country = summary.get("country")
    if country:
        code = str(country).strip().upper()
        graph.link(subject, graph.node("country", code, code), "located_in", plugin)
    city = extra.get("city")
    if city:
        place = ", ".join(str(part) for part in (city, extra.get("region"), country) if part)
        graph.link(subject, graph.node("city", _key(place), place), "located_in", plugin)


def _add_services(graph: Graph, subject: str | None, summary: dict[str, Any], plugin: str) -> None:
    for port in _as_list(summary.get("open_ports")):
        graph.link(subject, graph.node("port", str(port), str(port)), "exposes", plugin)
    for tech in _as_list(summary.get("technologies")):
        text = str(tech).strip()
        if text:
            graph.link(subject, graph.node("technology", _key(text), text), "runs", plugin)
    for cve in _as_list(summary.get("cves")):
        identifier = str(cve).strip().upper()
        graph.link(subject, graph.node("cve", identifier, identifier), "affected_by", plugin)


def _add_names(
    graph: Graph,
    subject: str | None,
    summary: dict[str, Any],
    extra: dict[str, Any],
    raw: dict[str, Any],
    plugin: str,
) -> None:
    for host in _as_list(summary.get("hostnames")) + _as_list(extra.get("ptr")):
        name = _host(host)
        graph.link(subject, graph.node("domain", name, name), "reverse_dns", plugin)

    records = raw.get("records")
    if not isinstance(records, dict):
        return
    for address in _as_list(records.get("A")) + _as_list(records.get("AAAA")):
        graph.link(subject, graph.node("ip", str(address), str(address)), "resolves_to", plugin)
    for server in _as_list(records.get("NS")):
        name = _host(server)
        graph.link(subject, graph.node("domain", name, name), "nameserver", plugin)


def _add_issuer(graph: Graph, name: object) -> str | None:
    label = str(name).strip()
    return graph.node("issuer", _key(label), label) if label else None


def _add_certificates(
    graph: Graph,
    subject: str | None,
    extra: dict[str, Any],
    raw: dict[str, Any],
    plugin: str,
) -> None:
    for name in _as_list(raw.get("names")):
        host = _host(name)
        graph.link(subject, graph.node("domain", host, host), "certified_as", plugin)
    for issuer in _as_list(raw.get("issuers")):
        graph.link(subject, _add_issuer(graph, issuer), "issued_by", plugin)
    for cert in _as_list(raw.get("certificates"))[:MAX_CERTIFICATES]:
        if not isinstance(cert, dict) or cert.get("id") is None:
            continue
        cert_id = str(cert["id"])
        node = graph.node(
            "certificate",
            cert_id,
            str(cert.get("common_name") or cert_id),
            issuer=cert.get("issuer_name"),
            not_before=cert.get("not_before"),
            not_after=cert.get("not_after"),
            serial=cert.get("serial_number"),
        )
        graph.link(subject, node, "presented", plugin)
        graph.link(node, _add_issuer(graph, cert.get("issuer_name")), "issued_by", plugin)

    for entry in _as_list(extra.get("certificates")):
        if not isinstance(entry, dict) or not entry.get("fingerprint"):
            continue
        fingerprint = str(entry["fingerprint"]).lower()
        node = graph.node(
            "certificate",
            fingerprint,
            str(entry.get("subject") or fingerprint[:16]),
            issuer=entry.get("issuer"),
            validity=entry.get("validity"),
        )
        graph.link(subject, node, "presented", plugin)
        graph.link(node, _add_issuer(graph, entry.get("issuer")), "issued_by", plugin)


def _add_registration(
    graph: Graph, subject: str | None, extra: dict[str, Any], plugin: str
) -> None:
    registrar = extra.get("registrar")
    if registrar:
        text = str(registrar).strip()
        graph.link(subject, graph.node("registrar", _key(text), text), "registered_with", plugin)
    for contact in [extra.get("abuse_email"), *_as_list(extra.get("abuse_contacts"))]:
        if contact:
            text = str(contact).strip()
            graph.link(subject, graph.node("contact", _key(text), text), "abuse_contact", plugin)
    prefix = extra.get("prefix")
    if prefix:
        graph.link(subject, graph.node("prefix", str(prefix), str(prefix)), "in_prefix", plugin)
    for number in _as_list(extra.get("asns")):
        _link_asn(graph, subject, number, None, plugin)


def _verdict_line(job: Job, report: PluginReport) -> dict[str, Any]:
    summary: dict[str, Any] = report.summary_data or {}
    return {
        "job_id": job.id,
        "observable_value": report.observable_value,
        "plugin_name": report.plugin_name,
        "plugin_type": report.plugin_type,
        "status": report.status,
        "verdict": summary.get("verdict") or "unknown",
        "detection_ratio": summary.get("detection_ratio"),
        "headline": summary.get("headline"),
        "links": [link for link in _as_list(summary.get("links")) if isinstance(link, dict)][:10],
    }


def build_recap(root: Job, jobs: list[Job]) -> dict[str, Any]:
    """Facts and graph for a job and the pivots it spawned, as the API returns them."""
    graph = build_graph(root, jobs)
    reports = [report for job in jobs for report in job.reports]
    certificates = [
        {"label": node["label"], **node["data"]}
        for node in graph.nodes.values()
        if node["kind"] == "certificate"
    ]
    return {
        "subject": {
            "job_id": root.id,
            "observable_value": root.observable_value,
            "observable_type": root.observable_type,
            "status": root.status,
            "verdict": root.verdict,
            "tlp": root.tlp,
            "tags": list(root.tags or []),
            "requested_by_name": root.requested_by_name,
            "created_at": root.created_at,
            "finished_at": root.finished_at,
            "jobs": len(jobs),
            "reports": len(reports),
        },
        "network": {
            "ips": graph.labels("ip"),
            "domains": graph.labels("domain"),
            "asns": graph.labels("asn"),
            "countries": graph.labels("country"),
            "cities": graph.labels("city"),
            "ports": sorted(graph.labels("port"), key=_port_order),
            "technologies": graph.labels("technology"),
            "cves": graph.labels("cve"),
        },
        "certificates": {
            "names": graph.targets("certified_as"),
            "issuers": graph.labels("issuer"),
            "certificates": certificates,
        },
        "registration": {
            "registrars": graph.labels("registrar"),
            "contacts": graph.labels("contact"),
            "prefixes": graph.labels("prefix"),
        },
        "verdicts": [_verdict_line(job, report) for job in jobs for report in job.reports],
        "graph": graph.as_dict(),
        # Scored on the root observable only: pivots are other observables.
        "xeno_score": xeno_score.compute(list(root.reports)).as_dict(),
    }
