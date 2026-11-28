"""MISP export connector, against mocked responses only."""

from __future__ import annotations

import json
import socket
import uuid

import httpx
import pytest
import respx

from app.models.job import ReportStatus, Tlp, Verdict
from app.plugins.base.plugin import JobContext
from app.plugins.connector.misp import MispConnector, attribute_type
from app.services.observables import classify

_BASE = "https://203.0.113.20"  # TEST-NET literal: no DNS needed


def _context(value: str, verdict: Verdict, tlp: Tlp = Tlp.AMBER) -> JobContext:
    return JobContext(
        job_id=uuid.uuid4(),
        observable=classify(value),
        verdict=verdict,
        tlp=tlp,
        tags=["phishing"],
        summary={},
        reports=[],
        requested_by="analyst",
    )


def _connector(**options: object) -> MispConnector:
    return MispConnector(secrets={"base_url": _BASE, "api_key": "k" * 40}, options=options)


def test_attribute_types_follow_the_observable() -> None:
    assert attribute_type(classify("8.8.8.8").type, "8.8.8.8") == "ip-dst"
    assert attribute_type(classify("a.example.com").type, "a.example.com") == "domain"
    assert attribute_type(classify("a" * 64).type, "a" * 64) == "sha256"
    assert attribute_type(classify("a" * 32).type, "a" * 32) == "md5"


@respx.mock
async def test_a_malicious_domain_creates_an_unpublished_private_event() -> None:
    route = respx.post(f"{_BASE}/events/add").mock(
        return_value=httpx.Response(200, json={"Event": {"id": "42", "uuid": "u-1"}})
    )
    result = await _connector().run(_context("evil.example.com", Verdict.MALICIOUS))
    assert result.status is ReportStatus.SUCCESS
    sent = json.loads(route.calls[0].request.content)
    assert route.calls[0].request.headers["Authorization"] == "k" * 40
    assert sent["published"] is False
    assert sent["distribution"] == 0
    assert sent["threat_level_id"] == 1
    assert sent["Attribute"][0]["to_ids"] is True
    names = {tag["name"] for tag in sent["Tag"]}
    assert {"tlp:amber", "xenoproxy:verdict=malicious", "phishing"} <= names
    assert result.summary.as_dict()["links"][0]["url"].endswith("/events/view/42")


@respx.mock
async def test_only_a_malicious_verdict_is_marked_for_ids() -> None:
    route = respx.post(f"{_BASE}/events/add").mock(
        return_value=httpx.Response(200, json={"Event": {"id": "7"}})
    )
    await _connector().run(_context("8.8.8.8", Verdict.SUSPICIOUS))
    sent = json.loads(route.calls[0].request.content)
    assert sent["Attribute"][0]["to_ids"] is False
    assert sent["threat_level_id"] == 2


@respx.mock
async def test_a_rejected_event_is_a_failure() -> None:
    respx.post(f"{_BASE}/events/add").mock(
        return_value=httpx.Response(200, json={"name": "x", "message": "Event already exists"})
    )
    result = await _connector().run(_context("8.8.8.8", Verdict.MALICIOUS))
    assert result.status is ReportStatus.FAILED
    assert "already exists" in (result.error or "")


@respx.mock
async def test_an_http_error_is_a_failure() -> None:
    respx.post(f"{_BASE}/events/add").mock(return_value=httpx.Response(403))
    result = await _connector().run(_context("8.8.8.8", Verdict.MALICIOUS))
    assert result.status is ReportStatus.FAILED
    assert "403" in (result.error or "")


async def test_red_is_refused_for_a_public_instance(monkeypatch: pytest.MonkeyPatch) -> None:
    # TEST-NET counts as private to ipaddress, so resolve to a genuinely public address.
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("104.18.1.1", 0))],
    )
    plugin = MispConnector(
        secrets={"base_url": _BASE, "api_key": "k" * 40},
        options={"trusted_internal": True},
        job_tlp=Tlp.RED,
    )
    result = await plugin.run(_context("8.8.8.8", Verdict.MALICIOUS, Tlp.RED))
    assert result.status is ReportStatus.SKIPPED
