"""Critical-threat alert connector: formats, signing, floor and failures."""

from __future__ import annotations

import json
import uuid

import httpx
import respx

from app.models.job import JobStatus, PluginKind, ReportStatus, Tlp, Verdict
from app.plugins.base.plugin import JobContext, ReportView
from app.plugins.connector.critical_webhook import CriticalWebhookConnector
from app.services.observables import classify

_URL = "https://203.0.113.10/services/T000/B000/secret"  # TEST-NET literal: no DNS needed


def _context(
    verdict: Verdict = Verdict.MALICIOUS,
    *,
    tlp: Tlp = Tlp.AMBER,
    value: str = "evil.example.com",
    reports: list[ReportView] | None = None,
) -> JobContext:
    return JobContext(
        job_id=uuid.uuid4(),
        observable=classify(value),
        verdict=verdict,
        tlp=tlp,
        tags=["phishing"],
        summary={},
        reports=reports
        if reports is not None
        else [
            ReportView(
                plugin_name="virustotal",
                plugin_type=PluginKind.ANALYZER,
                status=ReportStatus.SUCCESS,
                summary={"verdict": "malicious", "headline": "12 engines flag it."},
                raw_output=None,
            ),
            ReportView(
                plugin_name="otx",
                plugin_type=PluginKind.ANALYZER,
                status=ReportStatus.SUCCESS,
                summary={"verdict": "clean", "headline": "Nothing."},
                raw_output=None,
            ),
        ],
        requested_by="analyst",
    )


def _connector(fmt: str, **options: object) -> CriticalWebhookConnector:
    return CriticalWebhookConnector(
        secrets={"webhook_url": _URL, "signing_key": "k" * 32},
        options={"format": fmt, **options},
    )


def _sent(route: respx.Route) -> dict:
    return json.loads(route.calls.last.request.content)


@respx.mock
async def test_slack_message_names_the_observable_and_escapes_markup() -> None:
    route = respx.post(_URL).mock(return_value=httpx.Response(200, text="ok"))
    context = _context(value="evil.example.com", reports=_context().reports)
    result = await _connector("slack").run(context)
    assert result.status is ReportStatus.SUCCESS
    text = _sent(route)["text"]
    assert "evil.example.com" in text
    assert "virustotal: malicious" in text
    assert "otx" not in text  # clean analyzers are not alerts
    assert "<" not in text and ">" not in text


@respx.mock
async def test_slack_request_is_not_signed() -> None:
    route = respx.post(_URL).mock(return_value=httpx.Response(200, text="ok"))
    await _connector("slack").run(_context())
    assert "X-XenoProxy-Signature" not in route.calls.last.request.headers


@respx.mock
async def test_discord_content_stays_under_the_limit() -> None:
    route = respx.post(_URL).mock(return_value=httpx.Response(204))
    long_headline = "x" * 500
    reports = [
        ReportView(
            plugin_name=f"analyzer{i}",
            plugin_type=PluginKind.ANALYZER,
            status=ReportStatus.SUCCESS,
            summary={"verdict": "suspicious", "headline": long_headline},
            raw_output=None,
        )
        for i in range(12)
    ]
    result = await _connector("discord").run(_context(Verdict.SUSPICIOUS, reports=reports))
    assert result.status is ReportStatus.SUCCESS
    assert len(_sent(route)["content"]) <= 1900


@respx.mock
async def test_teams_uses_a_message_card_with_a_verdict_colour() -> None:
    route = respx.post(_URL).mock(return_value=httpx.Response(200, text="1"))
    await _connector("teams").run(_context())
    body = _sent(route)
    assert body["@type"] == "MessageCard"
    assert body["themeColor"] == "C00000"
    assert "evil.example.com" in body["title"]


@respx.mock
async def test_generic_format_is_signed_and_carries_the_verdict() -> None:
    route = respx.post(_URL).mock(return_value=httpx.Response(200, json={"ok": True}))
    await _connector("generic").run(_context())
    assert route.calls.last.request.headers["X-XenoProxy-Signature"].startswith("sha256=")
    body = _sent(route)
    assert body["event"] == "job.critical"
    assert body["verdict"] == "malicious"


def test_a_verdict_below_the_floor_is_declined() -> None:
    connector = _connector("slack")  # default floor: malicious
    assert connector.refusal_reason(_context(Verdict.MALICIOUS), JobStatus.SUCCESS) is None
    refusal = connector.refusal_reason(_context(Verdict.SUSPICIOUS), JobStatus.SUCCESS)
    assert refusal is not None
    assert "below the configured floor" in refusal


def test_a_suspicious_floor_sends_suspicious_verdicts() -> None:
    connector = _connector("slack", minimum_verdict="suspicious")
    assert connector.refusal_reason(_context(Verdict.SUSPICIOUS), JobStatus.SUCCESS) is None


def test_a_channel_declares_amber_so_red_material_never_reaches_it() -> None:
    # The orchestrator enforces max_tlp; this pins the declaration it reads.
    assert CriticalWebhookConnector.max_tlp is Tlp.AMBER


@respx.mock
async def test_unknown_format_fails_without_sending() -> None:
    route = respx.post(_URL).mock(return_value=httpx.Response(200))
    result = await _connector("sms").run(_context())
    assert result.status is ReportStatus.FAILED
    assert not route.called


@respx.mock
async def test_receiver_error_is_reported_as_failure() -> None:
    respx.post(_URL).mock(return_value=httpx.Response(500))
    result = await _connector("slack").run(_context())
    assert result.status is ReportStatus.FAILED
