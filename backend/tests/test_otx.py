"""AlienVault OTX analyzer: verdict scaling, quota handling and indicator routing."""

from __future__ import annotations

import httpx
import respx

from app.models.job import ReportStatus, Verdict
from app.plugins.analyzer.otx import OtxAnalyzer
from app.services.observables import classify

_KEY = "otx-test-key-0123456789"


def _pulses(count: int) -> dict:
    return {
        "reputation": 0,
        "pulse_info": {
            "count": count,
            "pulses": [
                {
                    "id": f"pulse{index}",
                    "name": f"Campaign {index}",
                    "tags": ["Phishing"],
                    "adversary": "APT-Example",
                    "malware_families": [{"display_name": "Emotet"}],
                }
                for index in range(min(count, 25))
            ],
        },
    }


@respx.mock
async def test_a_single_pulse_is_suspicious_not_malicious() -> None:
    respx.get(url__startswith="https://otx.alienvault.com/api/v1/indicators/IPv4/").mock(
        return_value=httpx.Response(200, json=_pulses(1))
    )
    result = await OtxAnalyzer(secrets={"api_key": _KEY}).execute(classify("8.8.8.8"))
    assert result.status is ReportStatus.SUCCESS
    summary = result.summary.as_dict()
    assert summary["verdict"] == Verdict.SUSPICIOUS.value
    assert "emotet" in summary["tags"]
    assert summary["extra"]["adversaries"] == ["APT-Example"]


@respx.mock
async def test_several_independent_pulses_are_malicious() -> None:
    respx.get(url__startswith="https://otx.alienvault.com/api/v1/indicators/domain/").mock(
        return_value=httpx.Response(200, json=_pulses(5))
    )
    result = await OtxAnalyzer(secrets={"api_key": _KEY}).execute(classify("evil.example.com"))
    summary = result.summary.as_dict()
    assert summary["verdict"] == Verdict.MALICIOUS.value
    assert summary["extra"]["pulse_count"] == 5
    assert summary["links"][0]["url"] == "https://otx.alienvault.com/pulse/pulse0"


@respx.mock
async def test_no_pulse_is_unknown_rather_than_clean() -> None:
    respx.get(url__startswith="https://otx.alienvault.com/api/v1/indicators/IPv4/").mock(
        return_value=httpx.Response(200, json=_pulses(0))
    )
    result = await OtxAnalyzer(secrets={"api_key": _KEY}).execute(classify("8.8.4.4"))
    assert result.summary.as_dict()["verdict"] == Verdict.UNKNOWN.value


@respx.mock
async def test_quota_is_reported_without_leaking_the_key() -> None:
    respx.get(url__startswith="https://otx.alienvault.com/api/v1/indicators/").mock(
        return_value=httpx.Response(429, json={"error": "rate limited"})
    )
    result = await OtxAnalyzer(secrets={"api_key": _KEY}).execute(classify("8.8.8.8"))
    assert result.status is ReportStatus.FAILED
    assert "429" in (result.error or "")
    assert _KEY not in (result.error or "")


@respx.mock
async def test_unknown_indicator_is_not_an_error() -> None:
    respx.get(url__startswith="https://otx.alienvault.com/api/v1/indicators/").mock(
        return_value=httpx.Response(404, json={"detail": "not found"})
    )
    result = await OtxAnalyzer(secrets={"api_key": _KEY}).execute(classify("8.8.8.8"))
    assert result.status is ReportStatus.SUCCESS
    assert result.summary.as_dict()["verdict"] == Verdict.UNKNOWN.value


@respx.mock
async def test_url_is_escaped_and_routed_as_a_url_indicator() -> None:
    route = respx.get(url__startswith="https://otx.alienvault.com/api/v1/indicators/url/").mock(
        return_value=httpx.Response(200, json=_pulses(0))
    )
    await OtxAnalyzer(secrets={"api_key": _KEY}).execute(classify("https://evil.example.com/a?b=1"))
    assert route.called
    requested = str(route.calls.last.request.url)
    assert "https%3A%2F%2Fevil.example.com%2Fa%3Fb%3D1" in requested


@respx.mock
async def test_ipv6_is_routed_as_ipv6() -> None:
    route = respx.get(url__startswith="https://otx.alienvault.com/api/v1/indicators/IPv6/").mock(
        return_value=httpx.Response(200, json=_pulses(0))
    )
    await OtxAnalyzer(secrets={"api_key": _KEY}).execute(classify("2001:4860:4860::8888"))
    assert route.called
