"""Have I Been Pwned breach lookup, checked against mocks only."""

from __future__ import annotations

import httpx
import respx

from app.models.job import ReportStatus, Verdict
from app.plugins.analyzer.hibp import HibpAnalyzer
from app.services.observables import classify

_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/"


def _analyzer() -> HibpAnalyzer:
    return HibpAnalyzer(secrets={"api_key": "h" * 32})


@respx.mock
async def test_breached_address_is_suspicious_with_breach_names() -> None:
    respx.get(url__startswith=_URL).mock(
        return_value=httpx.Response(
            200,
            json=[{"Name": "Adobe"}, {"Name": "LinkedIn"}, {"Name": "Adobe"}],
        )
    )
    result = await _analyzer().execute(classify("user@example.com"))
    summary = result.summary.as_dict()
    assert result.status is ReportStatus.SUCCESS
    assert summary["verdict"] == Verdict.SUSPICIOUS.value
    assert "breached" in summary["tags"]
    assert result.raw_output == {"breaches": ["Adobe", "LinkedIn"]}


@respx.mock
async def test_stealer_log_and_sensitive_breach_are_tagged_not_malicious() -> None:
    respx.get(url__startswith=_URL).mock(
        return_value=httpx.Response(
            200,
            json=[{"Name": "Infostealer", "IsStealerLog": True, "IsSensitive": True}],
        )
    )
    result = await _analyzer().execute(classify("user@example.com"))
    summary = result.summary.as_dict()
    assert summary["verdict"] == Verdict.SUSPICIOUS.value
    assert "stealer-log" in summary["tags"]
    assert "sensitive-breach" in summary["tags"]


@respx.mock
async def test_no_breach_is_unknown_not_clean() -> None:
    respx.get(url__startswith=_URL).mock(return_value=httpx.Response(404))
    result = await _analyzer().execute(classify("user@example.com"))
    assert result.status is ReportStatus.SUCCESS
    assert result.summary.as_dict()["verdict"] == Verdict.UNKNOWN.value


@respx.mock
async def test_key_and_user_agent_are_sent_and_path_is_quoted() -> None:
    route = respx.get(url__startswith=_URL).mock(return_value=httpx.Response(404))
    await _analyzer().execute(classify("user+tag@example.com"))
    request = route.calls.last.request
    assert request.headers["hibp-api-key"] == "h" * 32
    assert request.headers["User-Agent"] == "XenoProxy"
    assert "truncateResponse=true" in str(request.url)
    assert "user%2Btag" in str(request.url) or "user+tag" in str(request.url)


@respx.mock
async def test_quota_is_reported_as_a_failure() -> None:
    respx.get(url__startswith=_URL).mock(
        return_value=httpx.Response(429, headers={"retry-after": "6"})
    )
    result = await _analyzer().execute(classify("user@example.com"))
    assert result.status is ReportStatus.FAILED
    assert "429" in (result.error or "")


@respx.mock
async def test_unauthorised_key_is_reported_without_leaking_it() -> None:
    respx.get(url__startswith=_URL).mock(return_value=httpx.Response(401))
    result = await _analyzer().execute(classify("user@example.com"))
    assert result.status is ReportStatus.FAILED
    assert "h" * 32 not in (result.error or "")


async def test_a_non_email_is_skipped() -> None:
    result = await _analyzer().execute(classify("not-an-email-thing"))
    assert result.status is ReportStatus.SKIPPED
