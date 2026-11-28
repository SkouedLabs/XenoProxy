"""YARAify and EmailRep, checked against mocks only."""

from __future__ import annotations

import httpx
import respx

from app.models.job import ReportStatus, Verdict
from app.plugins.analyzer.emailrep import EmailRepAnalyzer
from app.plugins.analyzer.yaraify import YaraifyAnalyzer
from app.services.observables import classify

_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
_YARA_URL = "https://yaraify-api.abuse.ch/api/v1/"
_EMAIL_URL = "https://emailrep.io/"


def _yara(*rules: str) -> dict:
    return {
        "query_status": "ok",
        "data": {"yara_rules": [{"rule_name": name} for name in rules]},
    }


def _yara_analyzer() -> YaraifyAnalyzer:
    return YaraifyAnalyzer(secrets={"auth_key": "k" * 16})


# -- YARAify -----------------------------------------------------------------


@respx.mock
async def test_yaraify_one_rule_is_suspicious() -> None:
    respx.post(_YARA_URL).mock(return_value=httpx.Response(200, json=_yara("Packed_UPX")))
    result = await _yara_analyzer().execute(classify(_SHA256))
    summary = result.summary.as_dict()
    assert result.status is ReportStatus.SUCCESS
    assert summary["verdict"] == Verdict.SUSPICIOUS.value
    assert "yara-match" in summary["tags"]


@respx.mock
async def test_yaraify_several_distinct_rules_are_malicious() -> None:
    respx.post(_YARA_URL).mock(return_value=httpx.Response(200, json=_yara("A", "B", "C", "A")))
    result = await _yara_analyzer().execute(classify(_SHA256))
    assert result.summary.as_dict()["verdict"] == Verdict.MALICIOUS.value


@respx.mock
async def test_yaraify_hash_not_found_is_unknown_not_clean() -> None:
    respx.post(_YARA_URL).mock(
        return_value=httpx.Response(200, json={"query_status": "hash_not_found"})
    )
    result = await _yara_analyzer().execute(classify(_SHA256))
    assert result.status is ReportStatus.SUCCESS
    assert result.summary.as_dict()["verdict"] == Verdict.UNKNOWN.value


@respx.mock
async def test_yaraify_sends_the_auth_key_and_the_hash() -> None:
    route = respx.post(_YARA_URL).mock(return_value=httpx.Response(200, json=_yara("A")))
    await _yara_analyzer().execute(classify(_SHA256))
    request = route.calls.last.request
    assert request.headers["Auth-Key"] == "k" * 16
    assert _SHA256.encode() in request.content


@respx.mock
async def test_yaraify_quota_is_reported_as_a_failure() -> None:
    respx.post(_YARA_URL).mock(return_value=httpx.Response(429))
    result = await _yara_analyzer().execute(classify(_SHA256))
    assert result.status is ReportStatus.FAILED
    assert "429" in (result.error or "")


@respx.mock
async def test_yaraify_unexpected_status_is_a_failure_not_a_verdict() -> None:
    respx.post(_YARA_URL).mock(
        return_value=httpx.Response(200, json={"query_status": "illegal_hash"})
    )
    result = await _yara_analyzer().execute(classify(_SHA256))
    assert result.status is ReportStatus.FAILED


async def test_yaraify_skips_a_value_that_is_not_a_hash() -> None:
    result = await _yara_analyzer().execute(classify("evil.example.com"))
    assert result.status is ReportStatus.SKIPPED


# -- EmailRep ----------------------------------------------------------------


def _email_body(**overrides: object) -> dict:
    details = {
        "blacklisted": False,
        "malicious_activity": False,
        "malicious_activity_recent": False,
        "credentials_leaked": False,
        "disposable": False,
    }
    details.update(overrides)
    return {
        "email": "user@example.com",
        "reputation": "high",
        "suspicious": False,
        "references": 12,
        "details": details,
    }


@respx.mock
async def test_emailrep_clean_reputation_is_clean() -> None:
    respx.get(url__startswith=_EMAIL_URL).mock(return_value=httpx.Response(200, json=_email_body()))
    result = await EmailRepAnalyzer().execute(classify("user@example.com"))
    assert result.status is ReportStatus.SUCCESS
    assert result.summary.as_dict()["verdict"] == Verdict.CLEAN.value


@respx.mock
async def test_emailrep_a_leaked_password_alone_does_not_raise_the_verdict() -> None:
    body = _email_body(credentials_leaked=True)
    respx.get(url__startswith=_EMAIL_URL).mock(return_value=httpx.Response(200, json=body))
    result = await EmailRepAnalyzer().execute(classify("user@example.com"))
    summary = result.summary.as_dict()
    assert summary["verdict"] == Verdict.CLEAN.value
    assert "credentials-leaked" in summary["tags"]


@respx.mock
async def test_emailrep_suspicious_flag_is_suspicious() -> None:
    body = _email_body(malicious_activity=True)
    body["suspicious"] = True
    body["reputation"] = "low"
    respx.get(url__startswith=_EMAIL_URL).mock(return_value=httpx.Response(200, json=body))
    result = await EmailRepAnalyzer().execute(classify("user@example.com"))
    assert result.summary.as_dict()["verdict"] == Verdict.SUSPICIOUS.value


@respx.mock
async def test_emailrep_blacklisted_and_recently_active_is_malicious() -> None:
    body = _email_body(blacklisted=True, malicious_activity=True, malicious_activity_recent=True)
    body["reputation"] = "low"
    respx.get(url__startswith=_EMAIL_URL).mock(return_value=httpx.Response(200, json=body))
    result = await EmailRepAnalyzer().execute(classify("user@example.com"))
    assert result.summary.as_dict()["verdict"] == Verdict.MALICIOUS.value


@respx.mock
async def test_emailrep_unknown_reputation_is_unknown_not_clean() -> None:
    body = _email_body()
    body["reputation"] = "none"
    respx.get(url__startswith=_EMAIL_URL).mock(return_value=httpx.Response(200, json=body))
    result = await EmailRepAnalyzer().execute(classify("user@example.com"))
    assert result.summary.as_dict()["verdict"] == Verdict.UNKNOWN.value


@respx.mock
async def test_emailrep_key_is_sent_only_when_configured() -> None:
    route = respx.get(url__startswith=_EMAIL_URL).mock(
        return_value=httpx.Response(200, json=_email_body())
    )
    await EmailRepAnalyzer(secrets={"api_key": "abc123"}).execute(classify("user@example.com"))
    assert route.calls.last.request.headers["Key"] == "abc123"
    await EmailRepAnalyzer().execute(classify("user@example.com"))
    assert "Key" not in route.calls.last.request.headers


@respx.mock
async def test_emailrep_quota_is_reported_as_a_failure() -> None:
    respx.get(url__startswith=_EMAIL_URL).mock(return_value=httpx.Response(429))
    result = await EmailRepAnalyzer().execute(classify("user@example.com"))
    assert result.status is ReportStatus.FAILED


async def test_emailrep_skips_a_generic_value_that_is_not_an_email() -> None:
    result = await EmailRepAnalyzer().execute(classify("not-an-email-thing"))
    assert result.status is ReportStatus.SKIPPED
