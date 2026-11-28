"""Intezer, Triage and CAPE: verdict mapping, quota handling and key hygiene, on mocks only."""

from __future__ import annotations

import httpx
import respx

from app.models.job import ReportStatus, Verdict
from app.plugins.analyzer.cape import CapeSandboxAnalyzer
from app.plugins.analyzer.intezer import IntezerAnalyzer
from app.plugins.analyzer.triage import TriageAnalyzer
from app.services.observables import classify

_SHA = "e" * 64
_KEY = "sandbox-test-key-0123456789"
_TOKEN = "intezer-token-0123456789"
_CAPE_HOST = "https://192.0.2.10"


def _observable():
    return classify(_SHA)


def _md5_observable():
    return classify("d41d8cd98f00b204e9800998ecf8427e")


# -- Intezer -----------------------------------------------------------------


@respx.mock
async def test_intezer_malicious_family_match_is_malicious_and_uses_bearer_token() -> None:
    respx.post("https://analyze.intezer.com/api/v2-0/get-access-token").mock(
        return_value=httpx.Response(200, json={"result": _TOKEN})
    )
    files = respx.get(f"https://analyze.intezer.com/api/v2-0/files/{_SHA}").mock(
        return_value=httpx.Response(
            200,
            json={
                "verdict": "malicious",
                "sub_verdict": "known_malicious",
                "family_name": "Emotet",
                "analysis_id": "abc123",
            },
        )
    )
    result = await IntezerAnalyzer(secrets={"api_key": _KEY}).execute(_observable())
    assert result.status is ReportStatus.SUCCESS
    summary = result.summary.as_dict()
    assert summary["verdict"] == Verdict.MALICIOUS.value
    assert "Emotet" in summary["tags"]
    assert files.calls.last.request.headers["Authorization"] == f"Bearer {_TOKEN}"


@respx.mock
async def test_intezer_trusted_code_is_clean() -> None:
    respx.post("https://analyze.intezer.com/api/v2-0/get-access-token").mock(
        return_value=httpx.Response(200, json={"result": _TOKEN})
    )
    respx.get(url__startswith="https://analyze.intezer.com/api/v2-0/files/").mock(
        return_value=httpx.Response(200, json={"verdict": "trusted"})
    )
    result = await IntezerAnalyzer(secrets={"api_key": _KEY}).execute(_observable())
    assert result.summary.as_dict()["verdict"] == Verdict.CLEAN.value


@respx.mock
async def test_intezer_unknown_hash_is_not_found_not_clean() -> None:
    respx.post("https://analyze.intezer.com/api/v2-0/get-access-token").mock(
        return_value=httpx.Response(200, json={"result": _TOKEN})
    )
    respx.get(url__startswith="https://analyze.intezer.com/api/v2-0/files/").mock(
        return_value=httpx.Response(404, json={"error": "not found"})
    )
    result = await IntezerAnalyzer(secrets={"api_key": _KEY}).execute(_observable())
    assert result.status is ReportStatus.SUCCESS
    assert result.raw_output == {"found": False}


@respx.mock
async def test_intezer_rejected_key_is_reported_without_leaking_it() -> None:
    respx.post("https://analyze.intezer.com/api/v2-0/get-access-token").mock(
        return_value=httpx.Response(401, json={"error": "bad key"})
    )
    result = await IntezerAnalyzer(secrets={"api_key": _KEY}).execute(_observable())
    assert result.status is ReportStatus.FAILED
    assert _KEY not in (result.error or "")


@respx.mock
async def test_intezer_quota_on_analysis_is_a_failure() -> None:
    respx.post("https://analyze.intezer.com/api/v2-0/get-access-token").mock(
        return_value=httpx.Response(200, json={"result": _TOKEN})
    )
    respx.get(url__startswith="https://analyze.intezer.com/api/v2-0/files/").mock(
        return_value=httpx.Response(429, json={"error": "slow down"})
    )
    result = await IntezerAnalyzer(secrets={"api_key": _KEY}).execute(_observable())
    assert result.status is ReportStatus.FAILED
    assert "429" in (result.error or "")


async def test_intezer_skips_a_non_sha256_hash() -> None:
    result = await IntezerAnalyzer(secrets={"api_key": _KEY}).execute(_md5_observable())
    assert result.status is ReportStatus.SKIPPED


# -- Triage ------------------------------------------------------------------


@respx.mock
async def test_triage_high_score_is_malicious_on_the_hundred_scale() -> None:
    respx.get("https://tria.ge/api/v0/search").mock(
        return_value=httpx.Response(200, json={"data": [{"id": "260101-aaa", "score": 9}]})
    )
    respx.get("https://tria.ge/api/v0/samples/260101-aaa/summary").mock(
        return_value=httpx.Response(
            200,
            json={
                "score": 9,
                "family": ["lumma"],
                "signatures": [{"name": "stealer_behaviour", "score": 9}],
            },
        )
    )
    result = await TriageAnalyzer(secrets={"api_key": _KEY}).execute(_observable())
    summary = result.summary.as_dict()
    assert summary["verdict"] == Verdict.MALICIOUS.value
    assert summary["score"] == 90
    assert "lumma" in summary["tags"]
    assert summary["extra"]["sample_id"] == "260101-aaa"


@respx.mock
async def test_triage_middle_score_is_suspicious() -> None:
    respx.get("https://tria.ge/api/v0/search").mock(
        return_value=httpx.Response(200, json={"data": [{"id": "x1", "score": 5}]})
    )
    respx.get("https://tria.ge/api/v0/samples/x1/summary").mock(
        return_value=httpx.Response(200, json={"score": 5, "signatures": []})
    )
    result = await TriageAnalyzer(secrets={"api_key": _KEY}).execute(_observable())
    assert result.summary.as_dict()["verdict"] == Verdict.SUSPICIOUS.value


@respx.mock
async def test_triage_quiet_run_is_unknown_not_clean() -> None:
    respx.get("https://tria.ge/api/v0/search").mock(
        return_value=httpx.Response(200, json={"data": [{"id": "x2", "score": 0}]})
    )
    respx.get("https://tria.ge/api/v0/samples/x2/summary").mock(
        return_value=httpx.Response(200, json={"score": 0, "signatures": []})
    )
    result = await TriageAnalyzer(secrets={"api_key": _KEY}).execute(_observable())
    assert result.summary.as_dict()["verdict"] == Verdict.UNKNOWN.value


@respx.mock
async def test_triage_no_run_is_not_found() -> None:
    respx.get("https://tria.ge/api/v0/search").mock(
        return_value=httpx.Response(200, json={"data": []})
    )
    result = await TriageAnalyzer(secrets={"api_key": _KEY}).execute(_observable())
    assert result.status is ReportStatus.SUCCESS
    assert result.raw_output == {"found": False}


@respx.mock
async def test_triage_rejected_token_is_reported_without_leaking_it() -> None:
    respx.get("https://tria.ge/api/v0/search").mock(
        return_value=httpx.Response(403, json={"error": "forbidden"})
    )
    result = await TriageAnalyzer(secrets={"api_key": _KEY}).execute(_observable())
    assert result.status is ReportStatus.FAILED
    assert _KEY not in (result.error or "")


# -- CAPE --------------------------------------------------------------------


@respx.mock
async def test_cape_reported_run_maps_malscore_to_verdict() -> None:
    respx.get(f"{_CAPE_HOST}/apiv2/tasks/search/sha256/{_SHA}/").mock(
        return_value=httpx.Response(200, json={"error": False, "data": [7, 12]})
    )
    view = respx.get(f"{_CAPE_HOST}/apiv2/tasks/view/12/").mock(
        return_value=httpx.Response(
            200, json={"error": False, "data": {"status": "reported", "malscore": 8.5}}
        )
    )
    result = await CapeSandboxAnalyzer(
        options={"base_url": _CAPE_HOST}, secrets={"api_token": _KEY}
    ).execute(_observable())
    summary = result.summary.as_dict()
    assert result.status is ReportStatus.SUCCESS
    assert summary["verdict"] == Verdict.MALICIOUS.value
    assert summary["extra"]["task_id"] == 12
    assert view.calls.last.request.headers["Authorization"] == f"Token {_KEY}"


@respx.mock
async def test_cape_run_still_queued_has_no_verdict() -> None:
    respx.get(f"{_CAPE_HOST}/apiv2/tasks/search/sha256/{_SHA}/").mock(
        return_value=httpx.Response(200, json={"error": False, "data": [3]})
    )
    respx.get(f"{_CAPE_HOST}/apiv2/tasks/view/3/").mock(
        return_value=httpx.Response(200, json={"error": False, "data": {"status": "running"}})
    )
    result = await CapeSandboxAnalyzer(options={"base_url": _CAPE_HOST}).execute(_observable())
    summary = result.summary.as_dict()
    assert summary["verdict"] == Verdict.UNKNOWN.value
    assert summary["score"] is None


@respx.mock
async def test_cape_quiet_reported_run_is_unknown_not_clean() -> None:
    respx.get(f"{_CAPE_HOST}/apiv2/tasks/search/sha256/{_SHA}/").mock(
        return_value=httpx.Response(200, json={"error": False, "data": [4]})
    )
    respx.get(f"{_CAPE_HOST}/apiv2/tasks/view/4/").mock(
        return_value=httpx.Response(
            200, json={"error": False, "data": {"status": "reported", "malscore": 0.0}}
        )
    )
    result = await CapeSandboxAnalyzer(options={"base_url": _CAPE_HOST}).execute(_observable())
    assert result.summary.as_dict()["verdict"] == Verdict.UNKNOWN.value


@respx.mock
async def test_cape_no_run_is_not_found() -> None:
    respx.get(f"{_CAPE_HOST}/apiv2/tasks/search/sha256/{_SHA}/").mock(
        return_value=httpx.Response(200, json={"error": False, "data": []})
    )
    result = await CapeSandboxAnalyzer(options={"base_url": _CAPE_HOST}).execute(_observable())
    assert result.raw_output == {"found": False}


async def test_cape_without_a_base_url_fails_with_a_clear_message() -> None:
    result = await CapeSandboxAnalyzer().execute(_observable())
    assert result.status is ReportStatus.FAILED
    assert "base URL" in (result.error or "")


async def test_cape_skips_a_non_sha256_hash() -> None:
    result = await CapeSandboxAnalyzer(options={"base_url": _CAPE_HOST}).execute(_md5_observable())
    assert result.status is ReportStatus.SKIPPED
