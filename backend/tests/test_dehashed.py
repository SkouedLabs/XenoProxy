"""Dehashed leak lookup, checked against mocks only. Passwords must never reach the output."""

from __future__ import annotations

import json

import httpx
import respx

from app.models.job import ReportStatus, Verdict
from app.plugins.analyzer.dehashed import DehashedAnalyzer
from app.services.observables import classify

_URL = "https://api.dehashed.com/v2/search"
_KEY = "dehashed-test-key-0123456789"
_PASSWORD = "Winter2019!plaintext"


def _analyzer() -> DehashedAnalyzer:
    return DehashedAnalyzer(secrets={"api_key": _KEY})


@respx.mock
async def test_plaintext_password_hit_is_suspicious_and_password_is_not_kept() -> None:
    route = respx.post(_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "total": 2,
                "entries": [
                    {
                        "email": ["user@example.com"],
                        "database_name": "ExampleForum",
                        "password": [_PASSWORD],
                    },
                    {
                        "email": ["user@example.com"],
                        "database_name": "OtherSite",
                        "hashed_password": ["5f4dcc3b5aa765d61d8327deb882cf99"],
                    },
                ],
            },
        )
    )
    result = await _analyzer().execute(classify("user@example.com"))
    assert result.status is ReportStatus.SUCCESS
    summary = result.summary.as_dict()
    assert summary["verdict"] == Verdict.SUSPICIOUS.value
    assert "plaintext-password" in summary["tags"]
    assert summary["extra"]["databases"] == ["ExampleForum", "OtherSite"]
    assert summary["extra"]["record_count"] == 2
    # The password value is read to know it was exposed, and never stored.
    stored = json.dumps({"raw": result.raw_output, "summary": summary})
    assert _PASSWORD not in stored
    assert "5f4dcc3b5aa765d61d8327deb882cf99" not in stored
    # The query and key went out as expected.
    sent = json.loads(route.calls.last.request.content)
    assert sent["query"] == 'email:"user@example.com"'
    assert route.calls.last.request.headers["Dehashed-Api-Key"] == _KEY


@respx.mock
async def test_hit_without_credentials_is_still_suspicious_never_malicious() -> None:
    respx.post(_URL).mock(
        return_value=httpx.Response(
            200,
            json={"total": 1, "entries": [{"database_name": "Shop", "name": ["A"]}]},
        )
    )
    result = await _analyzer().execute(classify("user@example.com"))
    summary = result.summary.as_dict()
    assert summary["verdict"] == Verdict.SUSPICIOUS.value
    assert "plaintext-password" not in summary["tags"]


@respx.mock
async def test_no_record_is_not_found_not_clean() -> None:
    respx.post(_URL).mock(return_value=httpx.Response(200, json={"total": 0, "entries": []}))
    result = await _analyzer().execute(classify("nobody@example.com"))
    assert result.status is ReportStatus.SUCCESS
    assert result.raw_output == {"found": False}


@respx.mock
async def test_out_of_credits_is_a_failure_with_a_clear_message() -> None:
    respx.post(_URL).mock(return_value=httpx.Response(402, json={"error": "no credits"}))
    result = await _analyzer().execute(classify("user@example.com"))
    assert result.status is ReportStatus.FAILED
    assert "credits" in (result.error or "")


@respx.mock
async def test_rejected_key_is_reported_without_leaking_it() -> None:
    respx.post(_URL).mock(return_value=httpx.Response(401, json={"error": "bad key"}))
    result = await _analyzer().execute(classify("user@example.com"))
    assert result.status is ReportStatus.FAILED
    assert _KEY not in (result.error or "")


@respx.mock
async def test_unreadable_body_is_a_failure() -> None:
    respx.post(_URL).mock(return_value=httpx.Response(200, json=["not", "an", "object"]))
    result = await _analyzer().execute(classify("user@example.com"))
    assert result.status is ReportStatus.FAILED


async def test_a_value_that_is_not_an_email_is_skipped() -> None:
    result = await _analyzer().execute(classify("example.com"))
    assert result.status is ReportStatus.SKIPPED


async def test_an_address_with_a_quote_never_reaches_the_query() -> None:
    result = await _analyzer().execute(classify('a"b@example.com'))
    assert result.status is ReportStatus.SKIPPED
