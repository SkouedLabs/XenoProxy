"""Strings_Info: extraction and verdicts, on synthetic byte fixtures (no network, no mocks)."""

from __future__ import annotations

import base64

from app.models.job import ObservableType, ReportStatus, Verdict
from app.plugins.analyzer.strings_info import StringsInfoAnalyzer, extract_strings
from app.plugins.base.plugin import SampleAccess
from app.services.observables import Observable

_SHA = "c" * 64


def _analyzer(payload: bytes | None, **options: object) -> StringsInfoAnalyzer:
    sample = (
        None
        if payload is None
        else SampleAccess(sha256=_SHA, file_name="s.exe", read_local=lambda: payload)
    )
    return StringsInfoAnalyzer(options=dict(options), sample=sample)


def _observable() -> Observable:
    return Observable(value=_SHA, type=ObservableType.FILE)


def _utf16(text: str) -> bytes:
    return text.encode("utf-16-le")


def test_ascii_and_utf16_runs_are_both_extracted() -> None:
    payload = b"\x00\x01MZ\x90VirtualAllocEx\x00\x00\x00" + _utf16("CreateRemoteThread") + b"\xff"
    found = extract_strings(payload, min_length=6)
    assert "VirtualAllocEx" in found
    assert "CreateRemoteThread" in found


def test_short_runs_are_dropped_by_min_length() -> None:
    assert extract_strings(b"\x00abcd\x00longer_run\x00", min_length=6) == ["longer_run"]
    assert extract_strings(b"\x00abcd\x00longer_run\x00", min_length=4) == ["longer_run", "abcd"]


async def test_two_injection_apis_are_malicious() -> None:
    payload = b"\x00VirtualAllocEx\x00\x00WriteProcessMemory\x00\x00CreateRemoteThread\x00"
    result = await _analyzer(payload).execute(_observable())
    summary = result.summary.as_dict()
    assert result.status is ReportStatus.SUCCESS
    assert summary["verdict"] == Verdict.MALICIOUS.value
    assert "injection-api" in summary["tags"]


async def test_one_download_api_is_suspicious_not_malicious() -> None:
    result = await _analyzer(b"\x00URLDownloadToFileW\x00").execute(_observable())
    assert result.summary.as_dict()["verdict"] == Verdict.SUSPICIOUS.value


async def test_one_injection_api_alone_is_suspicious() -> None:
    result = await _analyzer(b"\x00VirtualAllocEx\x00").execute(_observable())
    assert result.summary.as_dict()["verdict"] == Verdict.SUSPICIOUS.value


async def test_an_encoded_powershell_command_is_a_dropper_indicator() -> None:
    result = await _analyzer(b"\x00powershell.exe -enc SQBFAFgA\x00").execute(_observable())
    assert result.summary.as_dict()["verdict"] == Verdict.SUSPICIOUS.value


async def test_a_base64_command_is_decoded_and_checked() -> None:
    hidden = base64.b64encode(b"URLDownloadToFileA http://203.0.113.7/p.exe").decode()
    payload = b"\x00" + hidden.encode() + b"\x00"
    result = await _analyzer(payload).execute(_observable())
    assert result.raw_output["decoded_base64"]
    assert result.summary.as_dict()["verdict"] == Verdict.SUSPICIOUS.value


async def test_urls_and_ips_alone_do_not_raise_the_verdict() -> None:
    payload = b"\x00https://updates.example.org/check 198.51.100.4\x00"
    result = await _analyzer(payload).execute(_observable())
    summary = result.summary.as_dict()
    assert summary["verdict"] == Verdict.UNKNOWN.value
    assert "url" in summary["tags"]
    assert "ip" in summary["tags"]


async def test_no_indicator_is_unknown_not_clean() -> None:
    result = await _analyzer(b"just a plain readable sentence here").execute(_observable())
    assert result.status is ReportStatus.SUCCESS
    assert result.summary.as_dict()["verdict"] == Verdict.UNKNOWN.value


async def test_without_a_file_the_analyzer_skips() -> None:
    result = await _analyzer(None).execute(_observable())
    assert result.status is ReportStatus.SKIPPED
