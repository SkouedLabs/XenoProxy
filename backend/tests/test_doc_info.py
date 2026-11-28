"""Doc_Info: verdict rules on stubbed parser output, plus real parsing of non-macro input."""

from __future__ import annotations

import io
import zipfile

import pytest

from app.models.job import ObservableType, ReportStatus, Verdict
from app.plugins.analyzer import doc_info
from app.plugins.analyzer.doc_info import DocInfoAnalyzer, MacroReport
from app.plugins.base.plugin import SampleAccess
from app.services.observables import Observable

_SHA = "b" * 64


def _analyzer(payload: bytes | None, **options: object) -> DocInfoAnalyzer:
    sample = (
        None
        if payload is None
        else SampleAccess(sha256=_SHA, file_name="invoice.docm", read_local=lambda: payload)
    )
    return DocInfoAnalyzer(options=dict(options), sample=sample)


def _observable() -> Observable:
    return Observable(value=_SHA, type=ObservableType.FILE)


def _stub(monkeypatch: pytest.MonkeyPatch, report: MacroReport) -> None:
    monkeypatch.setattr(doc_info, "scan_document", lambda _payload: report)


def _docx_without_macros() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr("word/document.xml", "<w:document/>")
    return buffer.getvalue()


async def test_auto_run_with_several_suspicious_calls_is_malicious(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub(
        monkeypatch,
        MacroReport(
            kind="OpenXML",
            modules=1,
            autoexec=["Document_Open"],
            suspicious=["Shell", "CreateObject", "URLDownloadToFile"],
        ),
    )
    result = await _analyzer(b"x").execute(_observable())
    summary = result.summary.as_dict()
    assert result.status is ReportStatus.SUCCESS
    assert summary["verdict"] == Verdict.MALICIOUS.value
    assert "auto-exec" in summary["tags"]


async def test_auto_run_alone_is_suspicious_not_malicious(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub(monkeypatch, MacroReport(kind="OLE", modules=1, autoexec=["AutoOpen"]))
    result = await _analyzer(b"x").execute(_observable())
    assert result.summary.as_dict()["verdict"] == Verdict.SUSPICIOUS.value


async def test_one_suspicious_call_is_suspicious_not_malicious(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub(monkeypatch, MacroReport(kind="OLE", modules=1, suspicious=["Open"]))
    result = await _analyzer(b"x").execute(_observable())
    assert result.summary.as_dict()["verdict"] == Verdict.SUSPICIOUS.value


async def test_macros_without_indicators_are_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub(monkeypatch, MacroReport(kind="OLE", modules=2))
    result = await _analyzer(b"x").execute(_observable())
    assert result.status is ReportStatus.SUCCESS
    assert result.summary.as_dict()["verdict"] == Verdict.UNKNOWN.value


async def test_threshold_option_is_respected(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub(
        monkeypatch,
        MacroReport(kind="OLE", modules=1, autoexec=["AutoOpen"], suspicious=["Shell"]),
    )
    result = await _analyzer(b"x", malicious_keywords=1).execute(_observable())
    assert result.summary.as_dict()["verdict"] == Verdict.MALICIOUS.value


async def test_a_document_with_no_macros_is_unknown_not_clean() -> None:
    result = await _analyzer(_docx_without_macros()).execute(_observable())
    assert result.status is ReportStatus.SUCCESS
    summary = result.summary.as_dict()
    assert summary["verdict"] == Verdict.UNKNOWN.value
    assert result.raw_output["document_kind"] == "OpenXML"


async def test_a_file_that_is_not_an_office_document_is_skipped() -> None:
    result = await _analyzer(b"plain text, not a document " * 20).execute(_observable())
    assert result.status is ReportStatus.SKIPPED


async def test_a_parser_error_is_a_failure_not_a_verdict(monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(_payload: bytes) -> MacroReport:
        raise ValueError("malformed stream")

    monkeypatch.setattr(doc_info, "scan_document", broken)
    result = await _analyzer(b"x").execute(_observable())
    assert result.status is ReportStatus.FAILED
    assert "ValueError" in (result.error or "")


async def test_an_oversized_document_is_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(doc_info, "MAX_DOCUMENT_BYTES", 10)
    result = await _analyzer(b"x" * 11).execute(_observable())
    assert result.status is ReportStatus.SKIPPED


async def test_without_a_file_the_analyzer_skips() -> None:
    result = await _analyzer(None).execute(_observable())
    assert result.status is ReportStatus.SKIPPED
