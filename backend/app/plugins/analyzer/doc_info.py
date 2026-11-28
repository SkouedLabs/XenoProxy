"""Doc_Info: macro analysis of an Office document, with oletools, on this instance.

Like `yara_local`, nothing leaves the instance: the parser reads the submitted
bytes in memory and nothing is opened or executed. A macro is code that runs
when a user opens the document, so the question is what the code does, and the
indicators oletools reports answer that:

- AutoExec: runs on open or close (`AutoOpen`, `Document_Open`, ...).
- Suspicious: an API a dropper uses (`Shell`, `CreateObject`, `URLDownloadToFile`).
- IOC: a URL, an IP address or an executable name inside the code.

A document with macros but none of those is Unknown: having macros is common in
legitimate spreadsheets, so it is not evidence against the file. An AutoExec
macro that calls several suspicious APIs is Malicious. A single indicator is
Suspicious at most, because one keyword on its own misfires.

Contract note: exercised against stubbed parser output and non-Office input
only. It has not been run against a corpus of real malicious documents.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, ClassVar

from app.models.job import ObservableType, Tlp, Verdict
from app.plugins.base.analyzer import BaseAnalyzer
from app.plugins.base.plugin import PluginResult, PluginSummary, ProviderInfo
from app.plugins.base.registry import register
from app.services.observables import Observable

# Office files are a few MiB in practice; the parser holds the whole thing in
# memory, so the cap bounds that.
MAX_DOCUMENT_BYTES = 25 * 1024 * 1024
_MAX_REPORTED = 50
_NOT_OFFICE = {"Text"}


@dataclass
class MacroReport:
    """What oletools found, reduced to the parts a verdict needs."""

    kind: str
    modules: int = 0
    autoexec: list[str] = field(default_factory=list)
    suspicious: list[str] = field(default_factory=list)
    iocs: list[str] = field(default_factory=list)
    encoded: list[str] = field(default_factory=list)
    rows: list[dict[str, str]] = field(default_factory=list)


def scan_document(payload: bytes) -> MacroReport:
    """Parse and analyse one document. Blocking: call it off the event loop."""
    from oletools import olevba

    parser = olevba.VBA_Parser("sample", data=payload)
    try:
        kind = str(parser.type)
        if kind in _NOT_OFFICE:
            return MacroReport(kind="not-office")
        if not (parser.detect_vba_macros() or parser.detect_xlm_macros()):
            return MacroReport(kind=kind)

        modules = sum(1 for _ in parser.extract_all_macros())
        report = MacroReport(kind=kind, modules=modules)
        for row_type, keyword, description in parser.analyze_macros():
            report.rows.append(
                {
                    "type": str(row_type),
                    "keyword": str(keyword)[:100],
                    "description": str(description)[:200],
                }
            )
            keyword_text = str(keyword)
            if row_type == "AutoExec":
                report.autoexec.append(keyword_text)
            elif row_type == "Suspicious":
                report.suspicious.append(keyword_text)
            elif row_type == "IOC":
                report.iocs.append(keyword_text)
            elif row_type in {"Base64 String", "Hex String", "Dridex String"}:
                report.encoded.append(keyword_text)
        report.autoexec = sorted(set(report.autoexec))
        report.suspicious = sorted(set(report.suspicious))
        report.iocs = sorted(set(report.iocs))
        report.encoded = sorted(set(report.encoded))
        return report
    finally:
        parser.close()


def _verdict(report: MacroReport, threshold: int) -> Verdict:
    if report.autoexec and len(report.suspicious) >= threshold:
        return Verdict.MALICIOUS
    if report.autoexec or report.suspicious or report.iocs:
        return Verdict.SUSPICIOUS
    return Verdict.UNKNOWN


@register
class DocInfoAnalyzer(BaseAnalyzer):
    """Macros in an Office document: what runs on open, and what the code calls."""

    name = "doc_info"
    label = "Doc_Info (oletools)"
    description = "Macros in a submitted Office document, and what they do, analysed locally."
    supported_types: ClassVar[tuple[ObservableType, ...]] = (ObservableType.FILE,)
    options_schema: ClassVar[dict[str, Any]] = {
        "malicious_keywords": {
            "type": "integer",
            "default": 3,
            "label": "Suspicious API calls, with an auto-run macro, that make it Malicious",
        },
    }
    provider = ProviderInfo(
        name="Local oletools",
        url="https://github.com/decalage2/oletools",
        api_base_url="(none: runs locally)",
        credential_url="",
        free_tier="Free; no account.",
        rate_limit="None; bounded by the analyzer timeout.",
        notes="The document is never sent anywhere. The macros are read, never run.",
    )
    max_tlp = Tlp.RED
    documentation_url = "https://www.decalage.info/vba_tools"
    free_tier = True
    default_timeout = 90
    default_cache_ttl = 3600
    maturity = "alpha"

    async def run(self, observable: Observable) -> PluginResult:
        payload = self.local_sample_bytes()
        if payload is None:
            return self.skipped("Doc_Info reads a submitted document; no file came with this job.")
        if len(payload) > MAX_DOCUMENT_BYTES:
            return self.skipped(
                f"The document is larger than {MAX_DOCUMENT_BYTES // (1024 * 1024)} MiB."
            )

        try:
            report = await asyncio.wait_for(
                asyncio.to_thread(scan_document, payload), timeout=max(1, self.timeout - 5)
            )
        except TimeoutError:
            return self.failed("Doc_Info did not finish analysing the document in time.")
        except Exception as exc:
            # The parser is third-party code on untrusted input: a malformed file
            # may raise almost anything, and that is a fact about the file, not a crash.
            return self.failed(f"The document could not be parsed ({type(exc).__name__}).")

        if report.kind == "not-office":
            return self.skipped("Doc_Info analyses Office documents; this file is not one.")

        threshold = int(self.option("malicious_keywords", 3))
        verdict = _verdict(report, threshold)
        tags: list[str] = []
        if report.modules:
            tags.append("macros")
        if report.autoexec:
            tags.append("auto-exec")
        if report.suspicious:
            tags.append("suspicious-api")
        if report.iocs:
            tags.append("ioc")
        if report.encoded:
            tags.append("encoded-strings")

        if report.modules == 0:
            headline = "No macros in this document."
        else:
            headline = (
                f"{report.modules} macro module(s); {len(report.autoexec)} auto-run, "
                f"{len(report.suspicious)} suspicious API call(s), {len(report.iocs)} indicator(s)."
            )
        summary = PluginSummary(
            verdict=verdict,
            score=min(100, len(report.autoexec) * 30 + len(report.suspicious) * 10),
            tags=tags,
            headline=headline,
            extra={
                "document_kind": report.kind,
                "macro_modules": report.modules,
                "autoexec": report.autoexec[:_MAX_REPORTED],
                "suspicious": report.suspicious[:_MAX_REPORTED],
                "iocs": report.iocs[:_MAX_REPORTED],
            },
        )
        return self.ok(
            {"document_kind": report.kind, "indicators": report.rows[:_MAX_REPORTED]},
            summary,
        )
