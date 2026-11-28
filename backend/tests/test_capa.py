"""Capa-style capabilities from a PE import table, on synthetic fixtures only.

The PE is built byte by byte with one .idata section and a real import directory,
so the reader is checked against the layout it walks, not against a binary.
"""

from __future__ import annotations

import struct

from app.models.job import ObservableType, ReportStatus, Verdict
from app.plugins.analyzer.capa_info import CapaAnalyzer, matched_capabilities, read_imports
from app.plugins.base.plugin import SampleAccess
from app.services.observables import Observable

_SHA = "a" * 64
_BASE_RVA = 0x2000
_RAW = 0x400


def _pe_with_imports(imports: dict[str, list[str]], *, ordinal: bool = False) -> bytes:
    """A PE32+ with one .idata section holding the import directory for `imports`."""
    blob = bytearray()

    def add(data: bytes) -> int:
        position = len(blob)
        blob.extend(data)
        return _BASE_RVA + position

    def align() -> None:
        while len(blob) % 8:
            blob.append(0)

    descriptors_rva = add(b"\x00" * (20 * (len(imports) + 1)))
    for index, (dll, functions) in enumerate(imports.items()):
        name_rva = add(dll.encode() + b"\x00")
        align()
        entries: list[int] = []
        for function in functions:
            hint = add(b"\x00\x00" + function.encode() + b"\x00")
            align()
            entries.append(hint)
        if ordinal:
            entries.append(1 << 63 | 5)
        thunk_rva = add(b"".join(struct.pack("<Q", value) for value in entries) + b"\x00" * 8)
        align()
        struct.pack_into(
            "<IIIII",
            blob,
            descriptors_rva - _BASE_RVA + index * 20,
            thunk_rva,
            0,
            0,
            name_rva,
            thunk_rva,
        )

    header = bytearray(_RAW)
    header[0:2] = b"MZ"
    struct.pack_into("<I", header, 0x3C, 0x40)
    header[0x40:0x44] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", header, 0x44, 0x8664, 1, 0, 0, 0, 0xF0, 0x22)
    opt = 0x58
    struct.pack_into("<H", header, opt, 0x20B)
    # Data directory 1 (import table) sits at opt + 112 + 8.
    struct.pack_into("<II", header, opt + 112 + 8, descriptors_rva, 20 * (len(imports) + 1))
    section = opt + 0xF0
    struct.pack_into(
        "<8sIIIIIIHHI",
        header,
        section,
        b".idata",
        len(blob),
        _BASE_RVA,
        len(blob),
        _RAW,
        0,
        0,
        0,
        0,
        0x40000040,
    )
    return bytes(header) + bytes(blob)


def _observable() -> Observable:
    return Observable(value=_SHA, type=ObservableType.FILE)


def _analyzer(payload: bytes | None) -> CapaAnalyzer:
    sample = (
        None
        if payload is None
        else SampleAccess(sha256=_SHA, file_name="s.exe", read_local=lambda: payload)
    )
    return CapaAnalyzer(sample=sample)


def test_the_import_table_is_read_per_dll() -> None:
    payload = _pe_with_imports({"KERNEL32.dll": ["CreateThread", "ExitProcess"]})
    assert read_imports(payload) == {"kernel32.dll": ["CreateThread", "ExitProcess"]}


def test_ordinal_imports_have_no_name_and_are_skipped() -> None:
    payload = _pe_with_imports({"ws2_32.dll": ["connect"]}, ordinal=True)
    assert read_imports(payload) == {"ws2_32.dll": ["connect"]}


def test_a_truncated_or_bogus_import_table_is_not_read() -> None:
    assert read_imports(b"MZ" + b"\x00" * 20) is None
    assert read_imports(b"not a pe at all") is None


def test_injection_apis_together_are_a_capability() -> None:
    names = {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThreadA"}
    assert [cap.name for cap in matched_capabilities(names)] == ["code-injection"]


def test_one_injection_api_alone_is_not_a_capability() -> None:
    assert matched_capabilities({"WriteProcessMemory"}) == []


def test_ansi_and_wide_spellings_both_match() -> None:
    names = {"URLDownloadToFileW", "ShellExecuteA"}
    assert [cap.name for cap in matched_capabilities(names)] == ["download-and-execute"]


async def test_code_injection_is_suspicious_never_malicious() -> None:
    payload = _pe_with_imports(
        {"kernel32.dll": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]}
    )
    result = await _analyzer(payload).execute(_observable())
    summary = result.summary.as_dict()
    assert summary["verdict"] == Verdict.SUSPICIOUS.value
    assert "code-injection" in summary["tags"]


async def test_an_ordinary_program_is_unknown_not_clean() -> None:
    payload = _pe_with_imports({"kernel32.dll": ["ExitProcess", "GetModuleHandleA"]})
    result = await _analyzer(payload).execute(_observable())
    summary = result.summary.as_dict()
    assert summary["verdict"] == Verdict.UNKNOWN.value
    assert summary["score"] is None


async def test_a_low_severity_capability_is_a_tag_not_a_verdict() -> None:
    payload = _pe_with_imports({"advapi32.dll": ["RegSetValueExW", "RegOpenKeyExW"]})
    result = await _analyzer(payload).execute(_observable())
    summary = result.summary.as_dict()
    assert "persistence-registry" in summary["tags"]
    assert summary["verdict"] == Verdict.UNKNOWN.value


async def test_a_file_that_is_not_a_pe_is_skipped() -> None:
    result = await _analyzer(b"%PDF-1.7\n").execute(_observable())
    assert result.status is ReportStatus.SKIPPED


async def test_a_job_without_a_file_is_skipped() -> None:
    result = await _analyzer(None).execute(_observable())
    assert result.status is ReportStatus.SKIPPED
