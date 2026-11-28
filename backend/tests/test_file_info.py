"""File_Info: format, structure and verdicts, on synthetic byte fixtures (no network, no mocks).

The PE fixtures are built byte by byte, so the parser is checked against the layout it reads
rather than against a real binary that could change under the test.
"""

from __future__ import annotations

import random
import struct

from app.models.job import ObservableType, ReportStatus, Verdict
from app.plugins.analyzer.file_info import (
    FileInfoAnalyzer,
    identify,
    parse_pdf,
    parse_pe,
    shannon_entropy,
)
from app.plugins.base.plugin import SampleAccess
from app.services.observables import Observable

_SHA = "f" * 64
_TEXT = b"A" * 4096
_RANDOM = random.Random(7).randbytes(8192)  # noqa: S311 - fixture entropy, not a secret


def _pe(sections: list[tuple[bytes, int, bytes]], stamp: int = 1_700_000_000) -> bytes:
    """A minimal PE: DOS header, PE signature, COFF header and a section table.

    Each section is (name, characteristics, raw data). Raw data is laid out from offset 0x400.
    """
    e_lfanew = 0x40
    opt_size = 0xF0
    table = e_lfanew + 4 + 20 + opt_size
    header = bytearray(table + 40 * len(sections))
    header[0:2] = b"MZ"
    struct.pack_into("<I", header, 0x3C, e_lfanew)
    header[e_lfanew : e_lfanew + 4] = b"PE\x00\x00"
    struct.pack_into(
        "<HHIIIHH", header, e_lfanew + 4, 0x8664, len(sections), stamp, 0, 0, opt_size, 0x22
    )
    body = bytearray()
    for index, (name, flags, data) in enumerate(sections):
        raw_ptr = 0x400 + len(body)
        struct.pack_into(
            "<8sIIIIIIHHI",
            header,
            table + index * 40,
            name.ljust(8, b"\x00"),
            len(data),
            0x1000,
            len(data),
            raw_ptr,
            0,
            0,
            0,
            0,
            flags,
        )
        body += data
    out = bytearray(0x400) + body
    out[: len(header)] = header
    return bytes(out)


_CODE = 0x20000000 | 0x40000000  # executable, readable
_RWX = 0x20000000 | 0x80000000 | 0x40000000  # executable and writable
_DATA = 0x40000000 | 0x80000000  # readable, writable


def _analyzer(payload: bytes | None) -> FileInfoAnalyzer:
    sample = (
        None
        if payload is None
        else SampleAccess(sha256=_SHA, file_name="s.bin", read_local=lambda: payload)
    )
    return FileInfoAnalyzer(sample=sample)


def _observable() -> Observable:
    return Observable(value=_SHA, type=ObservableType.FILE)


def test_format_is_read_from_the_bytes_not_from_a_name() -> None:
    assert identify(b"%PDF-1.7\n...") == "pdf"
    assert identify(b"\x89PNG\r\n\x1a\n....") == "png"
    assert identify(b"PK\x03\x04....") == "zip"
    assert identify(b"#!/bin/sh\necho") == "script"
    assert identify(b"just text") == "unknown"


def test_a_pe_header_is_parsed_with_its_sections_and_compile_time() -> None:
    pe = parse_pe(_pe([(b".text", _CODE, _TEXT), (b".data", _DATA, _TEXT)]))
    assert pe is not None
    assert pe["machine"] == "x64"
    assert pe["compiled_at"].startswith("2023-11-14")
    assert [s["name"] for s in pe["sections"]] == [".text", ".data"]


def test_a_zero_timestamp_is_reported_as_absent_not_as_1970() -> None:
    pe = parse_pe(_pe([(b".text", _CODE, _TEXT)], stamp=0))
    assert pe is not None
    assert pe["compiled_at"] is None


def test_a_truncated_file_is_not_a_pe() -> None:
    assert parse_pe(b"MZ" + b"\x00" * 10) is None


async def test_an_ordinary_binary_is_unknown_not_clean() -> None:
    result = await _analyzer(_pe([(b".text", _CODE, _TEXT)])).execute(_observable())
    summary = result.summary.as_dict()
    assert result.status is ReportStatus.SUCCESS
    assert summary["verdict"] == Verdict.UNKNOWN.value
    assert summary["score"] is None
    assert result.raw_output["pe"]["machine"] == "x64"


async def test_a_packer_section_name_is_suspicious_never_malicious() -> None:
    payload = _pe([(b"UPX0", _CODE, _TEXT), (b"UPX1", _CODE, _TEXT)])
    result = await _analyzer(payload).execute(_observable())
    summary = result.summary.as_dict()
    assert summary["verdict"] == Verdict.SUSPICIOUS.value
    assert "packer-section" in summary["tags"]


async def test_a_writable_executable_section_is_suspicious() -> None:
    result = await _analyzer(_pe([(b".text", _RWX, _TEXT)])).execute(_observable())
    assert result.summary.as_dict()["verdict"] == Verdict.SUSPICIOUS.value
    assert "writable-code" in result.summary.as_dict()["tags"]


async def test_high_entropy_code_is_flagged_as_packed() -> None:
    payload = _pe([(b".text", _CODE, _RANDOM)])
    result = await _analyzer(payload).execute(_observable())
    tags = result.summary.as_dict()["tags"]
    assert "packed-code" in tags
    assert result.summary.as_dict()["verdict"] == Verdict.SUSPICIOUS.value


async def test_a_compressed_image_is_not_flagged_for_its_entropy() -> None:
    # PNG and ZIP are always high-entropy; that says nothing about them.
    payload = b"\x89PNG\r\n\x1a\n" + _RANDOM
    result = await _analyzer(payload).execute(_observable())
    assert result.summary.as_dict()["verdict"] == Verdict.UNKNOWN.value


def test_pdf_actions_are_listed_and_the_version_read() -> None:
    pdf = parse_pdf(b"%PDF-1.4\n1 0 obj << /OpenAction 2 0 R /JS (x) >> endobj")
    assert pdf["version"] == "1.4"
    assert pdf["actions"] == ["JS", "OpenAction"]


def test_a_pdf_key_that_only_contains_a_name_is_not_an_action() -> None:
    assert parse_pdf(b"%PDF-1.7 /JSONish /AAHello")["actions"] == []


async def test_a_pdf_that_runs_on_open_is_suspicious() -> None:
    payload = b"%PDF-1.7\n1 0 obj << /OpenAction << /S /JavaScript >> >> endobj"
    result = await _analyzer(payload).execute(_observable())
    summary = result.summary.as_dict()
    assert summary["verdict"] == Verdict.SUSPICIOUS.value
    assert "pdf-active-content" in summary["tags"]


async def test_a_jpeg_with_exif_is_tagged_as_carrying_metadata() -> None:
    payload = b"\xff\xd8\xff\xe1\x00\x10Exif\x00\x00II*\x00" + b"\x00" * 64 + b"\xff\xd9"
    result = await _analyzer(payload).execute(_observable())
    summary = result.summary.as_dict()
    assert "metadata" in summary["tags"]
    assert summary["verdict"] == Verdict.UNKNOWN.value


def test_entropy_bounds() -> None:
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(_TEXT) == 0.0
    assert shannon_entropy(bytes(range(256)) * 16) == 8.0


async def test_hashes_are_reported_for_the_submitted_bytes() -> None:
    import hashlib

    result = await _analyzer(_TEXT).execute(_observable())
    assert result.raw_output["sha256"] == hashlib.sha256(_TEXT).hexdigest()
    assert result.raw_output["md5"] == hashlib.md5(_TEXT, usedforsecurity=False).hexdigest()


async def test_a_job_without_a_file_is_skipped() -> None:
    result = await _analyzer(None).execute(_observable())
    assert result.status is ReportStatus.SKIPPED
