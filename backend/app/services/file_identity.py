"""Identification of a file from its bytes: format, PE structure, entropy.

Shared by the File_Info analyzer and the sample record kept at intake, so a file is
described the same way wherever it is looked at. Reads bytes only; nothing is executed.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import math
import struct
from typing import Any

_MAX_SECTIONS = 96
_PE_EXECUTE = 0x20000000
_PE_WRITE = 0x80000000
_PE_MACHINES = {0x014C: "x86", 0x8664: "x64", 0x01C0: "arm", 0xAA64: "arm64", 0x0200: "ia64"}


def shannon_entropy(data: bytes) -> float:
    """Bits per byte, 0 to 8. Compressed or encrypted content sits near 8."""
    if not data:
        return 0.0
    total = len(data)
    # One C-speed count per byte value: a Python loop over a 25 MB sample is seconds.
    counts = (data.count(value) for value in range(256))
    return round(-sum((n / total) * math.log2(n / total) for n in counts if n), 3)


def identify(payload: bytes) -> str:
    """The format, read from the leading bytes. The file name is never trusted."""
    if payload.startswith(b"MZ"):
        return "pe" if parse_pe(payload) is not None else "dos"
    if payload.startswith(b"\x7fELF"):
        return "elf"
    if payload.startswith((b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe")):
        return "macho"
    if payload.startswith(b"%PDF"):
        return "pdf"
    if payload.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if payload.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if payload.startswith((b"GIF87a", b"GIF89a")):
        return "gif"
    if payload.startswith(b"PK\x03\x04"):
        return "zip"
    if payload.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "ole"
    if payload.startswith(b"#!"):
        return "script"
    return "unknown"


def parse_pe(payload: bytes) -> dict[str, Any] | None:
    """The COFF header and section table of a PE file, or None when it is not one."""
    try:
        (e_lfanew,) = struct.unpack_from("<I", payload, 0x3C)
        if payload[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
            return None
        machine, count, stamp, _symbols, _nsyms, opt_size, characteristics = struct.unpack_from(
            "<HHIIIHH", payload, e_lfanew + 4
        )
        table = e_lfanew + 4 + 20 + opt_size
        sections: list[dict[str, Any]] = []
        for index in range(min(count, _MAX_SECTIONS)):
            raw_name, _vsize, _vaddr, raw_size, raw_ptr, _reloc, _lines, _nrel, _nlines, flags = (
                struct.unpack_from("<8sIIIIIIHHI", payload, table + index * 40)
            )
            name = raw_name.rstrip(b"\x00").decode("ascii", "replace")
            data = payload[raw_ptr : raw_ptr + raw_size]
            sections.append(
                {
                    "name": name,
                    "size": raw_size,
                    "entropy": shannon_entropy(data),
                    "executable": bool(flags & _PE_EXECUTE),
                    "writable": bool(flags & _PE_WRITE),
                }
            )
    except struct.error:
        return None
    return {
        "machine": _PE_MACHINES.get(machine, f"0x{machine:04x}"),
        "compiled_at": _timestamp(stamp),
        "characteristics": f"0x{characteristics:04x}",
        "sections": sections,
    }


def _timestamp(stamp: int) -> str | None:
    # Zero is what reproducible builds write, so it is reported as absent, not as 1970.
    if stamp == 0:
        return None
    try:
        return dt.datetime.fromtimestamp(stamp, dt.UTC).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


MIME_BY_KIND = {
    "pe": "application/x-msdownload",
    "dos": "application/x-msdos-program",
    "elf": "application/x-elf",
    "macho": "application/x-mach-binary",
    "pdf": "application/pdf",
    "png": "image/png",
    "jpeg": "image/jpeg",
    "gif": "image/gif",
    "zip": "application/zip",
    "ole": "application/x-ole-storage",
    "script": "text/x-script",
    "unknown": "application/octet-stream",
}

# The extensions a format is normally saved under. A file whose name claims
# something else is worth a line in the record: a PE called `invoice.pdf` is the
# classic lure. Containers such as zip (docx, apk, jar) are left out, because
# their extension says more than the container does.
EXPECTED_EXTENSIONS: dict[str, frozenset[str]] = {
    "pe": frozenset({".exe", ".dll", ".sys", ".scr", ".ocx", ".cpl", ".efi", ".msi"}),
    "pdf": frozenset({".pdf"}),
    "png": frozenset({".png"}),
    "jpeg": frozenset({".jpg", ".jpeg"}),
    "gif": frozenset({".gif"}),
    "ole": frozenset({".doc", ".xls", ".ppt", ".msi"}),
    "elf": frozenset({".elf", ".so", ".o", ".bin"}),
    "script": frozenset({".sh", ".py", ".pl", ".ps1", ".bat", ".cmd", ".js", ".vbs"}),
}


def submitted_extension(name: str | None) -> str:
    """The lower-cased extension the uploader gave, or an empty string."""
    base = (name or "").replace("\\", "/").split("/")[-1]
    dot = base.rfind(".")
    return base[dot:].lower() if 0 < dot < len(base) - 1 else ""


def describe(payload: bytes, *, submitted_name: str | None) -> dict[str, Any]:
    """Everything that can be said about a file from its bytes alone.

    Hashes are computed for every file, since they are what other sources are
    asked about. Nothing here runs the file, and the name is only compared, never
    trusted for the format.
    """
    kind = identify(payload)
    extension = submitted_extension(submitted_name)
    expected = EXPECTED_EXTENSIONS.get(kind)
    pe = parse_pe(payload) if kind == "pe" else None
    return {
        "size": len(payload),
        "md5": hashlib.md5(payload, usedforsecurity=False).hexdigest(),
        "sha1": hashlib.sha1(payload, usedforsecurity=False).hexdigest(),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "kind": kind,
        "mime": MIME_BY_KIND.get(kind, MIME_BY_KIND["unknown"]),
        "entropy": shannon_entropy(payload),
        "extension": extension,
        "extension_mismatch": bool(expected and extension and extension not in expected),
        "magic_hex": payload[:16].hex(),
        "pe": (
            {
                "machine": pe["machine"],
                "compiled_at": pe["compiled_at"],
                "sections": len(pe["sections"]),
            }
            if pe
            else None
        ),
    }
