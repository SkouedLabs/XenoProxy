"""File_Info: the static metadata of a submitted file, read without running it.

The file is identified from its bytes, not its name, then its structure is read:
the PE headers and sections of a Windows binary, the active-content keys of a PDF,
and whether an image carries EXIF or XMP metadata. Hashes and entropy come with
every file, since they are what another source needs to be asked about it.

Verdict. Static structure alone never proves a file hostile, and never proves it
clean. The indicators here are the ones packers and loaders leave: a section
named after a known packer, a section that is both writable and executable, code
whose entropy says it is compressed or encrypted, and PDF actions that run on
open. Any of them is Suspicious; none of them is Malicious on its own, because a
legitimate installer can be packed. A file with no indicator is Unknown.

This module does not use an external parser, so it adds no dependency to the
image. It is deliberately smaller than exiftool or pefile: it reads the fields
that matter for triage and ignores the rest.

Contract note: exercised against synthetic byte fixtures only.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import math
import re
import struct
from collections import Counter
from typing import Any, ClassVar

from app.models.job import ObservableType, Tlp, Verdict
from app.plugins.base.analyzer import BaseAnalyzer
from app.plugins.base.plugin import PluginResult, PluginSummary, ProviderInfo
from app.plugins.base.registry import register
from app.services.observables import Observable

MAX_FILE_BYTES = 25 * 1024 * 1024
_MAX_SECTIONS = 96
_HEAD_BYTES = 256 * 1024
_BINARY_KINDS = frozenset({"pe", "elf", "macho", "script"})
_PACKED_FILE_ENTROPY = 7.2
_PACKED_SECTION_ENTROPY = 7.0
_PACKER_SECTIONS = frozenset(
    {
        "upx0",
        "upx1",
        "upx2",
        ".upx0",
        ".upx1",
        ".themida",
        ".vmp0",
        ".vmp1",
        ".vmp2",
        ".aspack",
        ".adata",
        ".petite",
        ".mpress1",
        ".mpress2",
        ".nsp0",
        ".nsp1",
    }
)
_PE_EXECUTE = 0x20000000
_PE_WRITE = 0x80000000
_PE_MACHINES = {0x014C: "x86", 0x8664: "x64", 0x01C0: "arm", 0xAA64: "arm64", 0x0200: "ia64"}
_PDF_ACTIONS = re.compile(rb"/(JavaScript|JS|OpenAction|AA|Launch|EmbeddedFile|XFA)(?![A-Za-z])")
_PDF_VERSION = re.compile(rb"^%PDF-(\d\.\d)")


def shannon_entropy(data: bytes) -> float:
    """Bits per byte, 0 to 8. Compressed or encrypted content sits near 8."""
    if not data:
        return 0.0
    total = len(data)
    return round(-sum((n / total) * math.log2(n / total) for n in Counter(data).values()), 3)


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


def parse_pdf(payload: bytes) -> dict[str, Any]:
    version = _PDF_VERSION.match(payload[:16])
    actions = sorted({m.group(1).decode("ascii") for m in _PDF_ACTIONS.finditer(payload)})
    return {"version": version.group(1).decode("ascii") if version else None, "actions": actions}


def image_metadata(payload: bytes) -> dict[str, bool]:
    """Whether the common metadata blocks are present; their values are not read."""
    head = payload[:_HEAD_BYTES]
    return {
        "exif": b"Exif\x00\x00" in head or b"eXIf" in head,
        "xmp": b"http://ns.adobe.com/xap/1.0/" in head or b"XML:com.adobe.xmp" in head,
    }


def _indicators(kind: str, payload: bytes, pe: dict[str, Any] | None, pdf: dict[str, Any] | None):
    found: list[str] = []
    if kind in _BINARY_KINDS and shannon_entropy(payload) > _PACKED_FILE_ENTROPY:
        found.append("high-entropy")
    if pe:
        for section in pe["sections"]:
            if section["name"].lower() in _PACKER_SECTIONS:
                found.append("packer-section")
            if section["executable"] and section["writable"]:
                found.append("writable-code")
            if section["executable"] and section["entropy"] > _PACKED_SECTION_ENTROPY:
                found.append("packed-code")
    if pdf and pdf["actions"]:
        found.append("pdf-active-content")
    return sorted(set(found))


@register
class FileInfoAnalyzer(BaseAnalyzer):
    """Format, hashes, entropy and the structural indicators of a submitted file."""

    name = "file_info"
    label = "File_Info"
    description = (
        "Format, hashes and entropy of a submitted file, with PE, PDF and metadata structure."
    )
    supported_types: ClassVar[tuple[ObservableType, ...]] = (ObservableType.FILE,)
    provider = ProviderInfo(
        name="Local static analysis",
        url="https://github.com/",
        api_base_url="(none: runs locally)",
        credential_url="",
        free_tier="Free; no account.",
        rate_limit="None; bounded by the analyzer timeout.",
        notes="The file is never sent anywhere and never executed; only its bytes are read.",
    )
    max_tlp = Tlp.RED
    documentation_url = "https://github.com/"
    free_tier = True
    default_timeout = 60
    default_cache_ttl = 3600
    maturity = "alpha"

    async def run(self, observable: Observable) -> PluginResult:
        payload = self.local_sample_bytes()
        if payload is None:
            return self.skipped("File_Info reads a submitted file; no file came with this job.")
        if len(payload) > MAX_FILE_BYTES:
            return self.skipped(f"The file is larger than {MAX_FILE_BYTES // (1024 * 1024)} MiB.")

        kind = identify(payload)
        pe = parse_pe(payload) if kind == "pe" else None
        pdf = parse_pdf(payload) if kind == "pdf" else None
        image = image_metadata(payload) if kind in {"jpeg", "png", "gif"} else None
        indicators = _indicators(kind, payload, pe, pdf)

        verdict = Verdict.SUSPICIOUS if indicators else Verdict.UNKNOWN
        tags = [kind, *indicators]
        if image and (image["exif"] or image["xmp"]):
            tags.append("metadata")

        raw = {
            "kind": kind,
            "size": len(payload),
            "md5": hashlib.md5(payload, usedforsecurity=False).hexdigest(),
            "sha1": hashlib.sha1(payload, usedforsecurity=False).hexdigest(),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "entropy": shannon_entropy(payload),
            "pe": pe,
            "pdf": pdf,
            "image": image,
            "indicators": indicators,
        }
        summary = PluginSummary(
            verdict=verdict,
            score=min(100, 25 * len(indicators)) if indicators else None,
            tags=tags,
            headline=(
                f"{kind.upper()} file, {len(payload)} bytes; "
                f"{len(indicators)} structural indicator(s)."
            ),
            extra={
                "kind": kind,
                "size": len(payload),
                "entropy": raw["entropy"],
                "sha256": raw["sha256"],
                "indicators": indicators,
                "compiled_at": pe["compiled_at"] if pe else None,
            },
        )
        return self.ok(raw, summary)
