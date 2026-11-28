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

import hashlib
import re
from typing import Any, ClassVar

from app.models.job import ObservableType, Tlp, Verdict
from app.plugins.base.analyzer import BaseAnalyzer
from app.plugins.base.plugin import PluginResult, PluginSummary, ProviderInfo
from app.plugins.base.registry import register
from app.services.file_identity import identify, parse_pe, shannon_entropy
from app.services.observables import Observable

MAX_FILE_BYTES = 25 * 1024 * 1024
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
_PDF_ACTIONS = re.compile(rb"/(JavaScript|JS|OpenAction|AA|Launch|EmbeddedFile|XFA)(?![A-Za-z])")
_PDF_VERSION = re.compile(rb"^%PDF-(\d\.\d)")


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
    reads_local_sample: ClassVar[bool] = True
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
