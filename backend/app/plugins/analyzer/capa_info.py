"""Capa-style capabilities: what a Windows binary says it can do, from its import table.

Capa proper matches rules over disassembly and needs a large dependency and a rule
bundle. This module answers a narrower question with no dependency: which Windows API
families does the file import? The import table is read from the PE structure, and
each capability is a set of APIs that have to appear together. It never executes the
file and never disassembles it.

Verdict. An import is a claim the code *may* call an API, not that it does. A packed
file hides its imports, and a legitimate program can import everything here. So a
high-severity capability (code injection, process hollowing, download-and-execute) is
Suspicious, and nothing is Malicious from imports alone. Other capabilities are tags
only. A file with no high-severity capability is Unknown, never Clean.

Contract note: exercised against synthetic PE fixtures only; the rule list is a
starting set, not capa's rule bundle.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any, ClassVar

from app.models.job import ObservableType, Tlp, Verdict
from app.plugins.analyzer.file_info import MAX_FILE_BYTES, identify
from app.plugins.base.analyzer import BaseAnalyzer
from app.plugins.base.plugin import PluginResult, PluginSummary, ProviderInfo
from app.plugins.base.registry import register
from app.services.observables import Observable

_MAX_DLLS = 512
_MAX_FUNCTIONS = 8192
_MAX_SECTIONS = 96
_PE32 = 0x10B
_PE32_PLUS = 0x20B


@dataclass(frozen=True)
class Capability:
    """A capability holds when every group has at least one of its APIs imported."""

    name: str
    severity: str  # "high" raises the verdict to Suspicious; "info" is a tag
    groups: tuple[tuple[str, ...], ...]


CAPABILITIES: tuple[Capability, ...] = (
    Capability(
        "code-injection",
        "high",
        (("VirtualAllocEx",), ("WriteProcessMemory",), ("CreateRemoteThread", "NtCreateThreadEx")),
    ),
    Capability(
        "process-hollowing",
        "high",
        (
            ("NtUnmapViewOfSection", "ZwUnmapViewOfSection"),
            ("SetThreadContext",),
            ("ResumeThread",),
        ),
    ),
    Capability(
        "download-and-execute",
        "high",
        (
            ("URLDownloadToFile", "URLDownloadToCacheFile"),
            ("WinExec", "ShellExecute", "CreateProcess"),
        ),
    ),
    Capability(
        "shellcode-execution",
        "info",
        (("VirtualAlloc", "VirtualProtect"), ("CreateThread", "CreateFiberEx", "QueueUserAPC")),
    ),
    Capability("persistence-service", "info", (("CreateService",), ("StartService",))),
    Capability(
        "persistence-registry",
        "info",
        (("RegSetValueEx",), ("RegCreateKeyEx", "RegOpenKeyEx")),
    ),
    Capability("keylogging", "info", (("GetAsyncKeyState", "GetKeyState", "SetWindowsHookEx"),)),
    Capability("anti-debugging", "info", (("IsDebuggerPresent", "CheckRemoteDebuggerPresent"),)),
)


def _cstring(payload: bytes, offset: int) -> str:
    return payload[offset : offset + 256].split(b"\x00", 1)[0].decode("ascii", "replace")


def read_imports(payload: bytes) -> dict[str, list[str]] | None:
    """DLL name to imported function names, or None when the import table cannot be read.

    Every offset is bounds-checked and the walk is capped, so a hostile table costs a
    bounded amount of work and never reads past the file.
    """
    try:
        if payload[:2] != b"MZ":
            return None
        (e_lfanew,) = struct.unpack_from("<I", payload, 0x3C)
        if payload[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
            return None
        _machine, count, _stamp, _symbols, _nsyms, opt_size, _chars = struct.unpack_from(
            "<HHIIIHH", payload, e_lfanew + 4
        )
        opt = e_lfanew + 24
        (magic,) = struct.unpack_from("<H", payload, opt)
        if magic == _PE32_PLUS:
            width, directories = 8, opt + 112
        elif magic == _PE32:
            width, directories = 4, opt + 96
        else:
            return None
        import_rva, _import_size = struct.unpack_from("<II", payload, directories + 8)
        table = opt + opt_size
        sections = [
            struct.unpack_from("<IIII", payload, table + index * 40 + 8)
            for index in range(min(count, _MAX_SECTIONS))
        ]

        def offset(rva: int) -> int | None:
            for vsize, va, rawsize, rawptr in sections:
                if va <= rva < va + max(vsize, rawsize):
                    position = rawptr + (rva - va)
                    return position if position < len(payload) else None
            return None

        if import_rva == 0:
            return {}
        base = offset(import_rva)
        if base is None:
            return None

        found: dict[str, list[str]] = {}
        for index in range(_MAX_DLLS):
            entry = base + index * 20
            if entry + 20 > len(payload):
                break
            lookup, _stamp, _forwarder, name_rva, address = struct.unpack_from(
                "<IIIII", payload, entry
            )
            if not (lookup or name_rva or address):
                break
            name_at = offset(name_rva)
            dll = _cstring(payload, name_at).lower() if name_at is not None else "?"
            names = found.setdefault(dll, [])
            thunk = offset(lookup or address)
            if thunk is None:
                continue
            for item in range(_MAX_FUNCTIONS):
                position = thunk + item * width
                if position + width > len(payload):
                    break
                value = int.from_bytes(payload[position : position + width], "little")
                if value == 0:
                    break
                if value >> (width * 8 - 1):
                    continue  # imported by ordinal, which has no name to match
                hint_at = offset(value)
                if hint_at is not None:
                    names.append(_cstring(payload, hint_at + 2))
    except (struct.error, IndexError, ValueError):
        return None
    return found


def _has(names: set[str], group: tuple[str, ...]) -> bool:
    # A Windows API exists as FooA and FooW; either spelling counts.
    return any(name in names or f"{name}A" in names or f"{name}W" in names for name in group)


def matched_capabilities(names: set[str]) -> list[Capability]:
    return [cap for cap in CAPABILITIES if all(_has(names, group) for group in cap.groups)]


@register
class CapaAnalyzer(BaseAnalyzer):
    """Capabilities of a Windows binary, read from the APIs it imports."""

    name = "capa"
    label = "Capa"
    description = (
        "Capabilities of a Windows binary (code injection, persistence, download-and-execute), "
        "read from its import table without executing it."
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
        notes=(
            "Reads the import table only. The file is never executed or disassembled, and it "
            "is never sent anywhere. This is not the capa rule bundle."
        ),
    )
    max_tlp = Tlp.RED
    documentation_url = "https://github.com/mandiant/capa"
    free_tier = True
    default_timeout = 60
    default_cache_ttl = 3600
    maturity = "alpha"

    async def run(self, observable: Observable) -> PluginResult:
        payload = self.local_sample_bytes()
        if payload is None:
            return self.skipped("Capa reads a submitted file; no file came with this job.")
        if len(payload) > MAX_FILE_BYTES:
            return self.skipped(f"The file is larger than {MAX_FILE_BYTES // (1024 * 1024)} MiB.")
        if identify(payload) != "pe":
            return self.skipped("Capa reads Windows PE binaries; this file is not one.")

        imports = read_imports(payload)
        if imports is None:
            return self.failed("The import table of this PE could not be read.")

        names = {function for functions in imports.values() for function in functions}
        found = matched_capabilities(names)
        highs = [cap for cap in found if cap.severity == "high"]
        tags = [cap.name for cap in found]
        verdict = Verdict.SUSPICIOUS if highs else Verdict.UNKNOWN
        score = min(100, 30 * len(highs) + 5 * (len(found) - len(highs))) if found else None

        raw: dict[str, Any] = {
            "dlls": sorted(imports),
            "import_count": len(names),
            "capabilities": tags,
        }
        summary = PluginSummary(
            verdict=verdict,
            score=score,
            tags=tags,
            headline=(
                f"{len(highs)} high-severity and {len(found) - len(highs)} other "
                f"capability(ies) from {len(names)} imported function(s)."
            ),
            extra={"capabilities": tags, "import_count": len(names)},
        )
        return self.ok(raw, summary)
