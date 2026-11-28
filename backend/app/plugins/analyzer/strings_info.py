"""Strings_Info: the readable strings of a submitted file, and the ones that matter.

Like `yara_local`, this runs on the instance and sends nothing anywhere. It pulls
printable runs out of the bytes, ASCII and UTF-16LE, the way `strings` does, then
looks for what a dropper or an injector leaves behind in a binary: the Windows
APIs it imports by name, command lines that download or decode a payload, and
base64 blobs that decode to readable text.

Verdict. A single API name is common in legitimate software (`ShellExecuteW`
is in half of all installers), so one indicator is Suspicious at most. Process
injection needs several APIs together (allocate in another process, write, start
a thread there), so two or more injection APIs are Malicious. A file with no
indicator is Unknown: its strings say nothing about whether it is clean.

Floss, which also recovers strings a binary builds at runtime, is not part of
this module: it needs an emulator and is a separate analyzer.

Contract note: exercised against small synthetic byte fixtures only.
"""

from __future__ import annotations

import base64
import binascii
import re
from typing import Any, ClassVar

from app.models.job import ObservableType, Tlp, Verdict
from app.plugins.base.analyzer import BaseAnalyzer
from app.plugins.base.plugin import PluginResult, PluginSummary, ProviderInfo
from app.plugins.base.registry import register
from app.services.observables import Observable

MAX_FILE_BYTES = 25 * 1024 * 1024
MAX_REPORTED = 200
_MAX_STRING = 300
_ASCII = re.compile(rb"[\x20-\x7e\t]{4,}")
_UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
_BASE64 = re.compile(rb"[A-Za-z0-9+/]{24,}={0,2}")
_URL = re.compile(r"https?://[^\s\"'<>]{4,200}", re.IGNORECASE)
_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_REGISTRY = re.compile(r"HKEY_[A-Z_]+\\[^\s\"]{3,120}")
_ENCODED_COMMAND = re.compile(r"-e(?:nc|ncodedcommand)\s", re.IGNORECASE)

INJECTION_APIS = frozenset(
    {
        "VirtualAllocEx",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "NtUnmapViewOfSection",
        "SetThreadContext",
        "QueueUserAPC",
    }
)
DROPPER_APIS = frozenset(
    {"URLDownloadToFile", "URLDownloadToFileA", "URLDownloadToFileW", "WinExec", "InternetOpenUrl"}
)


def extract_strings(payload: bytes, min_length: int) -> list[str]:
    """Printable ASCII and UTF-16LE runs, longest first, each capped in length."""
    found: set[str] = set()
    for match in _ASCII.finditer(payload):
        if len(match.group()) >= min_length:
            found.add(match.group().decode("ascii", "replace").strip())
    for match in _UTF16.finditer(payload):
        text = match.group().decode("utf-16-le", "replace").strip()
        if len(text) >= min_length:
            found.add(text)
    return sorted((item[:_MAX_STRING] for item in found if item), key=lambda s: (-len(s), s))


def decode_base64_blobs(payload: bytes, limit: int = 200) -> list[str]:
    """Base64 runs that decode to mostly printable text; a dropper often hides a command so."""
    decoded: list[str] = []
    for match in _BASE64.finditer(payload):
        if len(decoded) >= limit:
            break
        blob = match.group()
        blob += b"=" * (-len(blob) % 4)
        try:
            raw = base64.b64decode(blob, validate=True)
        except (binascii.Error, ValueError):
            continue
        text = raw.decode("utf-16-le" if b"\x00" in raw[:8] else "utf-8", "replace")
        printable = sum(1 for char in text if char.isprintable() or char in "\t\r\n")
        if len(text) >= 8 and printable / len(text) >= 0.9:
            decoded.append(text.strip()[:_MAX_STRING])
    return sorted(set(decoded))


def _apis_in(strings: list[str]) -> tuple[set[str], set[str]]:
    injection: set[str] = set()
    dropper: set[str] = set()
    for text in strings:
        # Imports are stored as bare names; a substring match also catches them
        # inside a longer command line or a decoded blob.
        for name in INJECTION_APIS:
            if name in text:
                injection.add(name)
        for name in DROPPER_APIS:
            if name in text:
                dropper.add(name)
        if _ENCODED_COMMAND.search(text):
            dropper.add("powershell -enc")
    return injection, dropper


def _verdict(injection: set[str], dropper: set[str]) -> Verdict:
    if len(injection) >= 2:
        return Verdict.MALICIOUS
    if injection or dropper:
        return Verdict.SUSPICIOUS
    return Verdict.UNKNOWN


@register
class StringsInfoAnalyzer(BaseAnalyzer):
    """Readable strings in a submitted file, with the APIs and commands that matter."""

    name = "strings_info"
    label = "Strings_Info"
    description = (
        "Readable strings of a submitted file, and the injection and download APIs in them."
    )
    supported_types: ClassVar[tuple[ObservableType, ...]] = (ObservableType.FILE,)
    reads_local_sample: ClassVar[bool] = True
    options_schema: ClassVar[dict[str, Any]] = {
        "min_length": {
            "type": "integer",
            "default": 6,
            "label": "Shortest string to keep (characters)",
        },
    }
    provider = ProviderInfo(
        name="Local strings",
        url="https://github.com/mandiant/flare-floss",
        api_base_url="(none: runs locally)",
        credential_url="",
        free_tier="Free; no account.",
        rate_limit="None; bounded by the analyzer timeout.",
        notes="The file is never sent anywhere; its strings are read, never executed.",
    )
    max_tlp = Tlp.RED
    documentation_url = "https://github.com/mandiant/flare-floss"
    free_tier = True
    default_timeout = 60
    default_cache_ttl = 3600
    maturity = "alpha"

    async def run(self, observable: Observable) -> PluginResult:
        payload = self.local_sample_bytes()
        if payload is None:
            return self.skipped("Strings_Info reads a submitted file; no file came with this job.")
        if len(payload) > MAX_FILE_BYTES:
            return self.skipped(f"The file is larger than {MAX_FILE_BYTES // (1024 * 1024)} MiB.")

        min_length = max(4, min(int(self.option("min_length", 6)), 64))
        strings = extract_strings(payload, min_length)
        decoded = decode_base64_blobs(payload)
        # Decoded blobs are checked for the same indicators as the strings.
        injection, dropper = _apis_in(strings + decoded)
        urls = sorted({url for text in strings + decoded for url in _URL.findall(text)})
        ips = sorted({ip for text in strings for ip in _IPV4.findall(text)})
        registry = sorted({key for text in strings for key in _REGISTRY.findall(text)})

        verdict = _verdict(injection, dropper)
        tags: list[str] = []
        if injection:
            tags.append("injection-api")
        if dropper:
            tags.append("dropper-api")
        if urls:
            tags.append("url")
        if ips:
            tags.append("ip")
        if registry:
            tags.append("registry")
        if decoded:
            tags.append("encoded-strings")

        headline = (
            f"{len(strings)} string(s); {len(injection)} injection API(s), "
            f"{len(dropper)} download/exec indicator(s)."
        )
        summary = PluginSummary(
            verdict=verdict,
            score=min(100, len(injection) * 30 + len(dropper) * 15),
            tags=tags,
            headline=headline,
            extra={
                "strings": len(strings),
                "injection_apis": sorted(injection),
                "dropper_indicators": sorted(dropper),
                "urls": urls[:50],
                "ips": ips[:50],
            },
        )
        raw = {
            "min_length": min_length,
            "strings_total": len(strings),
            "strings": strings[:MAX_REPORTED],
            "decoded_base64": decoded[:50],
            "registry_keys": registry[:50],
        }
        return self.ok(raw, summary)
