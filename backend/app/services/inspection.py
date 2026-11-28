"""Static inspection of a submitted file: what can be read from its bytes, nothing run.

This is triage, not a sandbox. It answers the questions an analyst asks in the first
minute, from the file itself:

- Does the name lie about the content, or hide a second extension or a right-to-left
  override?
- Is it packed or encrypted (near-maximal entropy)?
- For a PE: writable and executable sections, the process-injection and download APIs
  its import names mention, a compile time in the future.
- For a PDF: launch, JavaScript and automatic-action objects.
- For an Office file: macros that run on open, and the APIs they call (via oletools,
  the same parser as `doc_info`).
- For an archive: traversal names, password-protected members, executable members,
  a compression ratio that looks like a bomb, and one level of member inspection.
  Members are read in memory and never written to disk or extracted.
- For a script: encoded commands, download and execution calls, long encoded blobs.

Verdicts are capped at Suspicious. A static heuristic misfires on legitimate software,
so only a YARA match or a provider can say Malicious. `clean` here means only "no
static indicator was found"; it is not a statement that the file is safe.

Limits, stated on purpose:
- Import names are read from the file's bytes, so a packed file can hide them.
- PDF object names are searched in the raw bytes; objects inside compressed object
  streams are not visible, so an absence is not evidence.
- Nothing is decompressed beyond what a member read needs, and every read is capped.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import io
import re
import unicodedata
import zipfile
from dataclasses import asdict, dataclass
from typing import Any

from app.core.logging import get_logger
from app.services import file_identity

logger = get_logger(__name__)

INSPECTION_VERSION = 1

MAX_MEMBERS = 50
MAX_MEMBER_BYTES = 16 * 1024 * 1024
MAX_MEMBER_TOTAL_BYTES = 64 * 1024 * 1024
MAX_ZIP_ENTRIES = 5000
MAX_SCRIPT_BYTES = 2 * 1024 * 1024
PACKED_ENTROPY = 7.2
PACKED_MIN_BYTES = 4096
BOMB_RATIO = 100
BOMB_MIN_UNCOMPRESSED = 10 * 1024 * 1024
FUTURE_SLACK = dt.timedelta(days=2)

SEVERITIES = ("info", "notice", "warning", "alert")
_RANK = {name: index for index, name in enumerate(SEVERITIES)}

# A name's final extension that a dropper uses, and the document-like one hidden before it.
_EXECUTABLE_EXTENSIONS = frozenset(
    {".exe", ".scr", ".com", ".pif", ".js", ".jse", ".vbs", ".vbe", ".bat", ".cmd",
     ".ps1", ".lnk", ".msi", ".hta", ".wsf", ".jar", ".dll", ".cpl"}
)  # fmt: skip
_LURE_EXTENSIONS = frozenset(
    {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".jpg", ".jpeg", ".png",
     ".txt", ".rtf", ".htm", ".html"}
)  # fmt: skip
_SCRIPT_EXTENSIONS = frozenset(
    {".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta", ".wsf", ".py", ".sh"}
)
_NESTED_ARCHIVE_SUFFIXES = (".zip", ".rar", ".7z", ".iso", ".img", ".gz", ".tar", ".cab")

# Process injection and code-loading APIs. Presence in the import names is a
# reason to look, not a finding on its own: many installers call some of these.
INJECTION_APIS = (
    b"VirtualAllocEx",
    b"WriteProcessMemory",
    b"CreateRemoteThread",
    b"NtUnmapViewOfSection",
    b"QueueUserAPC",
    b"SetWindowsHookEx",
    b"RtlCreateUserThread",
    b"NtWriteVirtualMemory",
)
DOWNLOAD_APIS = (
    b"URLDownloadToFile",
    b"URLDownloadToCacheFile",
    b"InternetOpenUrl",
    b"WinHttpOpen",
)

_PE_ANTI_ANALYSIS = (b"IsDebuggerPresent", b"CheckRemoteDebuggerPresent")

_PDF_OBJECTS = {
    "launch": re.compile(rb"/Launch\b"),
    "javascript": re.compile(rb"/JavaScript\b|/JS(?![A-Za-z])"),
    "auto_action": re.compile(rb"/OpenAction\b|/AA\b"),
    "embedded": re.compile(rb"/EmbeddedFile\b"),
    "form_or_media": re.compile(rb"/XFA\b|/RichMedia\b|/SubmitForm\b"),
}

_SCRIPT_PATTERNS: tuple[tuple[str, re.Pattern[str], str, str], ...] = (
    (
        "encoded_command",
        re.compile(r"(?i)(?:^|\s)-(?:enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}"),
        "warning",
        "PowerShell run with an encoded command",
    ),
    (
        "decodes_base64",
        re.compile(r"(?i)FromBase64String|System\.Convert\]::FromBase64"),
        "notice",
        "decodes Base64 at run time",
    ),
    (
        "invoke_expression",
        re.compile(r"(?i)\bInvoke-Expression\b|\bIEX\s*\("),
        "notice",
        "runs a string as code (Invoke-Expression)",
    ),
    (
        "dynamic_eval",
        re.compile(r"\b(?:eval|exec)\s*\("),
        "notice",
        "runs a string as code (eval or exec)",
    ),
    (
        "downloads",
        re.compile(
            r"(?i)DownloadString|DownloadFile|Invoke-WebRequest|\bcurl\s|\bwget\s|"
            r"XMLHTTP|WinHttp\.WinHttpRequest"
        ),
        "notice",
        "fetches something from the network",
    ),
    (
        "launches_process",
        re.compile(r"(?i)Start-Process|WScript\.Shell|Shell\.Application|CreateObject\s*\(\s*\"?WScript"),
        "notice",
        "starts another program",
    ),
    (
        "long_encoded_blob",
        re.compile(r"[A-Za-z0-9+/]{400,}={0,2}"),
        "notice",
        "contains a long Base64-like blob",
    ),
)  # fmt: skip

_BIDI_CONTROLS = ("‮", "‭", "⁦", "⁧", "⁨", "⁩")


@dataclass(frozen=True)
class Finding:
    severity: str
    code: str
    message: str
    member: str | None = None

    def as_dict(self) -> dict[str, Any]:
        data = asdict(self)
        if self.member is None:
            data.pop("member")
        return data


def _worst(findings: list[Finding]) -> str:
    """The verdict a list of findings supports: never above Suspicious."""
    if any(_RANK[f.severity] >= _RANK["warning"] for f in findings):
        return "suspicious"
    return "clean"


# -- names -------------------------------------------------------------------


def name_findings(name: str | None, *, mismatch: bool, kind: str) -> list[Finding]:
    """What the submitted name says that the content does not back up."""
    found: list[Finding] = []
    if not name:
        return found
    if any(char in name for char in _BIDI_CONTROLS) or any(
        unicodedata.category(char) == "Cf" for char in name
    ):
        found.append(
            Finding(
                "alert",
                "name_hidden_characters",
                "The name contains a right-to-left or invisible control character, "
                "the usual way to show `fdp.exe` as `exe.pdf`.",
            )
        )
    base = name.replace("\\", "/").split("/")[-1].lower()
    parts = base.split(".")
    if len(parts) >= 3:
        lure, final = f".{parts[-2]}", f".{parts[-1]}"
        if lure in _LURE_EXTENSIONS and final in _EXECUTABLE_EXTENSIONS:
            found.append(
                Finding(
                    "alert",
                    "double_extension",
                    f"The name ends in {final} after {lure}: a document that is an executable.",
                )
            )
    if mismatch:
        found.append(
            Finding(
                "warning",
                "name_mismatch",
                f"The name claims a different format from the content, which is a {kind}.",
            )
        )
    return found


# -- whole file --------------------------------------------------------------


def entropy_findings(profile: dict[str, Any], kind: str) -> list[Finding]:
    # Compressed containers and media are high-entropy by design: not a signal.
    if kind in {"zip", "png", "jpeg", "gif", "pdf"}:
        return []
    if profile["size"] >= PACKED_MIN_BYTES and profile["entropy"] >= PACKED_ENTROPY:
        return [
            Finding(
                "notice",
                "packed_or_encrypted",
                f"The content is nearly random (entropy {profile['entropy']}): packed, "
                "encrypted or compressed. Its real content cannot be read statically.",
            )
        ]
    return []


# -- PE ----------------------------------------------------------------------


def pe_findings(payload: bytes, pe: dict[str, Any], *, now: dt.datetime) -> list[Finding]:
    found: list[Finding] = []
    rwx = [s["name"] for s in pe["sections"] if s["writable"] and s["executable"]]
    if rwx:
        found.append(
            Finding(
                "warning",
                "writable_executable_section",
                "Sections that are both writable and executable: code that rewrites "
                f"itself, a common packer trait. Sections: {', '.join(rwx[:5])}.",
            )
        )
    hot = [
        s["name"]
        for s in pe["sections"]
        if s["size"] >= PACKED_MIN_BYTES and s["entropy"] >= PACKED_ENTROPY
    ]
    if hot:
        found.append(
            Finding(
                "notice",
                "high_entropy_section",
                f"Nearly random section content in {', '.join(hot[:5])}: likely packed.",
            )
        )
    injection = [api.decode() for api in INJECTION_APIS if api in payload]
    if len(injection) >= 3:
        found.append(
            Finding(
                "warning",
                "process_injection_apis",
                f"{len(injection)} process-injection APIs named in the file: "
                f"{', '.join(injection[:6])}.",
            )
        )
    elif injection:
        found.append(
            Finding(
                "notice",
                "process_injection_api",
                f"Process-injection API named in the file: {', '.join(injection)}.",
            )
        )
    downloads = [api.decode() for api in DOWNLOAD_APIS if api in payload]
    if downloads:
        found.append(
            Finding(
                "notice",
                "download_apis",
                f"Network download API named in the file: {', '.join(downloads)}.",
            )
        )
    if any(api in payload for api in _PE_ANTI_ANALYSIS):
        found.append(
            Finding("notice", "anti_debug_api", "Debugger-detection API named in the file.")
        )
    compiled = pe.get("compiled_at")
    if compiled:
        when = dt.datetime.fromisoformat(compiled)
        if when > now + FUTURE_SLACK:
            found.append(
                Finding(
                    "notice",
                    "future_compile_time",
                    f"The compile time ({compiled}) is in the future: the header was edited.",
                )
            )
    return found


# -- PDF ---------------------------------------------------------------------


def pdf_findings(payload: bytes) -> list[Finding]:
    present = {name for name, pattern in _PDF_OBJECTS.items() if pattern.search(payload)}
    found: list[Finding] = []
    if "launch" in present:
        found.append(
            Finding("warning", "pdf_launch_action", "The PDF launches an external program or file.")
        )
    if "javascript" in present and "auto_action" in present:
        found.append(
            Finding(
                "warning",
                "pdf_javascript_on_open",
                "JavaScript that runs when the document opens.",
            )
        )
    elif "javascript" in present:
        found.append(Finding("notice", "pdf_javascript", "The PDF contains JavaScript."))
    elif "auto_action" in present:
        found.append(Finding("notice", "pdf_auto_action", "The PDF runs an action when it opens."))
    if "embedded" in present:
        found.append(Finding("notice", "pdf_embedded_file", "The PDF embeds another file."))
    if "form_or_media" in present:
        found.append(Finding("info", "pdf_form_or_media", "The PDF has forms, XFA or rich media."))
    return found


# -- Office macros -----------------------------------------------------------


def office_findings(payload: bytes) -> list[Finding]:
    from app.plugins.analyzer import doc_info  # oletools: imported only when needed

    try:
        report = doc_info.scan_document(payload)
    except Exception as exc:
        logger.info("inspection_office_unparsed", error=str(exc)[:120])
        return [Finding("info", "office_not_parsed", "The Office file could not be parsed.")]
    if report.kind == "not-office" or not report.modules:
        return []
    if report.autoexec and report.suspicious:
        return [
            Finding(
                "alert",
                "macro_autoexec_with_apis",
                "Macros that run on open and call "
                f"{', '.join(report.suspicious[:5])}: the usual dropper shape.",
            )
        ]
    if report.autoexec:
        return [
            Finding(
                "warning",
                "macro_autoexec",
                f"Macros run on open or close ({', '.join(report.autoexec[:3])}).",
            )
        ]
    if report.suspicious:
        return [
            Finding(
                "notice",
                "macro_suspicious_api",
                f"Macros call {', '.join(report.suspicious[:5])}.",
            )
        ]
    return [Finding("info", "macros_present", f"{report.modules} macro module(s), none auto-run.")]


# -- archives ----------------------------------------------------------------


def zip_entry_findings(infos: list[zipfile.ZipInfo]) -> list[Finding]:
    """Checks on the directory of an archive: names, encryption, bomb shape."""
    found: list[Finding] = []
    if len(infos) > MAX_ZIP_ENTRIES:
        found.append(
            Finding(
                "warning",
                "zip_too_many_entries",
                f"{len(infos)} entries: more than the inspection reads.",
            )
        )
    encrypted = [i.filename for i in infos if i.flag_bits & 0x1]
    if encrypted:
        found.append(
            Finding(
                "notice",
                "zip_encrypted_members",
                f"{len(encrypted)} member(s) are password-protected, so their content "
                "cannot be inspected here.",
            )
        )
    traversal = [
        i.filename
        for i in infos
        if i.filename.startswith(("/", "\\"))
        or ".." in i.filename.replace("\\", "/").split("/")
        or ":" in i.filename[:3]
    ]
    if traversal:
        found.append(
            Finding(
                "alert",
                "zip_path_traversal",
                f"{len(traversal)} member name(s) escape the archive folder, e.g. "
                f"{traversal[0][:120]!r}.",
            )
        )
    executables = [i.filename for i in infos if _suffix(i.filename) in _EXECUTABLE_EXTENSIONS]
    if executables:
        found.append(
            Finding(
                "notice",
                "zip_executable_members",
                f"{len(executables)} executable or script member(s): "
                f"{', '.join(n[:80] for n in executables[:5])}.",
            )
        )
    total_size = sum(i.file_size for i in infos)
    total_packed = sum(i.compress_size for i in infos)
    if (
        total_size >= BOMB_MIN_UNCOMPRESSED
        and total_packed > 0
        and total_size / total_packed > BOMB_RATIO
    ):
        found.append(
            Finding(
                "alert",
                "zip_bomb_like",
                f"{total_size // (1024 * 1024)} MiB expands from {total_packed // 1024} KiB: "
                f"a ratio of {total_size // total_packed}:1.",
            )
        )
    return found


def _suffix(name: str) -> str:
    base = name.replace("\\", "/").split("/")[-1].lower()
    dot = base.rfind(".")
    return base[dot:] if dot > 0 else ""


def apk_findings(payload: bytes) -> list[Finding]:
    from app.plugins.analyzer import apk_info

    try:
        manifest = apk_info.read_manifest(payload)
    except Exception as exc:
        logger.info("inspection_apk_unreadable", error=str(exc)[:120])
        return []
    found = [
        Finding(
            "warning" if indicator.severity == "high" else "info",
            f"apk_{indicator.name.replace('-', '_')}",
            f"Permission combination: {indicator.name}.",
        )
        for indicator in apk_info.matched_indicators(manifest.permissions)
    ]
    return found


def _member_findings(
    archive: zipfile.ZipFile, infos: list[zipfile.ZipInfo], depth: int
) -> list[dict[str, Any]]:
    """Inspect each member in memory, one level deep. Never extracted to disk."""
    members: list[dict[str, Any]] = []
    budget = MAX_MEMBER_TOTAL_BYTES
    for info in infos[:MAX_MEMBERS]:
        if info.is_dir():
            continue
        entry: dict[str, Any] = {"name": info.filename, "size": info.file_size}
        if info.flag_bits & 0x1:
            entry.update(verdict="unknown", kind=None, skipped="password-protected")
            members.append(entry)
            continue
        if info.file_size > MAX_MEMBER_BYTES or info.file_size > budget:
            entry.update(verdict="unknown", kind=None, skipped="too large to read")
            members.append(entry)
            continue
        try:
            data = archive.read(info)
        except (zipfile.BadZipFile, RuntimeError, OSError, NotImplementedError) as exc:
            entry.update(verdict="unknown", kind=None, skipped=f"unreadable: {str(exc)[:80]}")
            members.append(entry)
            continue
        budget -= len(data)
        result = inspect_bytes(data, submitted_name=info.filename, depth=depth + 1)
        entry.update(
            sha256=file_identity.describe(data, submitted_name=None)["sha256"],
            kind=result["kind"],
            verdict=result["verdict"],
            findings=result["findings"],
        )
        members.append(entry)
    if len(infos) > MAX_MEMBERS:
        members.append({"name": f"... {len(infos) - MAX_MEMBERS} more", "skipped": "member cap"})
    return members


def _archive(payload: bytes, *, depth: int) -> tuple[list[Finding], list[dict[str, Any]]]:
    try:
        archive = zipfile.ZipFile(io.BytesIO(payload))
    except zipfile.BadZipFile:
        return [
            Finding("warning", "zip_unreadable", "Claims to be a zip but its directory is broken.")
        ], []
    with archive:
        infos = archive.infolist()
        found = zip_entry_findings(infos)
        if depth == 0 and any(i.filename == "AndroidManifest.xml" for i in infos):
            found.extend(apk_findings(payload))
        members = _member_findings(archive, infos, depth) if depth == 0 else []
    nested = [i.filename for i in infos if i.filename.lower().endswith(_NESTED_ARCHIVE_SUFFIXES)]
    if nested and depth == 0:
        found.append(
            Finding(
                "notice",
                "zip_nested_archives",
                f"{len(nested)} archive(s) nested inside: their content is not opened.",
            )
        )
    return found, members


def _member_verdict_findings(members: list[dict[str, Any]]) -> list[Finding]:
    """Lift member findings onto the archive, so the top-level list tells the story."""
    lifted: list[Finding] = []
    for entry in members:
        for finding in entry.get("findings", []):
            if _RANK[finding["severity"]] >= _RANK["warning"]:
                lifted.append(
                    Finding(
                        finding["severity"],
                        finding["code"],
                        finding["message"],
                        member=entry["name"],
                    )
                )
    return lifted


# -- scripts -----------------------------------------------------------------


def script_findings(payload: bytes, name: str | None) -> list[Finding]:
    head = payload[:MAX_SCRIPT_BYTES]
    if b"\x00" in head[:4096]:
        return []  # binary, not a script
    text = head.decode("utf-8", "replace")
    found: list[Finding] = []
    for code, pattern, severity, meaning in _SCRIPT_PATTERNS:
        hits = len(pattern.findall(text))
        if hits:
            found.append(Finding(severity, code, f"{meaning} ({hits} occurrence(s))."))
    if any(char in text for char in _BIDI_CONTROLS):
        found.append(
            Finding(
                "alert",
                "script_bidi_controls",
                "The script contains right-to-left control characters, which hide what it does.",
            )
        )
    longest = max((len(line) for line in text.splitlines()), default=0)
    if longest > 5000:
        found.append(Finding("notice", "script_very_long_line", f"A line of {longest} characters."))
    return found


# -- entry points ------------------------------------------------------------


def inspect_bytes(
    payload: bytes,
    *,
    submitted_name: str | None,
    depth: int = 0,
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    """Inspect one file. Blocking and CPU-bound: call it off the event loop."""
    now = now or dt.datetime.now(dt.UTC)
    profile = file_identity.describe(payload, submitted_name=submitted_name)
    kind = profile["kind"]
    findings: list[Finding] = []
    findings += name_findings(submitted_name, mismatch=profile["extension_mismatch"], kind=kind)
    findings += entropy_findings(profile, kind)
    members: list[dict[str, Any]] = []

    if kind == "pe":
        pe = file_identity.parse_pe(payload)
        if pe is not None:
            findings += pe_findings(payload, pe, now=now)
    elif kind == "pdf":
        findings += pdf_findings(payload)
    elif kind == "ole":
        findings += office_findings(payload)
    elif kind == "zip":
        archive_findings, members = _archive(payload, depth=depth)
        findings += archive_findings
        findings += _member_verdict_findings(members)
    elif kind in {"unknown", "script"} and _looks_textual(submitted_name, kind):
        findings += script_findings(payload, submitted_name)

    verdict = _worst(findings)
    if (
        verdict == "clean"
        and kind == "unknown"
        and not any(_RANK[f.severity] >= _RANK["notice"] for f in findings)
    ):
        verdict = "unknown"
    return {
        "version": INSPECTION_VERSION,
        "kind": kind,
        "verdict": verdict,
        "findings": [f.as_dict() for f in findings],
        "members": members,
        "counts": {
            "alert": sum(f.severity == "alert" for f in findings),
            "warning": sum(f.severity == "warning" for f in findings),
            "notice": sum(f.severity == "notice" for f in findings),
        },
        "inspected_at": now.isoformat(),
    }


def _looks_textual(name: str | None, kind: str) -> bool:
    return kind == "script" or _suffix(name or "") in _SCRIPT_EXTENSIONS


async def inspect_file(payload: bytes, *, submitted_name: str | None) -> dict[str, Any]:
    """The inspection of a submitted file, computed off the event loop."""
    return await asyncio.to_thread(inspect_bytes, payload, submitted_name=submitted_name)


def failed(reason: str) -> dict[str, Any]:
    """What is recorded when inspection itself breaks: the upload still succeeds."""
    return {
        "version": INSPECTION_VERSION,
        "kind": None,
        "verdict": "unknown",
        "findings": [{"severity": "info", "code": "inspection_failed", "message": reason}],
        "members": [],
        "counts": {"alert": 0, "warning": 0, "notice": 0},
        "inspected_at": dt.datetime.now(dt.UTC).isoformat(),
    }
