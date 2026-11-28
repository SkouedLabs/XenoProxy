"""YARA rulesets for the local scanner: where they live, how they are pulled.

Layout under `Settings.yara_rules_dir`:

    custom/              rules the operator drops in, any depth, `.yar`/`.yara`
    sources/<id>/        a public ruleset pulled from the interface
    sources/<id>.json    where it came from: URL, archive digest, date, counts
    state.json           which pulled sources are enabled
    status.json          the last pull, so the interface can show progress

The API switches rulesets on and off and removes them. A pull runs in the worker,
the one container with an outbound route, and is the only one that downloads.

**Rulesets are untrusted input.** They are text that a YARA compiler parses, so
the risk is resource use rather than code execution, and it is bounded: the
download has a size cap, the archive a file count and an expanded-size cap, a
single rule file a size cap, and member names are never used as paths. A file
that does not compile is left out and reported, so one broken rule from a
community pack cannot disable the rest.
"""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import re
import shutil
import tempfile
import threading
import zipfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.core import http_client
from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)

RULE_SUFFIXES = (".yar", ".yara")
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_EXPANDED_BYTES = 128 * 1024 * 1024
MAX_RULE_FILE_BYTES = 8 * 1024 * 1024
MAX_RULE_FILES = 5000

# Many community rules read these to scope a match; compiling without them
# declared rejects the file, so they are declared empty and a scan ignores them.
EXTERNALS = {
    "filename": "",
    "filepath": "",
    "extension": "",
    "filetype": "",
    "owner": "",
}

_SAFE_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{1,39}$")
_lock = threading.RLock()


@dataclass(frozen=True)
class RuleSource:
    """A public ruleset an administrator can pull."""

    id: str
    label: str
    url: str
    # Only members under this prefix of the archive are taken.
    include_prefix: str
    homepage: str
    licence: str
    description: str


# Archives are fetched from GitHub's codeload by branch, so a pull takes the
# current state. The digest of what was fetched is recorded with every pull,
# which is what makes a later change to a ruleset visible.
SOURCES: tuple[RuleSource, ...] = (
    RuleSource(
        id="signature-base",
        label="Neo23x0 signature-base",
        url="https://codeload.github.com/Neo23x0/signature-base/zip/refs/heads/master",
        include_prefix="signature-base-master/yara/",
        homepage="https://github.com/Neo23x0/signature-base",
        licence="Detection Rule License 1.1 (check before commercial use)",
        description="Florian Roth's maintained rules for malware, webshells and tooling.",
    ),
    RuleSource(
        id="elastic",
        label="Elastic protections-artifacts",
        url="https://codeload.github.com/elastic/protections-artifacts/zip/refs/heads/main",
        include_prefix="protections-artifacts-main/yara/rules/",
        homepage="https://github.com/elastic/protections-artifacts",
        licence="Elastic License 2.0 (check before commercial use)",
        description="Elastic Security's endpoint YARA rules.",
    ),
    RuleSource(
        id="yara-rules",
        label="Yara-Rules community",
        url="https://codeload.github.com/Yara-Rules/rules/zip/refs/heads/master",
        include_prefix="rules-master/",
        homepage="https://github.com/Yara-Rules/rules",
        licence="GPL-2.0",
        description="Large community collection; some files are old and may not compile.",
    ),
)


class PullError(Exception):
    """A pull that could not complete, with something an administrator can act on."""


def source_by_id(source_id: str) -> RuleSource | None:
    return next((item for item in SOURCES if item.id == source_id), None)


def rules_root() -> Path:
    return Path(get_settings().yara_rules_dir)


def custom_dir() -> Path:
    return rules_root() / "custom"


def sources_dir() -> Path:
    return rules_root() / "sources"


# -- state -------------------------------------------------------------------


def _read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".partial")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    temporary.replace(path)


def enabled_sources() -> set[str]:
    raw = _read_json(rules_root() / "state.json").get("enabled")
    return {str(item) for item in raw} if isinstance(raw, list) else set()


def set_enabled(source_id: str, enabled: bool) -> None:
    with _lock:
        current = enabled_sources()
        if enabled:
            current.add(source_id)
        else:
            current.discard(source_id)
        _write_json(rules_root() / "state.json", {"enabled": sorted(current)})


def read_status() -> dict[str, Any]:
    return _read_json(rules_root() / "status.json")


def write_status(**fields: Any) -> None:
    _write_json(rules_root() / "status.json", fields)


def _rule_files(directory: Path) -> list[Path]:
    if not directory.is_dir():
        return []
    return sorted(
        path
        for path in directory.rglob("*")
        if path.suffix.lower() in RULE_SUFFIXES and path.is_file() and not path.is_symlink()
    )


def overview() -> dict[str, Any]:
    """What the interface shows: the mount point, each source, the last pull."""
    settings = get_settings()
    enabled = enabled_sources()
    sources = []
    for source in SOURCES:
        meta = _read_json(sources_dir() / f"{source.id}.json")
        sources.append(
            {
                "id": source.id,
                "label": source.label,
                "description": source.description,
                "homepage": source.homepage,
                "licence": source.licence,
                "url": source.url,
                "pulled": bool(meta),
                "enabled": source.id in enabled,
                "pulled_at": meta.get("pulled_at"),
                "archive_sha256": meta.get("archive_sha256"),
                "files": meta.get("files", 0),
                "rejected": meta.get("rejected", []),
            }
        )
    return {
        "directory": str(rules_root()),
        "custom_directory": str(custom_dir()),
        "custom_files": len(_rule_files(custom_dir())),
        "pull_enabled": settings.yara_pull_enabled,
        "status": read_status(),
        "sources": sources,
    }


# -- pulling -----------------------------------------------------------------


def extract_rules(payload: bytes, source: RuleSource, target: Path) -> tuple[int, list[str]]:
    """Write the rule files of an archive into `target`; return (kept, rejected).

    Member names are only used to select (`include_prefix`) and are never turned
    into paths: each kept file is stored under an index and a sanitised name, so
    a name like `../../x` cannot escape `target`.
    """
    try:
        archive = zipfile.ZipFile(io.BytesIO(payload))
    except zipfile.BadZipFile as exc:
        raise PullError("The download is not a valid zip archive.") from exc

    rejected: list[str] = []
    kept = 0
    expanded = 0
    with archive:
        for info in archive.infolist():
            name = info.filename
            if info.is_dir() or not name.startswith(source.include_prefix):
                continue
            if not name.lower().endswith(RULE_SUFFIXES):
                continue
            if kept >= MAX_RULE_FILES:
                rejected.append(f"{name}: more than {MAX_RULE_FILES} rule files, rest skipped")
                break
            if info.file_size > MAX_RULE_FILE_BYTES:
                rejected.append(f"{name}: larger than {MAX_RULE_FILE_BYTES // (1024 * 1024)} MiB")
                continue
            expanded += info.file_size
            if expanded > MAX_EXPANDED_BYTES:
                raise PullError("The archive expands past the size limit; nothing was installed.")
            with archive.open(info) as handle:
                data = handle.read(MAX_RULE_FILE_BYTES + 1)
            if len(data) > MAX_RULE_FILE_BYTES:
                rejected.append(f"{name}: larger than its declared size")
                continue
            safe = re.sub(r"[^A-Za-z0-9._-]", "_", Path(name).name)[:100]
            (target / f"{kept:05d}_{safe}").write_bytes(data)
            kept += 1
    return kept, rejected


async def pull(source_id: str) -> dict[str, Any]:
    """Download one ruleset and install it atomically. Runs in the worker."""
    settings = get_settings()
    source = source_by_id(source_id)
    if source is None:
        raise PullError(f"Unknown ruleset '{source_id}'.")
    if not settings.yara_pull_enabled:
        raise PullError("Pulling rulesets is disabled on this instance.")

    fetched = await http_client.get_bytes(source.url, timeout=120.0, max_bytes=MAX_ARCHIVE_BYTES)
    if fetched is None:
        raise PullError(
            "The ruleset could not be downloaded (unreachable, refused, or over "
            f"{MAX_ARCHIVE_BYTES // (1024 * 1024)} MiB)."
        )
    payload, _content_type = fetched
    meta = await asyncio.to_thread(_install, payload, source)
    set_enabled(source.id, True)
    logger.info(
        "yara_ruleset_pulled", source=source.id, files=meta["files"], sha256=meta["archive_sha256"]
    )
    return meta


def _install(payload: bytes, source: RuleSource) -> dict[str, Any]:
    """Unpack, validate and swap in a downloaded archive. Blocking: run off the loop."""
    digest = hashlib.sha256(payload).hexdigest()
    sources_dir().mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{source.id}-", dir=sources_dir()))
    try:
        kept, rejected = extract_rules(payload, source, staging)
        if kept == 0:
            raise PullError("The archive held no rule files under the expected folder.")
        usable, broken = validate_directory(staging)
        rejected.extend(broken)
        final = sources_dir() / source.id
        with _lock:
            old = sources_dir() / f".{source.id}.old"
            shutil.rmtree(old, ignore_errors=True)
            if final.exists():
                final.replace(old)
            staging.replace(final)
            shutil.rmtree(old, ignore_errors=True)
            meta = {
                "id": source.id,
                "url": source.url,
                "archive_sha256": digest,
                "archive_bytes": len(payload),
                "pulled_at": datetime.now(UTC).isoformat(),
                "files": kept,
                "compiled": usable,
                "rejected": rejected[:100],
            }
            _write_json(sources_dir() / f"{source.id}.json", meta)
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    return meta


def remove_source(source_id: str) -> None:
    if not _SAFE_ID.match(source_id) or source_by_id(source_id) is None:
        raise PullError(f"Unknown ruleset '{source_id}'.")
    with _lock:
        shutil.rmtree(sources_dir() / source_id, ignore_errors=True)
        (sources_dir() / f"{source_id}.json").unlink(missing_ok=True)
        set_enabled(source_id, False)


# -- compiling ---------------------------------------------------------------


def get_yara() -> Any:
    import yara

    return yara


def validate_directory(directory: Path) -> tuple[int, list[str]]:
    """Compile each file on its own; return (usable count, problems)."""
    yara = get_yara()
    usable = 0
    problems: list[str] = []
    for path in _rule_files(directory):
        try:
            yara.compile(filepath=str(path), externals=EXTERNALS)
            usable += 1
        except yara.Error as exc:
            problems.append(f"{path.name}: {str(exc)[:160]}")
    return usable, problems


@dataclass
class CompiledRules:
    rules: Any | None
    files: int
    problems: list[str] = field(default_factory=list)
    fingerprint: str = ""


_cache: CompiledRules | None = None


def _selected_files() -> list[tuple[str, Path]]:
    selected = [(f"custom_{index}", path) for index, path in enumerate(_rule_files(custom_dir()))]
    for source in SOURCES:
        if source.id in enabled_sources():
            base = sources_dir() / source.id
            selected += [
                (f"{source.id.replace('-', '_')}_{index}", path)
                for index, path in enumerate(_rule_files(base))
            ]
    return selected


def _fingerprint(files: list[tuple[str, Path]]) -> str:
    digest = hashlib.sha256()
    for namespace, path in files:
        try:
            stat = path.stat()
        except OSError:
            continue
        digest.update(f"{namespace}|{path}|{stat.st_mtime_ns}|{stat.st_size}\n".encode())
    return digest.hexdigest()


def load() -> CompiledRules:
    """The compiled ruleset, rebuilt only when a file changed.

    Each file is compiled on its own first, and only the ones that compile are
    combined, so a rule that does not parse is reported instead of taking the
    whole scan down.
    """
    global _cache
    files = _selected_files()
    fingerprint = _fingerprint(files)
    with _lock:
        if _cache is not None and _cache.fingerprint == fingerprint:
            return _cache
        yara = get_yara()
        good: dict[str, str] = {}
        problems: list[str] = []
        for namespace, path in files:
            try:
                yara.compile(filepath=str(path), externals=EXTERNALS)
                good[namespace] = str(path)
            except yara.Error as exc:
                problems.append(f"{path.name}: {str(exc)[:160]}")
        rules = None
        if good:
            try:
                rules = yara.compile(filepaths=good, externals=EXTERNALS)
            except yara.Error as exc:
                problems.append(f"combined ruleset: {str(exc)[:160]}")
                good = {}
        _cache = CompiledRules(
            rules=rules, files=len(good), problems=problems[:50], fingerprint=fingerprint
        )
        return _cache


def reset_cache() -> None:
    global _cache
    with _lock:
        _cache = None
