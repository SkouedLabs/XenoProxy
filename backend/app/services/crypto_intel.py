"""Local sanctions designations for crypto addresses.

The lists are files an administrator places in `Settings.crypto_intel_dir`. Nothing is
downloaded here: the analyzer runs in the same container as the scanner and has no reason
to reach out. Accepted files:

- `*.txt`, `*.csv`: one address per line, optionally followed by a comma and a label.
  Lines starting with `#` are comments. A header line is ignored when it has no address.
- `*.xml`: the OFAC Specially Designated Nationals (SDN) XML, read for its
  "Digital Currency Address" identifiers and the name of the designated party.

Each file has a size cap and the total number of addresses is capped, so a hostile or
broken list cannot exhaust memory. The parsed index is cached by file name, size and mtime.

This is a designation check. It says whether an address is on the list that was loaded.
It does not follow transactions, so it is not taint analysis in the chain-analytics sense.
"""

from __future__ import annotations

import csv
import hashlib
import io
import re
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from defusedxml import ElementTree as ET

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)

MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_ADDRESSES = 500_000
_ADDRESS_RE = re.compile(
    r"^(0x[0-9a-fA-F]{40}|[13][1-9A-HJ-NP-Za-km-z]{25,34}|bc1[02-9ac-hj-np-z]{11,71})$"
)
_MIXER_WORDS = ("tornado", "mixer", "blender", "coinjoin")
_lock = threading.Lock()
_cache: dict[tuple, Snapshot] = {}


@dataclass(frozen=True)
class Designation:
    address: str
    label: str
    source: str


@dataclass(frozen=True)
class Snapshot:
    designations: dict[str, Designation] = field(default_factory=dict)
    sources: tuple[tuple[str, str], ...] = ()  # (file name, sha256)

    @property
    def count(self) -> int:
        return len(self.designations)

    def lookup(self, address: str) -> Designation | None:
        return self.designations.get(_key(address))


def _key(address: str) -> str:
    """Ethereum addresses are case-insensitive hex; Bitcoin addresses are case-sensitive."""
    return address.lower() if address.lower().startswith("0x") else address


def is_mixer(label: str) -> bool:
    lowered = label.lower()
    return any(word in lowered for word in _MIXER_WORDS)


def _from_plain(text: str, source: str, into: dict[str, Designation]) -> None:
    for row in csv.reader(io.StringIO(text)):
        if not row or not row[0].strip() or row[0].lstrip().startswith("#"):
            continue
        address = row[0].strip()
        if not _ADDRESS_RE.match(address):
            continue  # header lines and anything that is not an address
        label = row[1].strip() if len(row) > 1 else ""
        into.setdefault(_key(address), Designation(address, label or "listed", source))
        if len(into) >= MAX_ADDRESSES:
            return


def _from_sdn(payload: bytes, source: str, into: dict[str, Designation]) -> None:
    root = ET.fromstring(payload)
    for entry in root.iter():
        if not entry.tag.endswith("sdnEntry"):
            continue
        name = " ".join(
            part
            for part in (
                _child_text(entry, "firstName"),
                _child_text(entry, "lastName"),
            )
            if part
        )
        for identifier in entry.iter():
            if not identifier.tag.endswith("id"):
                continue
            id_type = _child_text(identifier, "idType")
            number = _child_text(identifier, "idNumber")
            if "Digital Currency Address" not in id_type or not number:
                continue
            if not _ADDRESS_RE.match(number):
                continue
            label = name or "SDN entry"
            into.setdefault(_key(number), Designation(number, label, source))
            if len(into) >= MAX_ADDRESSES:
                return


def _child_text(element: Any, local: str) -> str:
    for child in element:
        if child.tag.endswith(local):
            return (child.text or "").strip()
    return ""


def _fingerprint(directory: Path) -> tuple[tuple, ...]:
    if not directory.is_dir():
        return ()
    items = []
    for path in sorted(directory.iterdir()):
        if path.is_file() and path.suffix.lower() in {".txt", ".csv", ".xml"}:
            stat = path.stat()
            items.append((path.name, stat.st_size, stat.st_mtime_ns))
    return tuple(items)


def snapshot(directory: str | None = None) -> Snapshot:
    """Load every list in the directory; reuse the cached index while files are unchanged."""
    root = Path(directory or get_settings().crypto_intel_dir)
    key = (str(root), _fingerprint(root))
    with _lock:
        cached = _cache.get(key)
        if cached is not None:
            return cached
        designations: dict[str, Designation] = {}
        sources: list[tuple[str, str]] = []
        for path in sorted(root.iterdir()) if root.is_dir() else []:
            if not path.is_file() or path.suffix.lower() not in {".txt", ".csv", ".xml"}:
                continue
            if path.stat().st_size > MAX_FILE_BYTES:
                logger.warning("crypto_list_too_large", file=path.name)
                continue
            payload = path.read_bytes()
            sources.append((path.name, hashlib.sha256(payload).hexdigest()))
            try:
                if path.suffix.lower() == ".xml":
                    _from_sdn(payload, path.name, designations)
                else:
                    _from_plain(payload.decode("utf-8", errors="replace"), path.name, designations)
            except ET.ParseError:
                logger.warning("crypto_list_unreadable", file=path.name)
        result = Snapshot(designations=designations, sources=tuple(sources))
        _cache.clear()
        _cache[key] = result
        return result
