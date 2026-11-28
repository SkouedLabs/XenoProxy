"""Plain-text blocklists for firewalls and EDR tooling, built from stored verdicts.

One entry per line, `#` comment header. The format is the common denominator of
pfSense URL aliases and Palo Alto External Dynamic Lists: a text file with one IP or
one domain per line. CrowdStrike and other EDRs need their own API and are not
covered here.

Safety rules, applied before anything is written:
- Only malicious verdicts by default; suspicious ones are an explicit opt-in.
- Only jobs at TLP CLEAR, GREEN or AMBER leave the database. RED never does.
- Private, loopback, link-local, multicast and reserved addresses are never listed,
  so an internal host that once got a verdict cannot be blocked by mistake.
- Internal-only domain suffixes (.local, .internal, ...) are never listed.
- Every value is validated against a strict pattern, so a value cannot carry a
  newline and inject extra rules.
- Lists are capped at the entry limits of the common consumers; the omitted count is
  stated in the header rather than dropped silently.

Verified with synthetic candidates only. Not loaded into a live pfSense or Palo Alto.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime

from app.models.job import ObservableType, Tlp, Verdict

# Palo Alto EDL: 50,000 IPs, 5,000 domains per list. pfSense aliases are not
# bounded this tightly, so the same caps keep one feed usable on every device.
MAX_ENTRIES = {"ip": 50_000, "domain": 5_000}
EXPORT_TLPS = frozenset({Tlp.CLEAR, Tlp.GREEN, Tlp.AMBER})
ALLOWED_VERDICTS = {
    "malicious": frozenset({Verdict.MALICIOUS}),
    "suspicious": frozenset({Verdict.SUSPICIOUS, Verdict.MALICIOUS}),
}
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_INTERNAL_SUFFIXES = (
    ".local",
    ".localhost",
    ".internal",
    ".lan",
    ".home.arpa",
    ".test",
    ".invalid",
    ".example",
    ".onion",
)


@dataclass(frozen=True)
class Candidate:
    """One stored job, reduced to the fields a blocklist needs."""

    value: str
    observable_type: ObservableType
    verdict: Verdict
    tlp: Tlp
    created_at: datetime


def normalise_ip(value: str) -> str | None:
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    if not address.is_global or address.is_private or address.is_multicast:
        return None
    return str(address)


def normalise_domain(value: str) -> str | None:
    name = value.strip().lower().rstrip(".")
    if not name or len(name) > 253 or "." not in name:
        return None
    labels = name.split(".")
    if not all(_LABEL.match(label) for label in labels):
        return None
    if not re.search(r"[a-z]", labels[-1]):  # a TLD has a letter; rejects bare IPv4 strings
        return None
    if name.endswith(_INTERNAL_SUFFIXES):
        return None
    return name


def build_entries(
    candidates: Iterable[Candidate], kind: str, min_verdict: str = "malicious"
) -> tuple[list[str], int]:
    """Return the sorted, de-duplicated entries and how many were omitted by the cap."""
    if kind not in MAX_ENTRIES:
        raise ValueError(f"Unknown blocklist kind: {kind}")
    wanted_type = ObservableType(kind)
    allowed = ALLOWED_VERDICTS[min_verdict]
    normalise = normalise_ip if kind == "ip" else normalise_domain

    values: set[str] = set()
    for candidate in candidates:
        if candidate.observable_type is not wanted_type:
            continue
        if candidate.verdict not in allowed or candidate.tlp not in EXPORT_TLPS:
            continue
        value = normalise(candidate.value)
        if value is not None:
            values.add(value)

    ordered = sorted(values)
    cap = MAX_ENTRIES[kind]
    return ordered[:cap], max(0, len(ordered) - cap)


def render(
    entries: list[str], kind: str, min_verdict: str, omitted: int, generated_at: datetime
) -> str:
    header = [
        f"# XenoProxy blocklist: {kind} ({min_verdict} and above)",
        f"# generated {generated_at.isoformat(timespec='seconds')}",
        f"# entries: {len(entries)}; omitted by the {MAX_ENTRIES[kind]} cap: {omitted}",
    ]
    body = "\n".join(entries)
    return "\n".join(header) + ("\n" + body if body else "") + "\n"
