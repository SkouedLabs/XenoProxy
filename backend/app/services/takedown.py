"""Abuse-report drafts for registrars and hosting providers. Drafts only: nothing is sent.

The draft is plain text for an analyst to read, edit and send through their own channel.
Nothing here contacts a registrar or a host, and the abuse contact is a placeholder, so no
WHOIS or RDAP lookup is made.

What a draft discloses is the evidence in it, so the rules are strict:
- Only GREEN and CLEAR jobs produce a draft. AMBER limits sharing to the organisation, and an
  abuse report goes to a third party; RED never leaves the deployment.
- Only IP, domain and URL observables are reportable.
- Evidence is the plugin headlines of the job, with newlines and control characters removed
  and each line capped, so a stored value cannot forge extra lines of the report.
- The analyst's name is not written in; the sender block is left for them to fill in.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime

from app.models.job import ObservableType, Tlp, Verdict

REPORTABLE = frozenset({ObservableType.IP, ObservableType.DOMAIN, ObservableType.URL})
DRAFTABLE_TLPS = frozenset({Tlp.CLEAR, Tlp.GREEN})
RECIPIENTS = {
    "registrar": "the domain registrar",
    "hosting": "the hosting provider",
}
_CONTROL = re.compile(r"[\x00-\x1f\x7f]+")
_MAX_LINE = 200


@dataclass(frozen=True)
class Evidence:
    plugin: str
    headline: str


def _clean(text: str) -> str:
    return _CONTROL.sub(" ", text).strip()[:_MAX_LINE]


def render_draft(
    *,
    value: str,
    observable_type: ObservableType,
    verdict: Verdict,
    first_seen: datetime,
    evidence: list[Evidence],
    recipient: str,
) -> str:
    kind = observable_type.value
    who = RECIPIENTS[recipient]
    lines = [
        "DRAFT - NOT SENT. Review before sending.",
        "",
        f"To: [abuse contact for {who}; look it up yourself via WHOIS/RDAP]",
        f"Subject: Abuse report: {kind} {_clean(value)} used for malicious activity",
        "",
        "Hello,",
        "",
        f"We are reporting the following {kind} for activity we assess as {verdict.value}:",
        "",
        f"  Observable: {_clean(value)} ({kind})",
        f"  First observed: {first_seen.date().isoformat()}",
        "",
        "Evidence:",
    ]
    if evidence:
        lines += [f"  - [{_clean(item.plugin)}] {_clean(item.headline)}" for item in evidence]
    else:
        lines.append("  - (no analyser produced a headline for this observable)")
    lines += [
        "",
        "Please investigate and take the action your terms of service allow. We are glad to",
        "provide the full evidence through a secure channel on request.",
        "",
        "Regards,",
        "[Name, organisation, contact details]",
        "",
    ]
    return "\n".join(lines)
