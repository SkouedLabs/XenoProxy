"""Takedown drafts: the rendering and its safety rules. Nothing is sent by any of this."""

from __future__ import annotations

from datetime import UTC, datetime

from app.models.job import ObservableType, Verdict
from app.services.takedown import REPORTABLE, Evidence, render_draft

_WHEN = datetime(2026, 11, 1, tzinfo=UTC)


def _draft(**overrides: object) -> str:
    args: dict[str, object] = {
        "value": "evil.example.com",
        "observable_type": ObservableType.DOMAIN,
        "verdict": Verdict.MALICIOUS,
        "first_seen": _WHEN,
        "evidence": [Evidence("virustotal", "4 engines flag it as phishing.")],
        "recipient": "registrar",
    }
    args.update(overrides)
    return render_draft(**args)  # type: ignore[arg-type]


def test_a_draft_is_marked_not_sent_and_leaves_the_contact_to_the_analyst() -> None:
    text = _draft()
    assert text.startswith("DRAFT - NOT SENT.")
    assert "[abuse contact for the domain registrar" in text
    assert "[Name, organisation, contact details]" in text


def test_the_evidence_is_listed_with_its_analyser() -> None:
    text = _draft()
    assert "  - [virustotal] 4 engines flag it as phishing." in text
    assert "First observed: 2026-11-01" in text


def test_a_headline_cannot_forge_lines_in_the_report() -> None:
    text = _draft(evidence=[Evidence("dns", "fine\nSubject: forged\r\n\x00Regards, the CEO")])
    assert "\nSubject: forged" not in text
    assert "  - [dns] fine Subject: forged Regards, the CEO" in text


def test_a_job_with_no_headline_says_so() -> None:
    assert "(no analyser produced a headline" in _draft(evidence=[])


def test_only_network_observables_are_reportable() -> None:
    assert {ObservableType.IP, ObservableType.DOMAIN, ObservableType.URL} == REPORTABLE
    assert ObservableType.HASH not in REPORTABLE
    assert ObservableType.CRYPTO not in REPORTABLE
