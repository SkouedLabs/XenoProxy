"""Blocklist feeds: what may leave, what is never listed, and the rendered format."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.models.job import ObservableType, Tlp, Verdict
from app.services.blocklist import Candidate, build_entries, normalise_domain, normalise_ip, render

_NOW = datetime(2026, 11, 28, tzinfo=UTC)


def _c(
    value: str,
    kind: ObservableType = ObservableType.IP,
    verdict: Verdict = Verdict.MALICIOUS,
    tlp: Tlp = Tlp.AMBER,
) -> Candidate:
    return Candidate(value, kind, verdict, tlp, _NOW)


def test_malicious_public_ips_are_listed_sorted_and_unique() -> None:
    entries, omitted = build_entries([_c("8.8.8.8"), _c("1.1.1.1"), _c("8.8.8.8")], "ip")
    assert entries == ["1.1.1.1", "8.8.8.8"]
    assert omitted == 0


@pytest.mark.parametrize(
    "value", ["10.0.0.5", "192.168.1.1", "127.0.0.1", "169.254.1.1", "224.0.0.1"]
)
def test_private_loopback_and_multicast_addresses_are_never_listed(value: str) -> None:
    assert normalise_ip(value) is None
    assert build_entries([_c(value)], "ip")[0] == []


def test_suspicious_is_excluded_unless_asked_for() -> None:
    candidates = [_c("8.8.4.4", verdict=Verdict.SUSPICIOUS)]
    assert build_entries(candidates, "ip")[0] == []
    assert build_entries(candidates, "ip", "suspicious")[0] == ["8.8.4.4"]


def test_red_and_unknown_are_never_listed() -> None:
    assert build_entries([_c("8.8.8.8", tlp=Tlp.RED)], "ip")[0] == []
    assert build_entries([_c("1.1.1.1", verdict=Verdict.CLEAN)], "ip")[0] == []


def test_a_value_with_a_newline_cannot_inject_rules() -> None:
    assert normalise_domain("evil.example.com\nallow any") is None
    assert normalise_ip("8.8.8.8\n0.0.0.0/0") is None


def test_domains_are_lowercased_and_internal_suffixes_dropped() -> None:
    assert normalise_domain("Bad-Site.Example.ORG.") == "bad-site.example.org"
    assert normalise_domain("printer.internal") is None
    assert normalise_domain("nas.lan") is None
    assert normalise_domain("1.2.3.4") is None
    assert normalise_domain("-bad.example.com") is None


def test_only_matching_observable_types_are_taken() -> None:
    candidates = [_c("evil.example.com", ObservableType.DOMAIN), _c("8.8.8.8")]
    assert build_entries(candidates, "domain")[0] == ["evil.example.com"]
    assert build_entries(candidates, "ip")[0] == ["8.8.8.8"]


def test_the_cap_is_applied_and_the_omitted_count_reported() -> None:
    candidates = [_c(f"evil{i}.example.com", ObservableType.DOMAIN) for i in range(5_003)]
    entries, omitted = build_entries(candidates, "domain")
    assert len(entries) == 5_000
    assert omitted == 3


def test_rendered_file_has_a_comment_header_and_one_entry_per_line() -> None:
    body = render(["1.1.1.1", "8.8.8.8"], "ip", "malicious", 0, _NOW)
    lines = body.splitlines()
    assert lines[0].startswith("# XenoProxy blocklist: ip")
    assert "omitted by the 50000 cap: 0" in lines[2]
    assert lines[3:] == ["1.1.1.1", "8.8.8.8"]
    assert body.endswith("\n")


def test_an_empty_list_still_renders_a_valid_header() -> None:
    body = render([], "domain", "malicious", 0, _NOW)
    assert body.splitlines()[-1].startswith("# entries: 0")
