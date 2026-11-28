"""Xeno-Score: weighting, normalisation and the cases where no score exists."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from app.models.job import PluginKind, ReportStatus
from app.services.xeno_score import compute


def _report(
    name: str,
    verdict: str | None,
    *,
    status: ReportStatus = ReportStatus.SUCCESS,
    kind: PluginKind = PluginKind.ANALYZER,
) -> Any:
    summary = {"verdict": verdict} if verdict else {}
    return SimpleNamespace(plugin_name=name, plugin_type=kind, status=status, summary_data=summary)


def test_weights_are_normalised_over_the_sources_that_answered() -> None:
    result = compute([_report("virustotal", "malicious"), _report("abuseipdb", "clean")])
    # (40 * 100 + 20 * 0) / 60
    assert result.score == 67


def test_unknown_and_failed_sources_are_left_out_not_counted_as_zero() -> None:
    result = compute(
        [
            _report("virustotal", "malicious"),
            _report("otx", "unknown"),
            _report("greynoise", "clean", status=ReportStatus.FAILED),
        ]
    )
    assert result.score == 100
    assert result.as_dict()["sources_scored"] == 1
    assert result.as_dict()["sources_considered"] == 3
    assert result.as_dict()["unscored"] == ["greynoise", "otx"]


def test_no_definite_verdict_gives_no_score() -> None:
    result = compute([_report("otx", "unknown")])
    assert result.score is None
    assert compute([]).score is None


def test_unlisted_analyzers_get_the_default_weight() -> None:
    result = compute([_report("urlscan", "suspicious"), _report("phishstats", "malicious")])
    assert result.score == 75


def test_non_analyzer_reports_are_ignored() -> None:
    result = compute(
        [_report("virustotal", "clean"), _report("opencti", "malicious", kind=PluginKind.CONNECTOR)]
    )
    assert result.score == 0
    assert result.as_dict()["sources_considered"] == 1


def test_score_is_flagged_alpha() -> None:
    assert compute([_report("virustotal", "clean")]).as_dict()["alpha"] is True
