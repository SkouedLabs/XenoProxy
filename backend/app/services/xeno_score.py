"""Xeno-Score: one weighted 0-100 number over the analyzers that answered.

This is a second opinion stored beside the job verdict, never a replacement for
it. The verdict is a rule an analyst can check (the worst verdict any source
reported); the score is an average that a single loud source cannot dominate,
which is the point of weighting. Both are shown, and the score states how many
sources it actually covered, so a 0 built from one quiet provider is not read as
an exoneration.

Only analyzer reports that succeeded and carried a definite verdict take part.
An `unknown` verdict means the source had nothing to say, so it is left out of
the average rather than counted as a zero. Weights are normalised over the
sources that took part, so the score is always on the 0-100 scale.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from app.models.job import PluginKind, PluginReport, ReportStatus

METHOD = "weighted-verdict-v1"

# Share of the score each analyzer carries when present. Anything not listed
# gets DEFAULT_WEIGHT, so a new analyzer counts without a code change here.
WEIGHTS: dict[str, float] = {
    "virustotal": 40.0,
    "abuseipdb": 20.0,
}
DEFAULT_WEIGHT = 10.0

# What each verdict is worth on the 0-100 scale.
POINTS: dict[str, float] = {
    "clean": 0.0,
    "suspicious": 50.0,
    "malicious": 100.0,
}


@dataclass
class Contribution:
    plugin: str
    verdict: str
    weight: float
    points: float

    def as_dict(self) -> dict[str, Any]:
        return {
            "plugin": self.plugin,
            "verdict": self.verdict,
            "weight": self.weight,
            "points": self.points,
        }


@dataclass
class XenoScore:
    score: int | None
    method: str
    contributions: list[Contribution] = field(default_factory=list)
    considered: int = 0
    unscored: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "method": self.method,
            "alpha": True,
            "sources_scored": len(self.contributions),
            "sources_considered": self.considered,
            "contributions": [entry.as_dict() for entry in self.contributions],
            "unscored": sorted(self.unscored),
        }


def compute(reports: Sequence[PluginReport]) -> XenoScore:
    """Weighted average of verdict points over the analyzers that gave a verdict.

    Returns `score=None` when no analyzer gave a definite verdict: no answer is
    not the same as a score of zero.
    """
    analyzers = [report for report in reports if report.plugin_type is PluginKind.ANALYZER]
    considered = len(analyzers)
    contributions: list[Contribution] = []
    unscored: list[str] = []

    for report in analyzers:
        raw = (report.summary_data or {}).get("verdict")
        if report.status is not ReportStatus.SUCCESS or raw not in POINTS:
            unscored.append(report.plugin_name)
            continue
        weight = WEIGHTS.get(report.plugin_name, DEFAULT_WEIGHT)
        contributions.append(
            Contribution(
                plugin=report.plugin_name,
                verdict=str(raw),
                weight=weight,
                points=POINTS[str(raw)],
            )
        )

    if not contributions:
        return XenoScore(score=None, method=METHOD, considered=considered, unscored=unscored)

    total_weight = sum(entry.weight for entry in contributions)
    weighted = sum(entry.weight * entry.points for entry in contributions)
    score = round(weighted / total_weight)
    return XenoScore(
        score=max(0, min(100, score)),
        method=METHOD,
        contributions=contributions,
        considered=considered,
        unscored=unscored,
    )
