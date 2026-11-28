"""Triage (Hatching): behavioural signatures and a score from existing sandbox runs.

Triage runs a sample in a sandbox and scores what it did. This analyzer reads
the sandbox results Triage already holds for a SHA-256. It never submits a
sample: a submission is published on the public service, and detonation is a
decision an analyst takes on purpose.

A quiet run is not evidence of a clean sample (sandboxes miss evasive code), so
a low score is Unknown, never Clean.

Contract note: exercised against mocks only. Not yet run against the live API.
"""

from __future__ import annotations

from typing import Any, ClassVar

from app.core import http_client
from app.models.job import ObservableType, Tlp, Verdict
from app.plugins.base.analyzer import BaseAnalyzer
from app.plugins.base.plugin import (
    PluginQuotaError,
    PluginResult,
    PluginSummary,
    ProviderInfo,
    SecretSpec,
)
from app.plugins.base.registry import register
from app.services.observables import Observable

BASE = "https://tria.ge/api/v0"
# Triage scores run 0 to 10; the summary scale is 0 to 100.
_MALICIOUS_AT = 7
_SUSPICIOUS_AT = 4


def _score_verdict(score: int | None) -> Verdict:
    if score is None:
        return Verdict.UNKNOWN
    if score >= _MALICIOUS_AT:
        return Verdict.MALICIOUS
    if score >= _SUSPICIOUS_AT:
        return Verdict.SUSPICIOUS
    return Verdict.UNKNOWN


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return int(value)


def _as_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, list):
        return [str(entry) for entry in value if entry]
    return []


@register
class TriageAnalyzer(BaseAnalyzer):
    """Triage's sandbox score, signatures and families for a sample, when it has run one."""

    name = "triage"
    label = "Triage (Hatching)"
    description = "Behavioural score, signatures and families from Triage's existing sandbox runs."
    supported_types: ClassVar[tuple[ObservableType, ...]] = (
        ObservableType.HASH,
        ObservableType.FILE,
    )
    secrets: ClassVar[tuple[SecretSpec, ...]] = (
        SecretSpec(
            "api_key",
            "API token",
            help_text="From your Triage profile, under API tokens.",
            placeholder="from tria.ge",
            user_overridable=True,
        ),
    )
    provider = ProviderInfo(
        name="Triage (Hatching)",
        url="https://tria.ge/",
        api_base_url="https://tria.ge/api/v0/search",
        credential_url="https://tria.ge/",
        free_tier="Free accounts are available; the quota is set by the plan.",
        rate_limit="Per plan.",
        notes=(
            "Reads existing sandbox results by SHA-256 only. It never submits: a submission is "
            "published on the public service."
        ),
    )
    max_tlp = Tlp.AMBER
    default_timeout = 45
    default_cache_ttl = 86400
    documentation_url = "https://tria.ge/docs/"
    maturity = "alpha"

    async def run(self, observable: Observable) -> PluginResult:
        if len(observable.value) != 64 or observable.hash_algorithm not in {"sha256", None}:
            return self.skipped("Triage is queried by SHA-256; this observable is another hash.")

        headers = {
            "Authorization": f"Bearer {self.secret('api_key')}",
            "Accept": "application/json",
        }
        response = await http_client.get(
            f"{BASE}/search",
            params={"query": f"sha256:{observable.value}"},
            headers=headers,
            timeout=self.timeout,
        )
        if response.status_code == 429:
            raise PluginQuotaError("Triage returned HTTP 429.")
        if response.status_code in (401, 403):
            raise PluginQuotaError("Triage rejected the configured API token.")
        if not response.ok:
            return self.provider_http_error(response.status_code)

        search = response.json_body if isinstance(response.json_body, dict) else {}
        samples = [
            entry
            for entry in search.get("data") or []
            if isinstance(entry, dict) and entry.get("id")
        ]
        if not samples:
            return self.not_found("Triage has no sandbox run for this sample.")

        # The run with the highest score is the most informative; a run that saw
        # nothing does not outvote one that saw the behaviour.
        best = max(samples, key=lambda entry: _as_int(entry.get("score")) or 0)
        sample_id = str(best["id"])

        summary_response = await http_client.get(
            f"{BASE}/samples/{sample_id}/summary",
            headers=headers,
            timeout=self.timeout,
        )
        if summary_response.status_code == 429:
            raise PluginQuotaError("Triage returned HTTP 429.")
        if not summary_response.ok:
            return self.provider_http_error(summary_response.status_code)

        body: dict[str, Any] = (
            summary_response.json_body if isinstance(summary_response.json_body, dict) else {}
        )
        raw_score = _as_int(body.get("score"))
        score = raw_score if raw_score is not None else _as_int(best.get("score"))
        families = _as_list(body.get("family"))
        signatures = [
            str(entry.get("name") or "")
            for entry in body.get("signatures") or []
            if isinstance(entry, dict) and entry.get("name")
        ]
        verdict = _score_verdict(score)

        headline = f"Triage score {score if score is not None else 'n/a'} out of 10"
        if families:
            headline += f" ({', '.join(families[:3])})"

        return self.ok(
            body,
            PluginSummary(
                verdict=verdict,
                score=score * 10 if score is not None else None,
                tags=[tag for tag in (*families[:5], *signatures[:8]) if tag],
                headline=headline,
                links=[{"label": "Open the run", "url": f"https://tria.ge/{sample_id}"}],
                extra={
                    "triage_score": score,
                    "families": families[:20],
                    "signatures": signatures[:40],
                    "sample_id": sample_id,
                },
            ),
        )
