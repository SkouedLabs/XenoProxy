"""Intezer Analyze: code genetics, the part a hash match misses.

A file hash says whether a sample is already known. Intezer compares the code
itself: a new build of a known family shares most of its code with the old one,
so the family is recognised even when every hash is new.

This analyzer reads existing analyses by SHA-256 only. It never uploads a file:
an upload is shared with the Intezer platform, and that is a decision for an
analyst, not a side effect of a lookup.

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

BASE = "https://analyze.intezer.com/api/v2-0"

_VERDICT = {
    "malicious": Verdict.MALICIOUS,
    "suspicious": Verdict.SUSPICIOUS,
    # "trusted" is Intezer's positive knowledge that the code is known-good software.
    "trusted": Verdict.CLEAN,
    "unknown": Verdict.UNKNOWN,
}


@register
class IntezerAnalyzer(BaseAnalyzer):
    """Code-level family match for a sample, from existing Intezer analyses."""

    name = "intezer"
    label = "Intezer Analyze"
    description = (
        "Code genetics: the family a sample's code is closest to, even when its hash is new."
    )
    supported_types: ClassVar[tuple[ObservableType, ...]] = (
        ObservableType.HASH,
        ObservableType.FILE,
    )
    secrets: ClassVar[tuple[SecretSpec, ...]] = (
        SecretSpec(
            "api_key",
            "API key",
            help_text="From your Intezer Analyze account, in its API section.",
            placeholder="from analyze.intezer.com",
            user_overridable=True,
        ),
    )
    provider = ProviderInfo(
        name="Intezer Analyze",
        url="https://analyze.intezer.com/",
        api_base_url="https://analyze.intezer.com/api/v2-0/files/{sha256}",
        credential_url="https://analyze.intezer.com/",
        free_tier="Community accounts have a limited quota; check your plan.",
        rate_limit="Per plan.",
        notes=(
            "Looks up existing analyses by SHA-256 only. It never uploads a sample: an upload "
            "is shared with the Intezer platform."
        ),
    )
    max_tlp = Tlp.AMBER
    default_timeout = 45
    default_cache_ttl = 86400
    documentation_url = "https://analyze.intezer.com/api-docs"
    maturity = "alpha"

    async def run(self, observable: Observable) -> PluginResult:
        if len(observable.value) != 64 or observable.hash_algorithm not in {"sha256", None}:
            return self.skipped("Intezer is queried by SHA-256; this observable is another hash.")

        token = await self._access_token()
        response = await http_client.get(
            f"{BASE}/files/{observable.value}",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
            timeout=self.timeout,
        )
        if response.status_code == 404:
            return self.not_found("Intezer has no analysis for this sample.")
        if response.status_code == 429:
            raise PluginQuotaError("Intezer returned HTTP 429.")
        if response.status_code in (401, 403):
            raise PluginQuotaError("Intezer rejected the access token for this key.")
        if not response.ok:
            return self.provider_http_error(response.status_code)

        body: dict[str, Any] = response.json_body if isinstance(response.json_body, dict) else {}
        if not body:
            return self.failed("Intezer returned an empty or unreadable analysis.")

        verdict_text = str(body.get("verdict") or "").lower()
        sub_verdict = str(body.get("sub_verdict") or "")
        family = str(body.get("family_name") or "")
        analysis_id = str(body.get("analysis_id") or "")

        headline = f"Verdict: {verdict_text or 'unknown'}"
        if family:
            headline += f" (family {family})"

        return self.ok(
            body,
            PluginSummary(
                verdict=_VERDICT.get(verdict_text, Verdict.UNKNOWN),
                tags=[tag for tag in (verdict_text, family, sub_verdict) if tag],
                headline=headline,
                links=(
                    [
                        {
                            "label": "Open the analysis",
                            "url": f"https://analyze.intezer.com/#/analyses/{analysis_id}",
                        }
                    ]
                    if analysis_id
                    else []
                ),
                extra={
                    "family": family,
                    "sub_verdict": sub_verdict,
                    "analysis_id": analysis_id,
                },
            ),
        )

    async def _access_token(self) -> str:
        """Exchange the API key for a short-lived bearer token."""
        response = await http_client.post(
            f"{BASE}/get-access-token",
            json={"api_key": self.secret("api_key")},
            headers={"Accept": "application/json"},
            timeout=self.timeout,
        )
        if response.status_code == 429:
            raise PluginQuotaError("Intezer returned HTTP 429.")
        if response.status_code in (401, 403):
            raise PluginQuotaError("Intezer rejected the configured API key.")
        if not response.ok:
            raise PluginQuotaError(
                f"Intezer token request failed with HTTP {response.status_code}."
            )
        body = response.json_body if isinstance(response.json_body, dict) else {}
        token = body.get("result")
        if not isinstance(token, str) or not token:
            raise PluginQuotaError("Intezer returned no access token.")
        return token
