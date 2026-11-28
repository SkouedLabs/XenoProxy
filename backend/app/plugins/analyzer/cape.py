"""CAPE sandbox: the result of a run on your own Cuckoo/CAPE instance.

CAPE is the sandbox most teams run themselves, so its results stay on your
network. The analyzer asks your instance for the newest run of a SHA-256 and
reads its score. It never submits a file: submitting is a decision for the
person running the sandbox, and it is not something a lookup should trigger.

Because the instance is self-hosted, its address is an option, and private
addresses are allowed by default. A CAPE instance is almost always on a private
network.

A quiet run is not evidence of a clean sample, so a low score is Unknown.

Contract note: exercised against mocks only. The endpoints follow the CAPE API v2
layout; they have not been run against a live instance.
"""

from __future__ import annotations

from typing import Any, ClassVar

from app.core import http_client
from app.models.job import ObservableType, Tlp, Verdict
from app.plugins.base.analyzer import BaseAnalyzer
from app.plugins.base.plugin import (
    PluginConfigurationError,
    PluginQuotaError,
    PluginResult,
    PluginSummary,
    ProviderInfo,
    SecretSpec,
)
from app.plugins.base.registry import register
from app.services.observables import Observable

_MALICIOUS_AT = 7.0
_SUSPICIOUS_AT = 4.0


def _malscore_verdict(score: float | None) -> Verdict:
    if score is None:
        return Verdict.UNKNOWN
    if score >= _MALICIOUS_AT:
        return Verdict.MALICIOUS
    if score >= _SUSPICIOUS_AT:
        return Verdict.SUSPICIOUS
    return Verdict.UNKNOWN


def _task_ids(entries: Any) -> list[int]:
    ids: list[int] = []
    for entry in entries if isinstance(entries, list) else []:
        candidate = entry.get("id") if isinstance(entry, dict) else entry
        if isinstance(candidate, int) and not isinstance(candidate, bool):
            ids.append(candidate)
    return ids


def _malscore(task: dict[str, Any]) -> float | None:
    raw = task.get("malscore", task.get("score"))
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        return None
    value = float(raw)
    return value if 0.0 <= value <= 10.0 else None


@register
class CapeSandboxAnalyzer(BaseAnalyzer):
    """The newest CAPE run of a sample, read from your own instance."""

    name = "cape"
    label = "CAPE sandbox"
    description = "The newest run of a sample on your own CAPE/Cuckoo instance, and its score."
    supported_types: ClassVar[tuple[ObservableType, ...]] = (
        ObservableType.HASH,
        ObservableType.FILE,
    )
    secrets: ClassVar[tuple[SecretSpec, ...]] = (
        SecretSpec(
            "api_token",
            "API token",
            required=False,
            help_text="Only if your instance requires one. Create it in the CAPE web interface.",
            placeholder="token from your CAPE instance",
            user_overridable=True,
        ),
    )
    options_schema: ClassVar[dict[str, Any]] = {
        "base_url": {
            "type": "string",
            "default": "",
            "label": "Base URL of your CAPE instance, for example https://cape.internal",
        },
        "allow_private_target": {
            "type": "boolean",
            "default": True,
            "label": "Allow the instance on a private network",
        },
    }
    provider = ProviderInfo(
        name="CAPE sandbox (self-hosted)",
        url="https://github.com/kevoreilly/CAPEv2",
        api_base_url="{base_url}/apiv2/tasks/search/sha256/{sha256}/",
        credential_url="Your CAPE web interface, under the user's API token.",
        free_tier="Open source and self-hosted; there is no quota to run into.",
        rate_limit="None set by CAPE; bounded by your instance.",
        notes=(
            "Reads the newest run on your own instance by SHA-256. It never submits a file. "
            "The base URL is required and is read from the analyzer options."
        ),
    )
    max_tlp = Tlp.AMBER
    default_timeout = 45
    default_cache_ttl = 86400
    documentation_url = "https://capev2.readthedocs.io/"
    maturity = "alpha"

    async def run(self, observable: Observable) -> PluginResult:
        if len(observable.value) != 64 or observable.hash_algorithm not in {"sha256", None}:
            return self.skipped("CAPE is queried by SHA-256; this observable is another hash.")

        base = str(self.option("base_url", "") or "").strip().rstrip("/")
        if not base:
            raise PluginConfigurationError(
                "Set the base URL of your CAPE instance in the analyzer options."
            )
        allow_private = bool(self.option("allow_private_target", True))

        headers = {"Accept": "application/json"}
        token = self.optional_secret("api_token")
        if token:
            headers["Authorization"] = f"Token {token}"

        search = await http_client.get(
            f"{base}/apiv2/tasks/search/sha256/{observable.value}/",
            headers=headers,
            timeout=self.timeout,
            allow_private=allow_private,
        )
        if search.status_code == 429:
            raise PluginQuotaError("CAPE returned HTTP 429.")
        if search.status_code in (401, 403):
            raise PluginQuotaError("CAPE rejected the API token.")
        if search.status_code == 404:
            return self.not_found("CAPE has no run for this sample.")
        if not search.ok:
            return self.provider_http_error(search.status_code)

        search_body = search.json_body if isinstance(search.json_body, dict) else {}
        ids = _task_ids(search_body.get("data"))
        if not ids:
            return self.not_found("CAPE has no run for this sample.")

        # Task ids grow with time: the highest one is the newest run.
        task_id = max(ids)
        view = await http_client.get(
            f"{base}/apiv2/tasks/view/{task_id}/",
            headers=headers,
            timeout=self.timeout,
            allow_private=allow_private,
        )
        if not view.ok:
            return self.provider_http_error(view.status_code)

        view_body = view.json_body if isinstance(view.json_body, dict) else {}
        task = view_body.get("data") if isinstance(view_body.get("data"), dict) else {}
        if not task:
            return self.failed("CAPE returned an unreadable task.")

        status = str(task.get("status") or "unknown")
        score = _malscore(task)
        # A run still in the queue has no score yet: that is not a verdict.
        verdict = _malscore_verdict(score) if status == "reported" else Verdict.UNKNOWN
        headline = (
            f"CAPE score {score:g} out of 10 (task {task_id})"
            if score is not None and status == "reported"
            else f"CAPE task {task_id} is {status}; no score yet"
        )

        return self.ok(
            task,
            PluginSummary(
                verdict=verdict,
                score=round(score * 10) if score is not None and status == "reported" else None,
                tags=[status],
                headline=headline,
                extra={
                    "task_id": task_id,
                    "status": status,
                    "malscore": score,
                    "runs": len(ids),
                },
            ),
        )
