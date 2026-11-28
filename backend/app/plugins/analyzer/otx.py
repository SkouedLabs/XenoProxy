"""AlienVault OTX: the community threat-intelligence pulses an observable appears in."""

from __future__ import annotations

import ipaddress
from typing import Any, ClassVar
from urllib.parse import quote

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
from app.plugins.user_keys import USER_KEY_HELP
from app.services.observables import Observable

_BASE = "https://otx.alienvault.com/api/v1/indicators"
_MAX_LINKED_PULSES = 20


def _indicator_path(observable: Observable) -> tuple[str, str]:
    """The OTX indicator type and the escaped value to request it with."""
    if observable.type is ObservableType.IP:
        try:
            version = ipaddress.ip_address(observable.value).version
        except ValueError:
            version = 4
        kind = "IPv6" if version == 6 else "IPv4"
        return kind, quote(observable.value, safe="")
    if observable.type is ObservableType.DOMAIN:
        return "domain", quote(observable.value, safe="")
    if observable.type is ObservableType.URL:
        return "url", quote(observable.value, safe="")
    return "file", quote(observable.value, safe="")


@register
class OtxAnalyzer(BaseAnalyzer):
    """Pulses (threat reports) that cite an observable, from AlienVault OTX.

    A pulse is a report written by a community member or a vendor. Its presence
    means somebody published something about the observable, not that the
    observable has been confirmed malicious, so the verdict scales with how many
    independent pulses cite it and never reaches Malicious on a single one.
    """

    name = "otx"
    label = "AlienVault OTX"
    description = "Threat pulses citing the observable, with adversaries and malware families."
    supported_types: ClassVar[tuple[ObservableType, ...]] = (
        ObservableType.IP,
        ObservableType.DOMAIN,
        ObservableType.URL,
        ObservableType.HASH,
    )
    secrets: ClassVar[tuple[SecretSpec, ...]] = (
        SecretSpec(
            "api_key",
            "OTX API key",
            help_text="AlienVault OTX API key (free account, Settings page). " + USER_KEY_HELP,
            user_overridable=True,
        ),
    )
    options_schema: ClassVar[dict[str, Any]] = {
        "malicious_threshold": {
            "type": "integer",
            "default": 3,
            "label": "Pulses citing the observable before the verdict is Malicious",
        },
    }
    provider = ProviderInfo(
        name="AlienVault OTX",
        url="https://otx.alienvault.com/",
        api_base_url=f"{_BASE}/{{IPv4|IPv6|domain|url|file}}/{{value}}/general",
        credential_url="https://otx.alienvault.com/settings",
        free_tier="Free account; the API key is available from the settings page.",
        rate_limit="Free tier is rate limited per key; a 429 is reported as a quota error.",
        notes=(
            "Community pulses are unverified reports: several agreeing pulses carry weight, "
            "a single one does not."
        ),
    )
    max_tlp = Tlp.AMBER
    documentation_url = "https://otx.alienvault.com/api"
    free_tier = True
    default_timeout = 30

    async def run(self, observable: Observable) -> PluginResult:
        kind, value = _indicator_path(observable)
        response = await http_client.get(
            f"{_BASE}/{kind}/{value}/general",
            headers={"X-OTX-API-KEY": self.secret("api_key")},
            timeout=self.timeout,
        )
        if response.status_code == 404:
            return self.not_found("AlienVault OTX has no record for this observable.")
        if response.status_code == 429:
            raise PluginQuotaError("AlienVault OTX returned HTTP 429 (quota exhausted).")
        if not response.ok:
            return self.provider_http_error(response.status_code)

        raw: dict[str, Any] = response.json_body if isinstance(response.json_body, dict) else {}
        pulse_info: dict[str, Any] = (
            raw["pulse_info"] if isinstance(raw.get("pulse_info"), dict) else {}
        )
        pulses = [item for item in pulse_info.get("pulses") or [] if isinstance(item, dict)]
        count = int(pulse_info.get("count") or len(pulses) or 0)

        threshold = max(int(self.option("malicious_threshold", 3)), 1)
        if count == 0:
            # Silence on a community feed is not a clean verdict.
            verdict = Verdict.UNKNOWN
        elif count >= threshold:
            verdict = Verdict.MALICIOUS
        else:
            verdict = Verdict.SUSPICIOUS

        tags: set[str] = set()
        families: set[str] = set()
        adversaries: set[str] = set()
        for pulse in pulses:
            tags.update(str(tag).lower() for tag in pulse.get("tags") or [] if tag)
            for family in pulse.get("malware_families") or []:
                if isinstance(family, dict) and family.get("display_name"):
                    families.add(str(family["display_name"]))
            if pulse.get("adversary"):
                adversaries.add(str(pulse["adversary"]))
        tags.update(name.lower() for name in families)

        links = [
            {
                "label": str(pulse.get("name") or "OTX pulse")[:120],
                "url": f"https://otx.alienvault.com/pulse/{pulse['id']}",
            }
            for pulse in pulses[:_MAX_LINKED_PULSES]
            if pulse.get("id")
        ]
        headline = (
            f"Cited by {count} OTX pulse(s)"
            + (f", malware families: {', '.join(sorted(families)[:5])}" if families else "")
            + "."
            if count
            else "Not cited by any OTX pulse."
        )

        summary = PluginSummary(
            verdict=verdict,
            score=min(100, count * 10),
            tags=sorted(tags)[:50],
            headline=headline,
            links=links,
            extra={
                "pulse_count": count,
                "adversaries": sorted(adversaries)[:20],
                "malware_families": sorted(families)[:20],
                "reputation": raw.get("reputation"),
                "indicator_type": kind,
            },
        )
        return self.ok(raw, summary)
