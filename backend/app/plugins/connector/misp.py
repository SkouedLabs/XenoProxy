"""MISP export connector (alpha).

Creates one MISP event per analysed observable, with the observable as an attribute,
the XenoProxy verdict as a tag and threat level, and the job's TLP as a `tlp:` tag.

Contract note: exercised against mocked MISP responses only, never a live instance.
The event is created unpublished and visible to the creating organisation only
(distribution 0), so nothing is shared until a person decides to.
"""

from __future__ import annotations

from typing import Any, ClassVar

from app.core import http_client
from app.models.job import ObservableType, Tlp, Verdict
from app.plugins.base.connector import BaseConnector
from app.plugins.base.plugin import (
    JobContext,
    PluginResult,
    PluginSummary,
    ProviderInfo,
    SecretSpec,
)
from app.plugins.base.registry import register

# MISP threat levels: 1 high, 2 medium, 3 low, 4 undefined.
_THREAT_LEVELS = {
    Verdict.MALICIOUS: 1,
    Verdict.SUSPICIOUS: 2,
    Verdict.UNKNOWN: 4,
    Verdict.CLEAN: 3,
}
_HASH_TYPES = {32: "md5", 40: "sha1", 64: "sha256"}
_NETWORK_TYPES = (ObservableType.IP, ObservableType.DOMAIN, ObservableType.URL)


def attribute_type(observable_type: ObservableType, value: str) -> str:
    if observable_type is ObservableType.IP:
        return "ip-dst"
    if observable_type is ObservableType.DOMAIN:
        return "domain"
    if observable_type is ObservableType.URL:
        return "url"
    if observable_type is ObservableType.HASH:
        return _HASH_TYPES.get(len(value), "sha256")
    return "text"


@register
class MispConnector(BaseConnector):
    """Records the analysed observable and its verdict as an event in a MISP instance."""

    name = "misp_export"
    label = "MISP export"
    description = "Creates an unpublished MISP event for the observable, tagged with the verdict."
    supported_types: ClassVar[tuple[ObservableType, ...]] = (
        ObservableType.IP,
        ObservableType.DOMAIN,
        ObservableType.URL,
        ObservableType.HASH,
        ObservableType.GENERIC,
    )
    secrets: ClassVar[tuple[SecretSpec, ...]] = (
        SecretSpec("base_url", "MISP URL", help_text="For example https://misp.example.com"),
        SecretSpec("api_key", "Auth key", help_text="The automation key of a MISP user."),
    )
    options_schema: ClassVar[dict[str, Any]] = {
        "trusted_internal": {
            "type": "boolean",
            "default": False,
            "label": "Trusted internal MISP: may receive TLP:RED while its address is private",
        },
        "tags": {
            "type": "string",
            "default": "xenoproxy",
            "label": "Comma-separated tags always applied to the event",
        },
        "export_job_tags": {
            "type": "boolean",
            "default": True,
            "label": "Also apply the job tags to the event",
        },
        "allow_private_target": {
            "type": "boolean",
            "default": True,
            "label": "Allow a MISP instance on the internal network",
        },
    }
    provider = ProviderInfo(
        name="MISP",
        url="https://www.misp-project.org/",
        api_base_url="{your instance}/events/add",
        credential_url="Your instance: Administration, List Auth Keys (or My Profile)",
        free_tier="Open source and self-hosted.",
        notes=(
            "Creates an unpublished event visible to your organisation only (distribution 0). "
            "Only a malicious verdict marks the attribute for IDS export."
        ),
        self_hosted=True,
    )
    max_tlp = Tlp.AMBER
    trusted_internal_max_tlp = Tlp.RED
    default_timeout = 60
    default_cache_ttl = 0
    documentation_url = "https://www.misp-project.org/openapi/"
    maturity = "alpha"
    run_on_partial_failure = True

    def _tags(self, context: JobContext) -> list[str]:
        tags = [t.strip() for t in str(self.option("tags", "xenoproxy")).split(",") if t.strip()]
        if self.option("export_job_tags", True):
            tags.extend(context.tags)
        tags.append(f"tlp:{context.tlp.value.lower()}")
        tags.append(f"xenoproxy:verdict={context.verdict.value}")
        return list(dict.fromkeys(tags))[:40]

    async def run(self, context: JobContext) -> PluginResult:
        base_url = self.secret("base_url").rstrip("/")
        refusal = await self.internal_only_refusal(base_url)
        if refusal:
            return self.skipped(refusal)

        observable = context.observable
        tags = self._tags(context)
        category = "Network activity" if observable.type in _NETWORK_TYPES else "Payload delivery"
        event = {
            "info": f"XenoProxy: {observable.value[:200]} ({context.verdict.value})",
            "threat_level_id": _THREAT_LEVELS[context.verdict],
            "analysis": 2,  # completed
            "distribution": 0,  # this organisation only
            "published": False,
            "Tag": [{"name": tag} for tag in tags],
            "Attribute": [
                {
                    "type": attribute_type(observable.type, observable.value),
                    "category": category,
                    "value": observable.value,
                    "to_ids": context.verdict is Verdict.MALICIOUS,
                    "distribution": 0,
                    "comment": f"XenoProxy job {context.job_id}",
                }
            ],
        }
        response = await http_client.post(
            f"{base_url}/events/add",
            headers={
                "Authorization": self.secret("api_key"),
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            json=event,
            timeout=self.timeout,
            allow_private=bool(self.option("allow_private_target", True)),
        )
        if not response.ok:
            return self.provider_http_error(response.status_code)

        raw: dict[str, Any] = response.json_body or {}
        created = raw.get("Event")
        if not isinstance(created, dict) or not created.get("id"):
            message = str(raw.get("message") or raw.get("errors") or "no event returned")[:300]
            return self.failed(f"MISP rejected the export: {message}")

        identifier = str(created["id"])
        return self.ok(
            raw,
            PluginSummary(
                verdict=context.verdict,
                score=None,
                tags=tags,
                headline=f"Exported to MISP as event {identifier}.",
                links=[{"label": "Open in MISP", "url": f"{base_url}/events/view/{identifier}"}],
                extra={"misp_event_id": identifier, "uuid": created.get("uuid")},
            ),
        )
