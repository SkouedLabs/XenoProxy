"""Critical-threat alert to a chat channel or a SIEM, by a plain webhook.

Fires when a finished job reaches the configured verdict floor. Four shapes are
supported, because the receiving end decides what it can read:

- `generic`: the signed JSON document (HMAC-SHA256 over timestamp and body), for a SIEM
  or a custom receiver that verifies it.
- `slack`, `discord`, `teams`: the text envelope each incoming-webhook API
  expects. These carry no signature; the URL itself is the secret.

Chat channels are not a place for TLP RED or TLP AMBER material, so the
connector declares AMBER and refuses anything above it. The message names the
observable, which is why the default floor is Malicious: a channel should not
be the first place an analyst reads about a suspicious host.
"""

from __future__ import annotations

from typing import Any, ClassVar

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
from app.plugins.webhook import post_signed

_FORMATS = ("generic", "slack", "discord", "teams")
_DISCORD_LIMIT = 1900  # Discord rejects content above 2000 characters.
_SEVERITY: dict[Verdict, int] = {
    Verdict.CLEAN: 0,
    Verdict.UNKNOWN: 1,
    Verdict.SUSPICIOUS: 2,
    Verdict.MALICIOUS: 3,
}
_TEAMS_COLOURS = {Verdict.SUSPICIOUS: "E6A700", Verdict.MALICIOUS: "C00000"}


def _escape_slack(text: str) -> str:
    """Slack mrkdwn reserves these three characters."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _flagged_lines(context: JobContext) -> list[str]:
    lines: list[str] = []
    for report in context.reports:
        verdict = report.summary.get("verdict")
        if verdict not in {Verdict.SUSPICIOUS.value, Verdict.MALICIOUS.value}:
            continue
        headline = str(report.summary.get("headline") or "")
        lines.append(f"{report.plugin_name}: {verdict}" + (f" - {headline}" if headline else ""))
    return lines[:12]


def _title(context: JobContext) -> str:
    return (
        f"XenoProxy: {context.verdict.value.upper()} {context.observable.type.value} "
        f"{context.observable.value}"
    )


def _generic(context: JobContext) -> dict[str, Any]:
    return {
        "event": "job.critical",
        "source": "xenoproxy",
        "job_id": str(context.job_id),
        "observable": context.observable.value,
        "observable_type": context.observable.type.value,
        "verdict": context.verdict.value,
        "tlp": context.tlp.value,
        "tags": context.tags,
        "flagged": _flagged_lines(context),
    }


def _text_body(context: JobContext) -> str:
    lines = [
        _title(context),
        f"TLP:{context.tlp.value.upper()} - requested by {context.requested_by}",
    ]
    lines.extend(f"- {line}" for line in _flagged_lines(context))
    return "\n".join(lines)


@register
class CriticalWebhookConnector(BaseConnector):
    """Sends an alert to a chat channel or a SIEM when a job is critical."""

    name = "critical_webhook"
    label = "Critical-threat alert (webhook)"
    description = "Alerts a Slack, Discord, Teams channel or a SIEM when a job is critical."
    supported_types: ClassVar[tuple[ObservableType, ...]] = ()
    secrets: ClassVar[tuple[SecretSpec, ...]] = (
        SecretSpec(
            "webhook_url",
            "Webhook URL",
            help_text="Incoming-webhook URL of the channel, or the SIEM receiver.",
        ),
        SecretSpec(
            "signing_key",
            "Signing key (generic format only)",
            required=False,
            help_text="When set with the generic format, requests are HMAC-SHA256 signed.",
        ),
        SecretSpec(
            "auth_token",
            "Header token",
            required=False,
            help_text="Sent as the header named by the 'auth_header' option.",
        ),
    )
    options_schema: ClassVar[dict[str, Any]] = {
        "format": {
            "type": "string",
            "default": "generic",
            "label": "Message format",
            "enum": list(_FORMATS),
        },
        "minimum_verdict": {
            "type": "string",
            "default": "malicious",
            "label": "Alert from this verdict upwards",
            "enum": ["suspicious", "malicious"],
        },
        "auth_header": {
            "type": "string",
            "default": "X-Webhook-Token",
            "label": "Auth header name",
        },
        "allow_private_target": {
            "type": "boolean",
            "default": True,
            "label": "Allow a receiver on the internal network",
        },
    }
    provider = ProviderInfo(
        name="Slack, Discord, Microsoft Teams, or a SIEM",
        url="https://api.slack.com/messaging/webhooks",
        api_base_url="The incoming-webhook URL of the channel, or the SIEM receiver",
        free_tier="Depends on the receiving platform.",
        notes=(
            "The message names the observable and the analyzers that flagged it. The "
            "generic format is signed; the chat formats rely on the secrecy of the URL. "
            "Teams MessageCards are a legacy format that Microsoft is retiring."
        ),
        self_hosted=False,
    )
    max_tlp = Tlp.AMBER
    default_timeout = 15
    default_cache_ttl = 0
    maturity = "alpha"
    documentation_url = "https://api.slack.com/messaging/webhooks"

    def refusal_reason(self, context: JobContext, job_status: Any) -> str | None:
        base = super().refusal_reason(context, job_status)
        if base is not None:
            return base

        configured = str(self.option("minimum_verdict", "malicious") or "malicious").lower()
        try:
            floor = Verdict(configured)
        except ValueError:
            return f"the configured minimum_verdict '{configured}' is not a verdict"
        if _SEVERITY[context.verdict] < _SEVERITY[floor]:
            return f"verdict is {context.verdict.value}, below the configured floor {floor.value}"
        return None

    def _payload(self, context: JobContext, fmt: str) -> dict[str, Any]:
        if fmt == "slack":
            return {"text": _escape_slack(f"*{_title(context)}*\n{_text_body(context)}")}
        if fmt == "discord":
            return {"content": _text_body(context)[:_DISCORD_LIMIT]}
        if fmt == "teams":
            return {
                "@type": "MessageCard",
                "@context": "https://schema.org/extensions",
                "summary": _title(context),
                "themeColor": _TEAMS_COLOURS.get(context.verdict, "C00000"),
                "title": _title(context),
                "text": _text_body(context).replace("\n", "<br>"),
            }
        return _generic(context)

    async def run(self, context: JobContext) -> PluginResult:
        fmt = str(self.option("format", "generic") or "generic").lower()
        if fmt not in _FORMATS:
            return self.failed(f"Unknown message format '{fmt}'.")

        # Only the generic shape is signed: a chat receiver cannot verify an HMAC.
        signing_key = self.optional_secret("signing_key") if fmt == "generic" else None
        response = await post_signed(
            self.secret("webhook_url"),
            self._payload(context, fmt),
            timeout=self.timeout,
            allow_private=bool(self.option("allow_private_target", True)),
            signing_key=signing_key,
            auth_header=str(self.option("auth_header", "X-Webhook-Token")),
            auth_token=self.optional_secret("auth_token"),
        )
        if not response.ok:
            return self.provider_http_error(response.status_code)

        return self.ok(
            {"format": fmt, "status_code": response.status_code},
            PluginSummary(
                verdict=context.verdict,
                headline=f"Alert sent as {fmt} (HTTP {response.status_code}).",
            ),
        )
