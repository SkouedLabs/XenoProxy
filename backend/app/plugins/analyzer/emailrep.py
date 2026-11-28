"""EmailRep: reputation of an email address from public and breach signals.

A flagged address is Suspicious, and only a recent malicious-activity record on
a blacklisted address reaches Malicious. A leaked password is a fact about the
mailbox owner, not about the sender, so it is tagged but never raises the
verdict on its own. An address EmailRep knows nothing about is Unknown, not
Clean.

Contract note: built from the public API documentation and tested against
mocks only. It has not been exercised against the live service.
"""

from __future__ import annotations

import re
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
from app.services.observables import Observable

_ENDPOINT = "https://emailrep.io"
_EMAIL = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,253}\.[a-z]{2,63}$")


@register
class EmailRepAnalyzer(BaseAnalyzer):
    """Reputation of an email address."""

    name = "emailrep"
    label = "EmailRep"
    description = "Reputation of an email address: suspicious activity, breaches, disposables."
    supported_types: ClassVar[tuple[ObservableType, ...]] = (ObservableType.GENERIC,)
    secrets: ClassVar[tuple[SecretSpec, ...]] = (
        SecretSpec(
            "api_key",
            "EmailRep key (optional)",
            required=False,
            help_text="Optional. Without a key the anonymous quota is small.",
            user_overridable=True,
        ),
    )
    provider = ProviderInfo(
        name="EmailRep",
        url="https://emailrep.io/",
        api_base_url="https://emailrep.io/{email}",
        credential_url="https://emailrep.io/key",
        free_tier="Anonymous access with a small daily quota; a free key raises it.",
        rate_limit="Published per key; anonymous access is throttled.",
        notes="The address is sent to EmailRep. It is a third party that retains lookups.",
    )
    max_tlp = Tlp.AMBER
    documentation_url = "https://emailrep.io/"
    free_tier = True
    default_timeout = 20
    default_cache_ttl = 86400
    maturity = "alpha"

    async def run(self, observable: Observable) -> PluginResult:
        email = observable.value.strip().lower()
        if not _EMAIL.match(email):
            return self.skipped("EmailRep looks up email addresses only.")

        headers = {"User-Agent": "XenoProxy"}
        key = self.optional_secret("api_key")
        if key:
            headers["Key"] = key

        response = await http_client.get(
            f"{_ENDPOINT}/{quote(email, safe='@')}",
            headers=headers,
            timeout=self.timeout,
        )
        if response.status_code == 429:
            raise PluginQuotaError("EmailRep returned HTTP 429 (quota exhausted).")
        if response.status_code == 404:
            return self.not_found("EmailRep has no record of this address.")
        if not response.ok:
            return self.provider_http_error(response.status_code)

        body = response.json_body
        if not isinstance(body, dict):
            return self.failed("EmailRep answered with a body that is not a JSON object.")
        return self._from_body(body)

    def _from_body(self, body: dict[str, Any]) -> PluginResult:
        reputation = str(body.get("reputation") or "none").lower()
        details = body.get("details") if isinstance(body.get("details"), dict) else {}
        blacklisted = bool(details.get("blacklisted"))
        recent = bool(details.get("malicious_activity_recent"))
        flagged = (
            bool(body.get("suspicious")) or blacklisted or bool(details.get("malicious_activity"))
        )

        if blacklisted and recent:
            verdict = Verdict.MALICIOUS
        elif flagged or reputation == "low":
            verdict = Verdict.SUSPICIOUS
        elif reputation in {"high", "medium"}:
            verdict = Verdict.CLEAN
        else:
            verdict = Verdict.UNKNOWN

        tags: list[str] = []
        if details.get("credentials_leaked"):
            tags.append("credentials-leaked")
        if details.get("disposable"):
            tags.append("disposable")
        if blacklisted:
            tags.append("blacklisted")

        summary = PluginSummary(
            verdict=verdict,
            tags=tags,
            headline=f"Reputation {reputation}; {body.get('references', 0)} reference(s).",
            extra={
                "reputation": reputation,
                "suspicious": bool(body.get("suspicious")),
                "blacklisted": blacklisted,
                "malicious_activity": bool(details.get("malicious_activity")),
                "credentials_leaked": bool(details.get("credentials_leaked")),
                "disposable": bool(details.get("disposable")),
            },
        )
        return self.ok(body, summary)
