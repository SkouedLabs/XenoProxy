"""Have I Been Pwned: is an email address in a known data breach?

A breach record is an exposure, not evidence that the address is hostile, so
any breach is Suspicious and never Malicious. An address with no breach record
is Unknown rather than Clean: HIBP has not indexed every breach, so silence is
not a clean bill of health.

Scope: email addresses only. The password range check (k-anonymity, no key)
takes a different input and is not part of this module yet.

Contract note: built from the public API v3 documentation and tested against
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

_ENDPOINT = "https://haveibeenpwned.com/api/v3/breachedaccount"
_EMAIL = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,253}\.[a-z]{2,63}$")
_MAX_NAMES = 50


@register
class HibpAnalyzer(BaseAnalyzer):
    """Lists the breaches an email address appears in."""

    name = "hibp"
    label = "Have I Been Pwned"
    description = "Data breaches an email address has appeared in."
    supported_types: ClassVar[tuple[ObservableType, ...]] = (ObservableType.GENERIC,)
    secrets: ClassVar[tuple[SecretSpec, ...]] = (
        SecretSpec(
            "api_key",
            "HIBP API key",
            help_text="Paid HIBP API key, sent as the hibp-api-key header.",
            user_overridable=True,
        ),
    )
    provider = ProviderInfo(
        name="Have I Been Pwned",
        url="https://haveibeenpwned.com/",
        api_base_url="https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
        credential_url="https://haveibeenpwned.com/API/Key",
        free_tier="No free key for the breach lookup; a paid key is required.",
        rate_limit="Published per key; 429 carries a Retry-After.",
        notes="The address is sent to HIBP. Breach matches are exposure, not maliciousness.",
    )
    max_tlp = Tlp.AMBER
    documentation_url = "https://haveibeenpwned.com/API/v3"
    default_timeout = 20
    default_cache_ttl = 86400
    maturity = "alpha"

    async def run(self, observable: Observable) -> PluginResult:
        email = observable.value.strip().lower()
        if not _EMAIL.match(email):
            return self.skipped("Have I Been Pwned looks up email addresses only.")

        response = await http_client.get(
            f"{_ENDPOINT}/{quote(email, safe='@')}?truncateResponse=true",
            headers={
                "hibp-api-key": self.secret("api_key"),
                "User-Agent": "XenoProxy",
            },
            timeout=self.timeout,
        )
        if response.status_code == 404:
            return self.not_found("No breach on record for this address.")
        if response.status_code == 429:
            raise PluginQuotaError("Have I Been Pwned returned HTTP 429 (rate limited).")
        if not response.ok:
            return self.provider_http_error(response.status_code)

        body = response.json_body
        if not isinstance(body, list):
            return self.failed("Have I Been Pwned answered with a body that is not a list.")
        return self._from_breaches([item for item in body if isinstance(item, dict)])

    def _from_breaches(self, breaches: list[dict[str, Any]]) -> PluginResult:
        if not breaches:
            return self.not_found("No breach on record for this address.")

        names = sorted({str(item["Name"]) for item in breaches if item.get("Name")})
        sensitive = any(item.get("IsSensitive") for item in breaches)
        stealer = any(item.get("IsStealerLog") for item in breaches)
        tags = ["breached"]
        if sensitive:
            tags.append("sensitive-breach")
        if stealer:
            tags.append("stealer-log")

        summary = PluginSummary(
            verdict=Verdict.SUSPICIOUS,
            score=min(100, len(names) * 10),
            tags=tags,
            headline=f"Appears in {len(names)} known breach(es).",
            extra={"breaches": names[:_MAX_NAMES], "breach_count": len(names)},
        )
        return self.ok({"breaches": names}, summary)
