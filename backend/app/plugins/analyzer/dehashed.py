"""Dehashed: is an email address in a leaked credential database, and with what data?

A leak record says that an address, and often a password, was exposed. It does
not say the address is hostile, so any hit is Suspicious and never Malicious. No
hit is Unknown rather than Clean: the index does not cover every leak.

Privacy: Dehashed returns plaintext and hashed passwords. Those values are read
only to know that a password was exposed. They are never copied into the stored
report, the summary, or the raw output. What is kept is the database names, the
counts, and which kinds of field were present.

Contract note: built from the public v2 search documentation and tested against
mocks only. It has not been exercised against the live service.
"""

from __future__ import annotations

import re
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

_ENDPOINT = "https://api.dehashed.com/v2/search"
# Strict on purpose: the address is put inside a quoted query, so no quote or
# space may reach it.
_EMAIL = re.compile(r"^[a-z0-9._%+-]{1,64}@[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63})+$")
_PAGE_SIZE = 100
_MAX_DATABASES = 50
_CREDENTIAL_FIELDS = ("password", "hashed_password")


@register
class DehashedAnalyzer(BaseAnalyzer):
    """Leak records that contain an email address, reduced to what an analyst needs."""

    name = "dehashed"
    label = "Dehashed"
    description = "Leaked records that contain an email address: which databases, which fields."
    supported_types: ClassVar[tuple[ObservableType, ...]] = (ObservableType.GENERIC,)
    secrets: ClassVar[tuple[SecretSpec, ...]] = (
        SecretSpec(
            "api_key",
            "Dehashed API key",
            help_text="From your Dehashed account. The search is paid and draws on credits.",
            placeholder="from dehashed.com",
            user_overridable=True,
        ),
    )
    provider = ProviderInfo(
        name="Dehashed",
        url="https://www.dehashed.com/",
        api_base_url="https://api.dehashed.com/v2/search",
        credential_url="https://www.dehashed.com/ (account, API key)",
        free_tier="No free search; a paid subscription is required.",
        rate_limit="Per plan; out of credits answers HTTP 402.",
        notes=(
            "The address is sent to Dehashed. Passwords in the results are never stored, only "
            "whether one was exposed. A hit is exposure, not maliciousness."
        ),
    )
    max_tlp = Tlp.AMBER
    documentation_url = "https://www.dehashed.com/docs"
    default_timeout = 30
    default_cache_ttl = 86400
    maturity = "alpha"

    async def run(self, observable: Observable) -> PluginResult:
        email = observable.value.strip().lower()
        if not _EMAIL.match(email):
            return self.skipped("Dehashed looks up email addresses only.")

        response = await http_client.post(
            _ENDPOINT,
            json={"query": f'email:"{email}"', "page": 1, "size": _PAGE_SIZE},
            headers={
                "Dehashed-Api-Key": self.secret("api_key"),
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": "XenoProxy",
            },
            timeout=self.timeout,
        )
        if response.status_code == 429:
            raise PluginQuotaError("Dehashed returned HTTP 429 (rate limited).")
        if response.status_code == 402:
            raise PluginQuotaError("Dehashed is out of credits for this key.")
        if response.status_code in (401, 403):
            raise PluginQuotaError("Dehashed rejected the configured API key.")
        if not response.ok:
            return self.provider_http_error(response.status_code)

        body = response.json_body
        if not isinstance(body, dict):
            return self.failed("Dehashed answered with a body that is not an object.")
        entries = [entry for entry in body.get("entries") or [] if isinstance(entry, dict)]
        if not entries:
            return self.not_found("No leaked record for this address in Dehashed.")
        return self._from_entries(entries, body.get("total"))

    def _from_entries(self, entries: list[dict[str, Any]], total: Any) -> PluginResult:
        databases = sorted({str(e["database_name"]) for e in entries if e.get("database_name")})
        exposed_fields = sorted(
            {field for entry in entries for field in _CREDENTIAL_FIELDS if entry.get(field)}
        )
        total_count = total if isinstance(total, int) and total >= len(entries) else len(entries)

        tags = ["leaked"]
        if "password" in exposed_fields:
            tags.append("plaintext-password")
        elif exposed_fields:
            tags.append("password-hash")

        summary = PluginSummary(
            verdict=Verdict.SUSPICIOUS,
            score=min(100, 60 if "password" in exposed_fields else 30),
            tags=tags,
            headline=(
                f"Found in {total_count} leaked record(s) across {len(databases)} database(s)."
            ),
            extra={
                "record_count": total_count,
                "databases": databases[:_MAX_DATABASES],
                "exposed_credential_fields": exposed_fields,
            },
        )
        # Only the summary facts are kept. The entries themselves hold personal data
        # and, in some records, passwords, so they are not returned.
        return self.ok(
            {
                "record_count": total_count,
                "databases": databases[:_MAX_DATABASES],
                "exposed_credential_fields": exposed_fields,
            },
            summary,
        )
