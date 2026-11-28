"""YARAify: community YARA rules that match a file hash, from abuse.ch.

A rule match is a pattern hit, not a verdict on the file. Community rules
misfire, so a single matching rule is Suspicious; several distinct rules are
Malicious. A hash that no rule has matched is Unknown: YARAify having nothing to
say about a sample does not make the sample clean.

Contract note: built from the public API documentation and tested against
mocks only. It has not been exercised against the live service.
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

_ENDPOINT = "https://yaraify-api.abuse.ch/api/v1/"
_AUTH_HELP = "Abuse.ch Auth-Key from your abuse.ch account profile."
_HASH_LENGTHS = {32, 40, 64}  # MD5, SHA-1, SHA-256


def _rule_names(data: dict[str, Any]) -> list[str]:
    names: set[str] = set()
    for entry in data.get("yara_rules") or []:
        if isinstance(entry, dict) and entry.get("rule_name"):
            names.add(str(entry["rule_name"]))
    return sorted(names)


@register
class YaraifyAnalyzer(BaseAnalyzer):
    """Looks a file hash up against community YARA rule matches."""

    name = "yaraify"
    label = "YARAify"
    description = "Community YARA rules that match this file hash."
    supported_types: ClassVar[tuple[ObservableType, ...]] = (ObservableType.HASH,)
    secrets: ClassVar[tuple[SecretSpec, ...]] = (
        SecretSpec(
            "auth_key", "Auth-Key", required=True, help_text=_AUTH_HELP, user_overridable=True
        ),
    )
    options_schema: ClassVar[dict[str, Any]] = {
        "malicious_rules": {
            "type": "integer",
            "default": 3,
            "label": "Distinct matching rules from which the file is Malicious",
        },
    }
    provider = ProviderInfo(
        name="abuse.ch YARAify",
        url="https://yaraify.abuse.ch/",
        api_base_url="https://yaraify-api.abuse.ch/api/v1/",
        credential_url="https://auth.abuse.ch/ (Auth-Key)",
        free_tier="Free; an Auth-Key is required.",
        rate_limit="Fair use.",
        notes="Only the hash is sent. Matches come from community rules that can misfire.",
    )
    max_tlp = Tlp.AMBER
    documentation_url = "https://yaraify.abuse.ch/api/"
    free_tier = True
    default_timeout = 30
    default_cache_ttl = 86400
    maturity = "alpha"

    async def run(self, observable: Observable) -> PluginResult:
        value = observable.value.strip().lower()
        if len(value) not in _HASH_LENGTHS or not all(char in "0123456789abcdef" for char in value):
            return self.skipped("YARAify looks up MD5, SHA-1 or SHA-256 hashes only.")

        response = await http_client.post(
            _ENDPOINT,
            headers={"Auth-Key": self.secret("auth_key")},
            data={"query": "lookup_hash", "search_hash": value},
            timeout=self.timeout,
        )
        if response.status_code == 429:
            raise PluginQuotaError("YARAify returned HTTP 429.")
        if not response.ok:
            return self.provider_http_error(response.status_code)

        body = response.json_body
        if not isinstance(body, dict):
            return self.failed("YARAify answered with a body that is not a JSON object.")
        status = str(body.get("query_status", ""))
        if status == "hash_not_found":
            return self.not_found("No YARA rule has matched this hash.")
        if status != "ok":
            return self.failed(f"YARAify answered with status '{status or 'missing'}'.")

        data = body.get("data") if isinstance(body.get("data"), dict) else {}
        rules = _rule_names(data)
        if not rules:
            return self.not_found("No YARA rule has matched this hash.")

        threshold = int(self.option("malicious_rules", 3))
        verdict = Verdict.MALICIOUS if len(rules) >= threshold else Verdict.SUSPICIOUS
        summary = PluginSummary(
            verdict=verdict,
            score=min(100, len(rules) * 20),
            tags=["yara-match"],
            headline=f"{len(rules)} community YARA rule(s) match this file.",
            extra={"matched_rules": rules[:50]},
        )
        return self.ok({"matched_rules": rules, "query_status": status}, summary)
