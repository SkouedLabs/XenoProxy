"""Shodan Honeyscore: how likely an address is an intentional honeypot."""

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
from app.plugins.user_keys import USER_KEY_HELP
from app.services.observables import Observable

_ENDPOINT = "https://api.shodan.io/labs/honeyscore"


@register
class ShodanHoneyscoreAnalyzer(BaseAnalyzer):
    """Honeypot probability for an address, from Shodan's Honeyscore model.

    Honeyscore is a probability between 0 and 1. A high score means the address
    looks like a deception trap: for an analyst that is a warning about the
    infrastructure they are looking at, not a verdict on whether it is malicious.
    """

    name = "shodan_honeyscore"
    label = "Shodan Honeyscore"
    description = "Probability that the address is an intentional honeypot (0 to 1)."
    supported_types: ClassVar[tuple[ObservableType, ...]] = (
        ObservableType.IP,
        ObservableType.DOMAIN,
        ObservableType.URL,
    )
    secrets: ClassVar[tuple[SecretSpec, ...]] = (
        SecretSpec(
            "api_key",
            "Shodan API key",
            help_text="Shodan API key. " + USER_KEY_HELP,
            user_overridable=True,
        ),
    )
    options_schema: ClassVar[dict[str, Any]] = {
        "honeypot_threshold": {
            "type": "number",
            "default": 0.5,
            "label": "Honeyscore from which the address is Suspicious (0 to 1)",
        },
    }
    provider = ProviderInfo(
        name="Shodan",
        url="https://www.shodan.io/",
        api_base_url="https://api.shodan.io/labs/honeyscore/{ip}",
        credential_url="https://account.shodan.io/",
        free_tier="Honeyscore access depends on the Shodan plan; confirm on your account.",
        rate_limit="Credits per plan.",
        notes="The address is sent to Shodan. Honeyscore is a model output, not a confirmed trap.",
    )
    max_tlp = Tlp.AMBER
    documentation_url = "https://developer.shodan.io/"
    default_timeout = 20
    maturity = "alpha"

    async def run(self, observable: Observable) -> PluginResult:
        address = await self.address_of(observable)
        if not address:
            return self.not_found("The name does not resolve to an address Shodan can score.")

        response = await http_client.get(
            f"{_ENDPOINT}/{address}",
            params={"key": self.secret("api_key")},
            timeout=self.timeout,
        )
        if response.status_code == 404:
            return self.not_found("Shodan has no Honeyscore for this address.")
        if response.status_code == 429:
            raise PluginQuotaError("Shodan returned HTTP 429 (credits exhausted).")
        if not response.ok:
            return self.provider_http_error(response.status_code)

        raw_value = response.json_body
        if isinstance(raw_value, bool) or not isinstance(raw_value, (int, float)):
            return self.failed("Shodan answered with a Honeyscore that is not a number.")
        score = float(raw_value)
        if not 0.0 <= score <= 1.0:
            return self.failed(f"Shodan answered an out-of-range Honeyscore ({score}).")

        threshold = float(self.option("honeypot_threshold", 0.5))
        if score >= threshold:
            verdict = Verdict.SUSPICIOUS
            headline = f"Looks like a honeypot (Honeyscore {score:.2f})."
        else:
            verdict = Verdict.CLEAN
            headline = f"Does not look like a honeypot (Honeyscore {score:.2f})."

        summary = PluginSummary(
            verdict=verdict,
            score=round(score * 100),
            tags=["honeypot"] if verdict is Verdict.SUSPICIOUS else [],
            headline=headline + self.resolved_note(observable, address),
            extra={"honeyscore": score, "address": address},
        )
        return self.ok({"address": address, "honeyscore": score}, summary)
