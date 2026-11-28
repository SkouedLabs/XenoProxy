"""Crypto address check against the sanctions designations loaded on this instance.

Only a designation on a loaded list makes an address Malicious. An address that is not on
the list is Unknown, never Clean: the list is not exhaustive, and it says nothing about
transactions. Mixers (for example Tornado Cash designations) are tagged as such.

Nothing leaves the instance: the list is read from a local directory and no chain or
provider API is called, so the analyzer is allowed at TLP:RED. Interaction tracing needs a
chain-analytics provider, which is a separate, opt-in decision.
"""

from __future__ import annotations

import asyncio
from typing import Any, ClassVar

from app.models.job import ObservableType, Tlp, Verdict
from app.plugins.base.analyzer import BaseAnalyzer
from app.plugins.base.plugin import PluginResult, PluginSummary, ProviderInfo
from app.plugins.base.registry import register
from app.services import crypto_intel
from app.services.observables import Observable


@register
class CryptoTaintAnalyzer(BaseAnalyzer):
    """Checks a BTC or ETH address against the sanctions designations loaded locally."""

    name = "crypto_taint"
    label = "Crypto sanctions check (local list)"
    description = (
        "Checks a Bitcoin or Ethereum address against the sanctions designations loaded on "
        "this instance, and flags mixer designations. Offline: no chain or provider lookup."
    )
    supported_types: ClassVar[tuple[ObservableType, ...]] = (ObservableType.CRYPTO,)
    provider = ProviderInfo(
        name="Local sanctions list",
        url="https://ofac.treasury.gov/sanctions-list-service",
        api_base_url="(none: reads a local directory)",
        credential_url="",
        free_tier="Free; the OFAC SDN list is public.",
        rate_limit="None; bounded by the analyzer timeout.",
        notes=(
            "Designation check only. The list is whatever was placed in the crypto intel "
            "directory; it is not refreshed here and it does not trace transactions."
        ),
    )
    max_tlp = Tlp.RED
    documentation_url = "https://ofac.treasury.gov/sanctions-list-service"
    free_tier = True
    default_timeout = 30
    default_cache_ttl = 3600
    maturity = "alpha"

    async def run(self, observable: Observable) -> PluginResult:
        snap = await asyncio.to_thread(crypto_intel.snapshot)
        if snap.count == 0:
            return self.skipped(
                "No sanctions list is loaded. Place an OFAC SDN XML or a plain address list in "
                "the crypto intel directory."
            )

        hit = snap.lookup(observable.value)
        raw: dict[str, Any] = {
            "address": observable.value,
            "list_entries": snap.count,
            "list_sources": [{"file": name, "sha256": digest} for name, digest in snap.sources],
            "designation": None,
        }
        if hit is None:
            summary = PluginSummary(
                verdict=Verdict.UNKNOWN,
                score=None,
                tags=[],
                headline=(
                    "Not on the loaded sanctions list. This does not prove the address is clean."
                ),
                extra={"designated": False},
            )
            return self.ok(raw, summary)

        mixer = crypto_intel.is_mixer(hit.label)
        tags = ["sanctioned-address"] + (["mixer"] if mixer else [])
        raw["designation"] = {"label": hit.label, "source": hit.source, "mixer": mixer}
        summary = PluginSummary(
            verdict=Verdict.MALICIOUS,
            score=90,
            tags=tags,
            headline=f"Designated on the loaded sanctions list: {hit.label}.",
            extra={"designated": True, "label": hit.label, "mixer": mixer},
        )
        return self.ok(raw, summary)
