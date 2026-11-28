"""Phone metadata from the numbering plans, read locally with libphonenumber.

This is the offline part of PhoneInfoga and Phunter: country, a line type and the
original carrier, taken from the public numbering plans. It makes no live lookup, so
the number is never sent to a provider and the analysis is safe at TLP:RED.

What it cannot tell you: whether the number is in service now, or which carrier it is
on after number portability. A live HLR lookup or a commercial lookup API would answer
those, and would send the number outward; that is a separate, opt-in decision.

Verdict. Metadata describes a number; it does not condemn it. A premium-rate or
shared-cost number is the usual vehicle for toll-fraud and "wangiri" scams, so it is
Suspicious. Everything else is Unknown, and nothing is Clean from metadata alone.
"""

from __future__ import annotations

from typing import Any, ClassVar

import phonenumbers
from phonenumbers import PhoneNumberType, carrier, geocoder, timezone

from app.models.job import ObservableType, Tlp, Verdict
from app.plugins.base.analyzer import BaseAnalyzer
from app.plugins.base.plugin import PluginResult, PluginSummary, ProviderInfo
from app.plugins.base.registry import register
from app.services.observables import Observable

# phonenumbers exposes line types as integer constants on a plain class, not an enum.
_LINE_NAMES = {
    value: name.lower()
    for name, value in vars(PhoneNumberType).items()
    if name.isupper() and isinstance(value, int)
}
_FRAUD_TYPES = {PhoneNumberType.PREMIUM_RATE, PhoneNumberType.SHARED_COST}


def line_type(number: phonenumbers.PhoneNumber) -> str:
    return _LINE_NAMES.get(phonenumbers.number_type(number), "unknown")


@register
class PhoneInfoAnalyzer(BaseAnalyzer):
    """Country, line type and original carrier of an international phone number."""

    name = "phone_info"
    label = "Phone metadata (libphonenumber)"
    description = (
        "Country, line type and original carrier of an international phone number, from the "
        "public numbering plans. Offline: the number is never sent anywhere."
    )
    supported_types: ClassVar[tuple[ObservableType, ...]] = (ObservableType.PHONE,)
    provider = ProviderInfo(
        name="Local libphonenumber",
        url="https://github.com/daviddrysdale/python-phonenumbers",
        api_base_url="(none: runs locally)",
        credential_url="",
        free_tier="Free; no account.",
        rate_limit="None; bounded by the analyzer timeout.",
        notes=(
            "Reads the numbering plans only. Line type and carrier are the allocation, not a "
            "live lookup: a ported or disconnected number still reads as it was allocated."
        ),
    )
    max_tlp = Tlp.RED
    documentation_url = "https://github.com/daviddrysdale/python-phonenumbers"
    free_tier = True
    default_timeout = 10
    default_cache_ttl = 86400
    maturity = "alpha"

    async def run(self, observable: Observable) -> PluginResult:
        try:
            number = phonenumbers.parse(observable.value)
        except phonenumbers.NumberParseException:
            return self.failed("The number could not be parsed in international format.")

        valid = phonenumbers.is_valid_number(number)
        region = phonenumbers.region_code_for_number(number) or ""
        country = geocoder.description_for_number(number, "en") or region or "unknown"
        kind = line_type(number)
        carrier_name = carrier.name_for_number(number, "en") or ""
        zones = list(timezone.time_zones_for_number(number))

        tags = [f"line-{kind}"] if kind != "unknown" else []
        if not valid:
            tags.append("invalid-number")
        if carrier_name:
            tags.append("carrier-known")
        suspicious = phonenumbers.number_type(number) in _FRAUD_TYPES
        if suspicious:
            tags.append("premium-rate")

        verdict = Verdict.SUSPICIOUS if suspicious else Verdict.UNKNOWN
        score = 40 if suspicious else None

        raw: dict[str, Any] = {
            "e164": phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.E164),
            "international": phonenumbers.format_number(
                number, phonenumbers.PhoneNumberFormat.INTERNATIONAL
            ),
            "valid": valid,
            "country": country,
            "region": region,
            "line_type": kind,
            "carrier": carrier_name,
            "time_zones": zones,
        }
        if suspicious:
            headline = f"{kind} number in {country}: a common toll-fraud vector."
        else:
            headline = f"{kind} number in {country}" + ("" if valid else " (not a valid number)")
        summary = PluginSummary(
            verdict=verdict,
            score=score,
            tags=tags,
            headline=headline,
            extra={"country": country, "line_type": kind, "carrier": carrier_name},
        )
        return self.ok(raw, summary)
