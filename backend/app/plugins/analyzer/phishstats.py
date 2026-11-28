"""PhishStats: phishing URLs and the hosts serving them, from a scored public feed."""

from __future__ import annotations

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

_ENDPOINT = "https://api.phishstats.info/api/phishing"
_MAX_RECORDS = 20


@register
class PhishStatsAnalyzer(BaseAnalyzer):
    """Looks a URL or an address up in the PhishStats phishing feed.

    A feed record is a machine-scored sighting, not a confirmed verdict. The
    verdict is Malicious only when a record reaches the phishscore threshold;
    any lower-scored sighting is Suspicious, and no sighting is Unknown, never
    Clean, because a feed that does not list a URL has not said it is safe.
    """

    name = "phishstats"
    label = "PhishStats"
    description = "Phishing sightings with a machine-learned phishscore."
    supported_types: ClassVar[tuple[ObservableType, ...]] = (
        ObservableType.URL,
        ObservableType.IP,
    )
    secrets: ClassVar[tuple[SecretSpec, ...]] = (
        SecretSpec(
            "api_key",
            "PhishStats API key (optional)",
            required=False,
            help_text=(
                "Optional. Without a key, anonymous access is capped at 50 requests a day; "
                "a key raises the limit. Created in PhishStats settings, API keys."
            ),
            user_overridable=True,
        ),
    )
    options_schema: ClassVar[dict[str, Any]] = {
        "malicious_score": {
            "type": "integer",
            "default": 5,
            "label": "Phishscore from which a sighting is Malicious (0-10)",
        },
    }
    provider = ProviderInfo(
        name="PhishStats",
        url="https://phishstats.info/",
        api_base_url="https://api.phishstats.info/api/phishing?_where=(url|ip,eq,<value>)",
        credential_url="https://phishstats.info/",
        free_tier="Anonymous access, 50 requests a day per IP; a free key gives 150 a day.",
        rate_limit="50 a day anonymous; the feed refreshes about every 90 minutes.",
        notes="Matching is exact: a URL is found only as it was reported.",
    )
    max_tlp = Tlp.AMBER
    documentation_url = "https://phishstats.info/"
    free_tier = True
    default_timeout = 20
    default_cache_ttl = 3600
    maturity = "alpha"

    def _where(self, observable: Observable) -> str:
        field = "ip" if observable.type is ObservableType.IP else "url"
        return f"({field},eq,{quote(observable.value, safe='')})"

    async def run(self, observable: Observable) -> PluginResult:
        headers: dict[str, str] = {}
        key = self.optional_secret("api_key")
        if key:
            headers["X-API-Key"] = key

        response = await http_client.get(
            f"{_ENDPOINT}?_where={self._where(observable)}&_sort=-date&_size={_MAX_RECORDS}",
            headers=headers,
            timeout=self.timeout,
        )
        if response.status_code == 429:
            raise PluginQuotaError("PhishStats returned HTTP 429 (daily quota exhausted).")
        if not response.ok:
            return self.provider_http_error(response.status_code)

        body = response.json_body
        records = (
            [item for item in body if isinstance(item, dict)] if isinstance(body, list) else []
        )
        if not records:
            return self.not_found("Not present in the PhishStats feed.")

        threshold = int(self.option("malicious_score", 5))
        scores = [float(record.get("score") or 0) for record in records]
        top = max(scores)
        verdict = Verdict.MALICIOUS if top >= threshold else Verdict.SUSPICIOUS
        hosts = sorted({str(record["ip"]) for record in records if record.get("ip")})
        countries = sorted(
            {str(record["countrycode"]) for record in records if record.get("countrycode")}
        )

        summary = PluginSummary(
            verdict=verdict,
            score=min(100, int(top * 10)),
            tags=["phishing"],
            headline=(
                f"{len(records)} phishing sighting(s) in PhishStats, top phishscore {top:g}."
            ),
            country=countries[0] if len(countries) == 1 else None,
            extra={
                "sightings": len(records),
                "top_score": top,
                "hosts": hosts,
                "records": [
                    {
                        "date": record.get("date"),
                        "ip": record.get("ip"),
                        "score": record.get("score"),
                        "asn": record.get("asn"),
                    }
                    for record in records[:_MAX_RECORDS]
                ],
            },
        )
        return self.ok(body, summary)
