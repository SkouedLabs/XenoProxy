"""Secure DNS (DNS-over-HTTPS) resolvers: is the domain filtered or sinkholed?

Cloudflare and Google answer the question without filtering by default, so an
NXDOMAIN from them only means the name does not exist. Quad9 blocks known-bad
names by answering NXDOMAIN or a sinkhole address. The signal therefore comes
from disagreement: one resolver refusing a name that another one resolves is a
filter at work, and a block page address is a block, whatever the resolver.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, ClassVar
from urllib.parse import quote

from app.core import http_client
from app.models.job import ObservableType, Tlp, Verdict
from app.plugins.base.analyzer import BaseAnalyzer
from app.plugins.base.plugin import PluginResult, PluginSummary, ProviderInfo
from app.plugins.base.registry import register
from app.services.observables import Observable, hostname_of

_RCODE_OK = 0
_RCODE_NXDOMAIN = 3
_RECORD_A = 1
_RECORD_AAAA = 28
# Block-page addresses a resolver answers with; nothing here is bound to.
_SINKHOLES = frozenset({"0.0.0.0", "::", "::0"})  # noqa: S104  # nosec B104


@dataclass(frozen=True)
class _Resolver:
    key: str
    label: str
    endpoint: str


_RESOLVERS: tuple[_Resolver, ...] = (
    _Resolver("cloudflare", "Cloudflare", "https://cloudflare-dns.com/dns-query"),
    _Resolver("google", "Google", "https://dns.google/resolve"),
    _Resolver("quad9", "Quad9", "https://dns.quad9.net/dns-query"),
)


def _classify(body: dict[str, Any]) -> str:
    """One of: resolves, nxdomain, sinkhole, empty, error."""
    status = body.get("Status")
    if status == _RCODE_NXDOMAIN:
        return "nxdomain"
    if status != _RCODE_OK:
        return "error"
    addresses = [
        str(answer.get("data", "")).strip()
        for answer in body.get("Answer") or []
        if isinstance(answer, dict) and answer.get("type") in {_RECORD_A, _RECORD_AAAA}
    ]
    if not addresses:
        return "empty"
    if all(address in _SINKHOLES for address in addresses):
        return "sinkhole"
    return "resolves"


def _verdict(outcomes: dict[str, str]) -> Verdict:
    values = set(outcomes.values())
    if "sinkhole" in values:
        return Verdict.SUSPICIOUS
    if "resolves" in values and "nxdomain" in values:
        # One resolver refuses a name another one resolves: a filter is in play.
        return Verdict.SUSPICIOUS
    if "resolves" in values:
        return Verdict.CLEAN
    return Verdict.UNKNOWN


@register
class DohResolversAnalyzer(BaseAnalyzer):
    """Asks three public secure-DNS resolvers whether they resolve a name."""

    name = "doh_resolvers"
    label = "Secure DNS resolvers (DoH)"
    description = "Whether Cloudflare, Google and Quad9 resolve the name, or block it."
    supported_types: ClassVar[tuple[ObservableType, ...]] = (
        ObservableType.DOMAIN,
        ObservableType.URL,
    )
    requires_network = True
    maturity = "alpha"
    provider = ProviderInfo(
        name="Cloudflare, Google, Quad9",
        url="https://quad9.net/",
        api_base_url=(
            "https://cloudflare-dns.com/dns-query · https://dns.google/resolve · "
            "https://dns.quad9.net/dns-query"
        ),
        free_tier="Public resolvers, no key.",
        rate_limit="Fair use; each lookup asks three resolvers.",
        notes=(
            "The name is sent to three third-party resolvers over HTTPS. Cloudflare and Google "
            "do not filter by default; Quad9 does."
        ),
    )
    max_tlp = Tlp.AMBER
    documentation_url = "https://developers.google.com/speed/public-dns/docs/doh/json"
    free_tier = True
    default_timeout = 10
    default_cache_ttl = 3600

    async def run(self, observable: Observable) -> PluginResult:
        hostname = hostname_of(observable)
        if not hostname:
            return self.not_found("No hostname to resolve.")

        outcomes: dict[str, str] = {}
        bodies: dict[str, Any] = {}
        for resolver in _RESOLVERS:
            response = await http_client.get(
                f"{resolver.endpoint}?name={quote(hostname, safe='')}&type=A",
                headers={"Accept": "application/dns-json"},
                timeout=self.timeout,
            )
            if not response.ok or not isinstance(response.json_body, dict):
                outcomes[resolver.key] = "error"
                continue
            body = response.json_body
            outcomes[resolver.key] = _classify(body)
            bodies[resolver.key] = {"status": body.get("Status"), "outcome": outcomes[resolver.key]}

        if all(outcome == "error" for outcome in outcomes.values()):
            return self.failed("No secure DNS resolver answered.")

        verdict = _verdict(outcomes)
        filtered_by = sorted(
            resolver.label
            for resolver in _RESOLVERS
            if outcomes.get(resolver.key) in {"nxdomain", "sinkhole"}
        )
        if verdict is Verdict.SUSPICIOUS and "sinkhole" in outcomes.values():
            headline = f"Sinkholed by a secure DNS resolver ({', '.join(filtered_by)})."
        elif verdict is Verdict.SUSPICIOUS:
            headline = f"Refused by {', '.join(filtered_by)} while others resolve it."
        elif verdict is Verdict.CLEAN:
            headline = "Resolved normally by every secure DNS resolver."
        else:
            headline = "No resolver returned an address for this name."

        summary = PluginSummary(
            verdict=verdict,
            tags=["dns-filtered"] if verdict is Verdict.SUSPICIOUS else [],
            headline=headline,
            extra={"hostname": hostname, "resolvers": bodies, "outcomes": outcomes},
        )
        return self.ok({"hostname": hostname, "outcomes": outcomes}, summary)
