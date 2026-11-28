"""Alpha analyzers (DoH resolvers, PhishStats, Shodan Honeyscore), checked against mocks only.

None of these contracts has been exercised against the live provider yet; the
tests pin how a response is read, not that the provider still answers this way.
"""

from __future__ import annotations

import httpx
import respx

from app.models.job import ReportStatus, Verdict
from app.plugins import load_all
from app.plugins.analyzer.doh_resolvers import DohResolversAnalyzer
from app.plugins.analyzer.phishstats import PhishStatsAnalyzer
from app.plugins.analyzer.shodan_honeyscore import ShodanHoneyscoreAnalyzer
from app.plugins.base.registry import describe, iter_analyzers
from app.services.observables import classify

_CF = "https://cloudflare-dns.com/dns-query"
_GOOGLE = "https://dns.google/resolve"
_QUAD9 = "https://dns.quad9.net/dns-query"


def _answer(address: str) -> dict:
    return {"Status": 0, "Answer": [{"name": "x.", "type": 1, "data": address}]}


def _nx() -> dict:
    return {"Status": 3}


def _mock_resolvers(cloudflare: dict, google: dict, quad9: dict) -> None:
    respx.get(url__startswith=_CF).mock(return_value=httpx.Response(200, json=cloudflare))
    respx.get(url__startswith=_GOOGLE).mock(return_value=httpx.Response(200, json=google))
    respx.get(url__startswith=_QUAD9).mock(return_value=httpx.Response(200, json=quad9))


# -- DoH resolvers -----------------------------------------------------------


@respx.mock
async def test_doh_all_resolvers_agree_is_clean() -> None:
    _mock_resolvers(_answer("93.184.216.34"), _answer("93.184.216.34"), _answer("93.184.216.34"))
    result = await DohResolversAnalyzer().execute(classify("example.com"))
    assert result.status is ReportStatus.SUCCESS
    assert result.summary.as_dict()["verdict"] == Verdict.CLEAN.value


@respx.mock
async def test_doh_quad9_refusing_a_resolved_name_is_suspicious() -> None:
    _mock_resolvers(_answer("203.0.113.7"), _answer("203.0.113.7"), _nx())
    result = await DohResolversAnalyzer().execute(classify("evil.example.com"))
    summary = result.summary.as_dict()
    assert summary["verdict"] == Verdict.SUSPICIOUS.value
    assert "Quad9" in summary["headline"]


@respx.mock
async def test_doh_sinkhole_address_is_suspicious() -> None:
    _mock_resolvers(_answer("0.0.0.0"), _answer("0.0.0.0"), _answer("0.0.0.0"))  # noqa: S104 - sinkhole
    result = await DohResolversAnalyzer().execute(classify("blocked.example.com"))
    assert result.summary.as_dict()["verdict"] == Verdict.SUSPICIOUS.value


@respx.mock
async def test_doh_nxdomain_everywhere_is_unknown_not_clean() -> None:
    _mock_resolvers(_nx(), _nx(), _nx())
    result = await DohResolversAnalyzer().execute(classify("gone.example.com"))
    assert result.summary.as_dict()["verdict"] == Verdict.UNKNOWN.value


@respx.mock
async def test_doh_fails_only_when_every_resolver_fails() -> None:
    respx.get(url__startswith=_CF).mock(return_value=httpx.Response(503))
    respx.get(url__startswith=_GOOGLE).mock(return_value=httpx.Response(503))
    respx.get(url__startswith=_QUAD9).mock(return_value=httpx.Response(500))
    result = await DohResolversAnalyzer().execute(classify("example.com"))
    assert result.status is ReportStatus.FAILED


@respx.mock
async def test_doh_survives_one_resolver_being_down() -> None:
    respx.get(url__startswith=_CF).mock(return_value=httpx.Response(503))
    respx.get(url__startswith=_GOOGLE).mock(
        return_value=httpx.Response(200, json=_answer("1.1.1.1"))
    )
    respx.get(url__startswith=_QUAD9).mock(
        return_value=httpx.Response(200, json=_answer("1.1.1.1"))
    )
    result = await DohResolversAnalyzer().execute(classify("example.com"))
    assert result.status is ReportStatus.SUCCESS
    assert result.summary.as_dict()["verdict"] == Verdict.CLEAN.value


# -- PhishStats ---------------------------------------------------------------

_PHISH_URL = "https://api.phishstats.info/api/phishing"


@respx.mock
async def test_phishstats_high_score_is_malicious() -> None:
    respx.get(url__startswith=_PHISH_URL).mock(
        return_value=httpx.Response(
            200,
            json=[
                {
                    "id": 1,
                    "url": "hxxps://bad[.]example",
                    "ip": "198.51.100.9",
                    "score": 8.2,
                    "countrycode": "US",
                    "asn": "AS64496",
                    "date": "2026-11-20T10:00:00Z",
                }
            ],
        )
    )
    result = await PhishStatsAnalyzer().execute(classify("https://bad.example/login"))
    summary = result.summary.as_dict()
    assert result.status is ReportStatus.SUCCESS
    assert summary["verdict"] == Verdict.MALICIOUS.value
    assert "phishing" in summary["tags"]


@respx.mock
async def test_phishstats_low_score_is_suspicious_not_malicious() -> None:
    respx.get(url__startswith=_PHISH_URL).mock(
        return_value=httpx.Response(200, json=[{"ip": "198.51.100.9", "score": 2.1}])
    )
    result = await PhishStatsAnalyzer().execute(classify("198.51.100.9"))
    assert result.summary.as_dict()["verdict"] == Verdict.SUSPICIOUS.value


@respx.mock
async def test_phishstats_absence_is_unknown_not_clean() -> None:
    respx.get(url__startswith=_PHISH_URL).mock(return_value=httpx.Response(200, json=[]))
    result = await PhishStatsAnalyzer().execute(classify("198.51.100.9"))
    assert result.status is ReportStatus.SUCCESS
    assert result.summary.as_dict()["verdict"] == Verdict.UNKNOWN.value


@respx.mock
async def test_phishstats_quota_is_reported_as_a_failure() -> None:
    respx.get(url__startswith=_PHISH_URL).mock(return_value=httpx.Response(429))
    result = await PhishStatsAnalyzer().execute(classify("198.51.100.9"))
    assert result.status is ReportStatus.FAILED
    assert "429" in (result.error or "")


# -- Shodan Honeyscore --------------------------------------------------------


@respx.mock
async def test_honeyscore_high_value_flags_a_honeypot() -> None:
    route = respx.get(url__startswith="https://api.shodan.io/labs/honeyscore/8.8.8.8").mock(
        return_value=httpx.Response(200, json=0.92)
    )
    result = await ShodanHoneyscoreAnalyzer(secrets={"api_key": "k" * 16}).execute(
        classify("8.8.8.8")
    )
    summary = result.summary.as_dict()
    assert route.called
    assert summary["verdict"] == Verdict.SUSPICIOUS.value
    assert summary["score"] == 92
    assert "honeypot" in summary["tags"]


@respx.mock
async def test_honeyscore_low_value_is_clean() -> None:
    respx.get(url__startswith="https://api.shodan.io/labs/honeyscore/").mock(
        return_value=httpx.Response(200, json=0.03)
    )
    result = await ShodanHoneyscoreAnalyzer(secrets={"api_key": "k" * 16}).execute(
        classify("8.8.4.4")
    )
    assert result.summary.as_dict()["verdict"] == Verdict.CLEAN.value


@respx.mock
async def test_honeyscore_out_of_range_value_is_rejected() -> None:
    respx.get(url__startswith="https://api.shodan.io/labs/honeyscore/").mock(
        return_value=httpx.Response(200, json=7.5)
    )
    result = await ShodanHoneyscoreAnalyzer(secrets={"api_key": "k" * 16}).execute(
        classify("8.8.4.4")
    )
    assert result.status is ReportStatus.FAILED


@respx.mock
async def test_honeyscore_non_numeric_body_is_rejected() -> None:
    respx.get(url__startswith="https://api.shodan.io/labs/honeyscore/").mock(
        return_value=httpx.Response(200, json={"error": "plan"})
    )
    result = await ShodanHoneyscoreAnalyzer(secrets={"api_key": "k" * 16}).execute(
        classify("8.8.4.4")
    )
    assert result.status is ReportStatus.FAILED


# -- Maturity ----------------------------------------------------------------


def test_new_analyzers_declare_alpha_maturity_and_the_rest_stay_stable() -> None:
    load_all()
    alpha = {
        "doh_resolvers",
        "phishstats",
        "shodan_honeyscore",
        "yaraify",
        "emailrep",
        "hibp",
        "yara_local",
        "doc_info",
        "strings_info",
        "intezer",
        "triage",
        "cape",
        "dehashed",
        "file_info",
        "capa",
        "apk_info",
        "phone_info",
        "crypto_taint",
    }
    seen = {cls.name: describe(cls)["maturity"] for cls in iter_analyzers()}
    for name in alpha:
        assert seen[name] == "alpha", name
    for name, maturity in seen.items():
        if name not in alpha:
            assert maturity == "stable", name
