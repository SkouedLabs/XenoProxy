"""Crypto observables, the local sanctions index, and the crypto_taint verdicts.

Every address here is synthetic; no real designation is used, and nothing is looked up.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.models.job import ObservableType, ReportStatus, Verdict
from app.plugins.analyzer.crypto_taint import CryptoTaintAnalyzer
from app.services import crypto_intel
from app.services.observables import classify

_ETH = "0x" + "ab" * 20
_BTC = "1" + "B" * 33  # base58, no 0 O I l
_BECH = "bc1" + "q" * 30
_SDN = f"""<?xml version="1.0"?>
<sdnList xmlns="urn:test">
  <sdnEntry>
    <uid>1</uid><firstName>Test</firstName><lastName>Mixer Co</lastName>
    <idList>
      <id><idType>Digital Currency Address - ETH</idType><idNumber>{_ETH}</idNumber></id>
      <id><idType>Passport</idType><idNumber>X123</idNumber></id>
    </idList>
  </sdnEntry>
</sdnList>
"""


@pytest.fixture(autouse=True)
def _fresh_cache() -> None:
    crypto_intel._cache.clear()


def test_ethereum_bitcoin_and_bech32_addresses_are_crypto() -> None:
    assert classify(_ETH.upper().replace("0X", "0x")).type is ObservableType.CRYPTO
    assert classify(_ETH).value == _ETH
    assert classify(_BTC).type is ObservableType.CRYPTO
    assert classify(_BECH).type is ObservableType.CRYPTO


def test_hashes_domains_and_ordinary_words_are_not_crypto() -> None:
    assert classify("a" * 64).type is ObservableType.HASH
    assert classify("example.com").type is ObservableType.DOMAIN
    assert classify("0xnotanaddress").type is ObservableType.GENERIC


def test_a_plain_list_with_labels_and_a_header_is_read(tmp_path: Path) -> None:
    (tmp_path / "list.csv").write_text(
        f"address,label\n# comment\n{_ETH},Example Mixer\n{_BTC}\n", encoding="utf-8"
    )
    snap = crypto_intel.snapshot(str(tmp_path))
    assert snap.count == 2
    assert snap.lookup(_ETH.upper().replace("0X", "0x")).label == "Example Mixer"
    assert snap.lookup(_BTC).label == "listed"


def test_an_sdn_xml_yields_its_digital_currency_addresses(tmp_path: Path) -> None:
    (tmp_path / "sdn.xml").write_text(_SDN, encoding="utf-8")
    snap = crypto_intel.snapshot(str(tmp_path))
    hit = snap.lookup(_ETH)
    assert hit is not None
    assert hit.label == "Test Mixer Co"
    assert snap.count == 1  # the passport identifier is not an address


def test_an_empty_or_missing_directory_has_no_entries(tmp_path: Path) -> None:
    assert crypto_intel.snapshot(str(tmp_path / "absent")).count == 0
    assert crypto_intel.snapshot(str(tmp_path)).count == 0


async def test_without_a_list_the_analyzer_is_skipped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(crypto_intel, "get_settings", _settings(tmp_path / "none"))
    result = await CryptoTaintAnalyzer().execute(classify(_ETH))
    assert result.status is ReportStatus.SKIPPED


async def test_a_designated_address_is_malicious_with_its_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "sdn.xml").write_text(_SDN, encoding="utf-8")
    monkeypatch.setattr(crypto_intel, "get_settings", _settings(tmp_path))
    result = await CryptoTaintAnalyzer().execute(classify(_ETH))
    summary = result.summary.as_dict()
    assert summary["verdict"] == Verdict.MALICIOUS.value
    assert result.raw_output["designation"]["label"] == "Test Mixer Co"
    assert "sanctioned-address" in summary["tags"]
    assert result.raw_output["list_sources"][0]["file"] == "sdn.xml"


async def test_a_mixer_designation_is_tagged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "list.txt").write_text(f"{_ETH},Tornado Cash Router\n", encoding="utf-8")
    monkeypatch.setattr(crypto_intel, "get_settings", _settings(tmp_path))
    summary = (await CryptoTaintAnalyzer().execute(classify(_ETH))).summary.as_dict()
    assert "mixer" in summary["tags"]


async def test_an_address_off_the_list_is_unknown_not_clean(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "list.txt").write_text(f"{_ETH}\n", encoding="utf-8")
    monkeypatch.setattr(crypto_intel, "get_settings", _settings(tmp_path))
    summary = (await CryptoTaintAnalyzer().execute(classify(_BECH))).summary.as_dict()
    assert summary["verdict"] == Verdict.UNKNOWN.value
    assert summary["score"] is None


def _settings(path: Path):  # type: ignore[no-untyped-def]
    class _S:
        crypto_intel_dir = str(path)

    return lambda: _S()
