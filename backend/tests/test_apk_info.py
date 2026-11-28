"""APK_Info: the risk combinations and the verdict, against a stubbed manifest.

The real Androguard parser runs only on a non-APK zip, to check that hostile input is
a clean failure. No real or synthetic APK is built here: a binary manifest is not
hand-assembled. Parser behaviour on real packages is unverified.
"""

from __future__ import annotations

import pytest

from app.models.job import ObservableType, ReportStatus, Verdict
from app.plugins.analyzer import apk_info
from app.plugins.analyzer.apk_info import ApkInfoAnalyzer, Manifest, matched_indicators
from app.plugins.base.plugin import SampleAccess
from app.services.observables import Observable

_SHA = "b" * 64
_PREFIX = "android.permission."


def _manifest(*permissions: str) -> Manifest:
    return Manifest(
        package="com.example.app",
        permissions={_PREFIX + p for p in permissions},
        activities=["com.example.app.Main"],
        services=[],
        receivers=[],
        min_sdk=21,
        target_sdk=33,
    )


def _analyzer(payload: bytes | None) -> ApkInfoAnalyzer:
    sample = (
        None
        if payload is None
        else SampleAccess(sha256=_SHA, file_name="a.apk", read_local=lambda: payload)
    )
    return ApkInfoAnalyzer(sample=sample)


def _observable() -> Observable:
    return Observable(value=_SHA, type=ObservableType.FILE)


def test_accessibility_with_overlay_is_a_high_indicator() -> None:
    names = [
        i.name
        for i in matched_indicators(
            {_PREFIX + "BIND_ACCESSIBILITY_SERVICE", _PREFIX + "SYSTEM_ALERT_WINDOW"}
        )
    ]
    assert "accessibility-overlay" in names


def test_one_sensitive_permission_alone_is_a_tag_only() -> None:
    found = matched_indicators({_PREFIX + "RECORD_AUDIO"})
    assert [i.severity for i in found] == ["info"]


def test_accessibility_without_its_companions_is_not_high() -> None:
    found = matched_indicators({_PREFIX + "BIND_ACCESSIBILITY_SERVICE"})
    assert {i.severity for i in found} == {"info"}


def test_short_and_full_permission_names_both_match() -> None:
    assert matched_indicators({"RECEIVE_SMS", "READ_SMS"})
    assert matched_indicators({_PREFIX + "RECEIVE_SMS", _PREFIX + "READ_SMS"})


async def test_an_overlay_trojan_shape_is_suspicious_never_malicious(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        apk_info,
        "read_manifest",
        lambda _p: _manifest("BIND_ACCESSIBILITY_SERVICE", "SYSTEM_ALERT_WINDOW", "INTERNET"),
    )
    result = await _analyzer(b"PK\x03\x04stub").execute(_observable())
    summary = result.summary.as_dict()
    assert result.status is ReportStatus.SUCCESS
    assert summary["verdict"] == Verdict.SUSPICIOUS.value
    assert "accessibility-overlay" in summary["tags"]


async def test_an_ordinary_app_is_unknown_not_clean(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(apk_info, "read_manifest", lambda _p: _manifest("INTERNET"))
    result = await _analyzer(b"PK\x03\x04stub").execute(_observable())
    summary = result.summary.as_dict()
    assert summary["verdict"] == Verdict.UNKNOWN.value
    assert summary["score"] is None


async def test_a_package_is_described_by_its_name_and_counts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(apk_info, "read_manifest", lambda _p: _manifest("INTERNET", "CAMERA"))
    result = await _analyzer(b"PK\x03\x04stub").execute(_observable())
    assert result.raw_output["package"] == "com.example.app"
    assert result.raw_output["min_sdk"] == 21


async def test_a_zip_that_is_not_an_apk_fails_cleanly() -> None:
    result = await _analyzer(b"PK\x03\x04" + b"\x00" * 64).execute(_observable())
    assert result.status is ReportStatus.FAILED
    assert "not a readable Android package" in (result.error or "")


async def test_a_file_that_is_not_a_zip_is_skipped() -> None:
    result = await _analyzer(b"%PDF-1.7\n").execute(_observable())
    assert result.status is ReportStatus.SKIPPED


async def test_a_job_without_a_file_is_skipped() -> None:
    result = await _analyzer(None).execute(_observable())
    assert result.status is ReportStatus.SKIPPED
