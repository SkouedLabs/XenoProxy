"""Phone observables and the local phone metadata analyzer. Nothing here leaves the process."""

from __future__ import annotations

import pytest

from app.models.job import ObservableType, ReportStatus, Verdict
from app.plugins.analyzer.phone_info import PhoneInfoAnalyzer
from app.services.observables import classify


@pytest.mark.parametrize(
    "raw",
    ["+33 6 12 34 56 78", "+33.6.12.34.56.78", "+33-6-12-34-56-78", "(+33) 612345678"],
)
def test_international_numbers_classify_as_phone_in_one_form(raw: str) -> None:
    observable = classify(raw)
    assert observable.type is ObservableType.PHONE
    assert observable.value == "+33612345678"


def test_a_number_without_a_plus_is_not_a_phone() -> None:
    assert classify("0612345678").type is ObservableType.GENERIC


def test_other_observables_are_not_taken_for_phones() -> None:
    assert classify("8.8.8.8").type is ObservableType.IP
    assert classify("example.com").type is ObservableType.DOMAIN


async def test_a_mobile_number_is_unknown_with_its_country() -> None:
    result = await PhoneInfoAnalyzer().execute(classify("+33612345678"))
    summary = result.summary.as_dict()
    assert result.status is ReportStatus.SUCCESS
    assert result.raw_output["country"] == "France"
    assert result.raw_output["line_type"] == "mobile"
    assert result.raw_output["valid"] is True
    assert summary["verdict"] == Verdict.UNKNOWN.value
    assert summary["score"] is None
    assert "line-mobile" in summary["tags"]


async def test_a_premium_rate_number_is_suspicious_not_malicious() -> None:
    result = await PhoneInfoAnalyzer().execute(classify("+1 900 555 0123"))
    summary = result.summary.as_dict()
    assert summary["verdict"] == Verdict.SUSPICIOUS.value
    assert "premium-rate" in summary["tags"]


async def test_an_invalid_number_is_flagged_and_stays_unknown() -> None:
    result = await PhoneInfoAnalyzer().execute(classify("+4411111111"))
    summary = result.summary.as_dict()
    assert result.raw_output["valid"] is False
    assert "invalid-number" in summary["tags"]
    assert summary["verdict"] == Verdict.UNKNOWN.value
