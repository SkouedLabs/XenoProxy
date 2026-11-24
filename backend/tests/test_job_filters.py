"""The job listing filters: validation and the SQL they produce."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from sqlalchemy.dialects import postgresql

from app.api.v1.jobs import _filtered_jobs, _ordered, job_filters
from app.core.errors import ValidationFailedError
from app.models.job import ReportStatus

ADMIN = SimpleNamespace(is_admin=True, group_ids=[], id=None)


def _filters(**overrides):
    values = {
        "search": None,
        "job_status": None,
        "job_verdict": None,
        "observable_type": None,
        "tag": None,
        "requested_by": None,
        "job_tlp": None,
        "origin": None,
        "derived": None,
        "created_from": None,
        "created_to": None,
        "plugin": None,
        "plugin_status": None,
        "order": "desc",
    }
    values.update(overrides)
    return job_filters(**values)


def test_a_naive_date_is_read_as_utc() -> None:
    parsed = _filters(created_from=datetime(2026, 11, 1))
    assert parsed.created_from == datetime(2026, 11, 1, tzinfo=UTC)


def test_an_inverted_date_range_is_refused() -> None:
    with pytest.raises(ValidationFailedError):
        _filters(
            created_from=datetime(2026, 11, 5, tzinfo=UTC),
            created_to=datetime(2026, 11, 1, tzinfo=UTC),
        )


def test_a_plugin_status_without_a_plugin_is_refused() -> None:
    with pytest.raises(ValidationFailedError):
        _filters(plugin_status=ReportStatus.FAILED)


def test_the_plugin_name_and_status_must_match_the_same_report() -> None:
    parsed = _filters(
        plugin="refexposer",
        plugin_status=ReportStatus.SUCCESS,
        created_from=datetime(2026, 11, 1, tzinfo=UTC),
        created_to=datetime(2026, 11, 20, tzinfo=UTC),
        requested_by="user",
        order="asc",
    )
    statement = _ordered(_filtered_jobs(ADMIN, parsed), parsed.order)
    sql = str(statement.compile(dialect=postgresql.dialect())).replace("\n", " ")

    # One EXISTS carries both conditions: two separate EXISTS would let the name
    # and the status match different reports.
    assert sql.count("EXISTS") == 1
    exists = sql[sql.index("EXISTS") :]
    assert "plugin_reports.plugin_name = " in exists
    assert "plugin_reports.status = " in exists
    assert "jobs.created_at >=" in sql
    assert "jobs.created_at <=" in sql
    assert sql.rstrip().endswith("ORDER BY jobs.created_at ASC, jobs.id ASC")
