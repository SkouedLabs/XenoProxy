"""Anonymous submission: fixed playbook, forced TLP, and a reduced view of the result."""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest

from app.api.v1 import public as public_module
from app.api.v1.public import PUBLIC_PLAYBOOK, _public_view
from app.core.errors import NotFoundError
from app.models.job import JobOrigin, JobStatus, PluginKind, ReportStatus, Verdict
from app.services.bootstrap import BUILTIN_PLAYBOOKS
from app.services.settings_store import BY_KEY


def test_public_submission_is_off_by_default() -> None:
    assert BY_KEY["public_submission"].default is False


def test_the_public_playbook_only_uses_observables_and_lookups() -> None:
    playbook = next(item for item in BUILTIN_PLAYBOOKS if item["name"] == PUBLIC_PLAYBOOK)

    assert set(playbook["observable_types"]) == {"ip", "domain", "url", "hash"}
    # Connectors publish outside the instance and pivots create more work: neither
    # is offered to an anonymous caller.
    assert not playbook.get("connectors")
    assert not playbook.get("pivots")
    assert "opencti_export" not in playbook["analyzers"]


def test_the_public_origin_exists() -> None:
    assert JobOrigin.PUBLIC.value == "public"


def test_the_result_view_leaves_out_everything_internal() -> None:
    job_id = uuid.uuid4()
    analyzer = SimpleNamespace(
        plugin_name="virustotal",
        plugin_type=PluginKind.ANALYZER,
        status=ReportStatus.SUCCESS,
        summary_data={"verdict": "malicious", "tags": ["trojan"]},
        raw_output={"secret": "do not leak"},
        file_path="/var/lib/xenoproxy/x",
    )
    connector = SimpleNamespace(
        plugin_name="opencti_export",
        plugin_type=PluginKind.CONNECTOR,
        status=ReportStatus.SUCCESS,
        summary_data={},
    )
    job = SimpleNamespace(
        id=job_id,
        observable_value="203.0.113.7",
        observable_type=SimpleNamespace(value="ip"),
        status=JobStatus.SUCCESS,
        verdict=Verdict.MALICIOUS,
        created_at=None,
        finished_at=None,
        requested_by_name="someone",
        visible_to_group_ids=[uuid.uuid4()],
        reports=[analyzer, connector],
    )

    view = _public_view(job).model_dump(mode="json")

    assert set(view) == {
        "id",
        "value",
        "type",
        "status",
        "verdict",
        "created_at",
        "finished_at",
        "sources",
    }
    assert view["sources"] == [
        {"name": "virustotal", "status": ReportStatus.SUCCESS.value, "verdict": "malicious"}
    ]
    assert "do not leak" not in str(view)
    assert "requested_by_name" not in view


@pytest.mark.asyncio
async def test_the_routes_answer_not_found_while_the_switch_is_off(monkeypatch) -> None:
    async def off(_session, _key):
        return False

    monkeypatch.setattr(public_module.settings_store, "get", off)
    with pytest.raises(NotFoundError):
        await public_module._require_enabled(None)


@pytest.mark.asyncio
async def test_the_routes_open_when_the_switch_is_on(monkeypatch) -> None:
    async def on(_session, _key):
        return True

    monkeypatch.setattr(public_module.settings_store, "get", on)
    await public_module._require_enabled(None)
