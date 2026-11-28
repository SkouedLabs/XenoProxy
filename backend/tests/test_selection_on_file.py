"""Which analyzers run on an uploaded file.

An upload's observable is the file's SHA-256, so a plugin that only takes files
would never run on it. The analyzers that read the file on this instance must
run; a plugin that can only send it out must not be admitted that way.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.models.job import ObservableType, PluginKind, Tlp
from app.plugins.base.registry import iter_plugins
from app.services import orchestrator


def _local_names() -> set[str]:
    orchestrator.load_all()
    return {cls.name for cls in iter_plugins(PluginKind.ANALYZER) if cls.reads_local_sample}


class _Configs(dict):
    """Every plugin is configured and enabled unless a test says otherwise."""

    def __missing__(self, key: str) -> SimpleNamespace:
        return SimpleNamespace(enabled=True, max_tlp=Tlp.RED, options={})

    def get(self, key, default=None):
        return self[key]


@pytest.fixture
def no_db(monkeypatch):
    async def configs(_session):
        return _Configs()

    async def stored(_session):
        # Every credential is present, so only the file decides what runs.
        return {
            cls.name: set(cls.required_secret_names()) for cls in iter_plugins(PluginKind.ANALYZER)
        }

    monkeypatch.setattr(orchestrator.plugin_configs, "list_all", configs)
    monkeypatch.setattr(orchestrator.secrets_vault, "configured_plugins", stored)


async def _analyzers(*, has_sample: bool):
    runnable, skipped = await orchestrator.candidate_plugins(
        None,
        plugin_type=PluginKind.ANALYZER,
        observable_type=ObservableType.HASH,
        job_tlp=Tlp.AMBER,
        has_sample=has_sample,
    )
    return set(runnable), {entry.name: entry.reason for entry in skipped}


@pytest.mark.asyncio
async def test_the_local_analyzers_run_on_an_uploaded_file(no_db) -> None:
    local = _local_names()
    assert len(local) == 6
    runnable, _ = await _analyzers(has_sample=True)
    assert runnable >= local


@pytest.mark.asyncio
async def test_the_local_analyzers_stay_out_without_a_file(no_db) -> None:
    local = _local_names()
    runnable, skipped = await _analyzers(has_sample=False)
    assert not (local & runnable)
    assert all("does not support" in skipped[name] for name in local)


@pytest.mark.asyncio
async def test_a_file_does_not_admit_a_plugin_that_could_only_send_it(no_db) -> None:
    runnable, _ = await _analyzers(has_sample=True)
    for cls in iter_plugins(PluginKind.ANALYZER):
        if ObservableType.HASH in cls.supported_types or cls.reads_local_sample:
            continue
        assert cls.name not in runnable, cls.name


@pytest.mark.asyncio
async def test_a_hash_job_without_a_file_is_unchanged(no_db) -> None:
    runnable, _ = await _analyzers(has_sample=False)
    for cls in iter_plugins(PluginKind.ANALYZER):
        if cls.reads_local_sample or ObservableType.HASH not in cls.supported_types:
            continue
        assert cls.name in runnable, cls.name
