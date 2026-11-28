"""LLM synthesizer: three lines, the TLP gate, and no change to the verdict.

The model is replaced by a fake; nothing here reaches a real inference server.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from typing import Any

import pytest

from app.core import db
from app.models.job import PluginKind, ReportStatus, Tlp, Verdict
from app.plugins.base.plugin import JobContext, ReportView
from app.plugins.connector.llm_synthesizer import LlmSynthesizerConnector, _three_lines
from app.services.assistant import profiles
from app.services.assistant import provider as provider_module
from app.services.observables import classify

_PRIVATE = "http://10.0.0.5:11434"
_PUBLIC = "https://openrouter.ai/api"


class _FakeSession:
    async def __aenter__(self) -> object:
        return object()

    async def __aexit__(self, *exc: object) -> None:
        return None


def _factory() -> object:
    return lambda: _FakeSession()


class _FakeProvider:
    def __init__(self, answer: str, seen: list[list[dict[str, Any]]]) -> None:
        self._answer = answer
        self._seen = seen

    async def chat(self, messages: list[dict[str, Any]]) -> SimpleNamespace:
        self._seen.append(messages)
        return SimpleNamespace(content=self._answer)


def _context(tlp: Tlp = Tlp.AMBER, verdict: Verdict = Verdict.SUSPICIOUS) -> JobContext:
    return JobContext(
        job_id=uuid.uuid4(),
        observable=classify("evil.example.com"),
        verdict=verdict,
        tlp=tlp,
        tags=[],
        summary={},
        reports=[
            ReportView(
                plugin_name="virustotal",
                plugin_type=PluginKind.ANALYZER,
                status=ReportStatus.SUCCESS,
                summary={"verdict": "suspicious", "headline": "4 engines flag it."},
                raw_output=None,
            )
        ],
        requested_by="analyst",
    )


def _wire(monkeypatch: pytest.MonkeyPatch, base_url: str, answer: str) -> list[list[dict]]:
    seen: list[list[dict]] = []
    settings = SimpleNamespace(configured=True, base_url=base_url, model="llama3")
    monkeypatch.setattr(db, "get_session_factory", _factory)

    async def effective(*_a: object, **_k: object) -> SimpleNamespace:
        return settings

    monkeypatch.setattr(profiles, "effective_settings", effective)
    monkeypatch.setattr(provider_module, "build_provider", lambda _s: _FakeProvider(answer, seen))
    return seen


def test_three_lines_are_kept_clean_and_capped() -> None:
    answer = "- first line\n2. second `line`\n\nthird\nfourth ignored"
    assert _three_lines(answer) == ["first line", "second line", "third"]
    assert len(_three_lines("x" * 5000)[0]) == 300


async def test_a_summary_is_three_lines_and_keeps_the_verdict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen = _wire(monkeypatch, _PRIVATE, "It is flagged.\nOne engine says phishing.\nCheck it.")
    result = await LlmSynthesizerConnector().run(_context())
    assert result.status is ReportStatus.SUCCESS
    summary = result.summary.as_dict()
    assert summary["verdict"] == Verdict.SUSPICIOUS.value
    assert result.raw_output["summary_lines"] == [
        "It is flagged.",
        "One engine says phishing.",
        "Check it.",
    ]
    assert "<reports>" in seen[0][1]["content"]


async def test_an_empty_answer_is_a_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    _wire(monkeypatch, _PRIVATE, "   \n  ")
    result = await LlmSynthesizerConnector().run(_context())
    assert result.status is ReportStatus.FAILED


async def test_red_is_refused_for_a_hosted_model(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _wire(monkeypatch, _PUBLIC, "unused")
    result = await LlmSynthesizerConnector().run(_context(tlp=Tlp.RED))
    assert result.status is ReportStatus.SKIPPED
    assert seen == []
