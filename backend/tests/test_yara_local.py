"""Local YARA: rule loading, ruleset extraction, and the analyzer, on small fixtures."""

from __future__ import annotations

import io
import zipfile
from collections.abc import Iterator
from pathlib import Path

import pytest

from app.core.config import get_settings
from app.models.job import ObservableType, ReportStatus, Verdict
from app.plugins.analyzer.yara_local import YaraLocalAnalyzer
from app.plugins.base.plugin import SampleAccess
from app.services import yara_rules
from app.services.observables import Observable

_SHA = "a" * 64
_GOOD = 'rule marker_a { strings: $a = "EVIL_MARKER_A" condition: $a }\n'
_GOOD_B = 'rule marker_b { strings: $a = "EVIL_MARKER_B" condition: $a }\n'
_GOOD_C = 'rule marker_c { strings: $a = "EVIL_MARKER_C" condition: $a }\n'
_EXTERNAL = 'rule scoped { condition: filename == "" }\n'
_BROKEN = "rule broken { condition: nope_undefined }\n"


@pytest.fixture
def rules_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    monkeypatch.setenv("BACKEND_YARA_RULES_DIR", str(tmp_path))
    get_settings.cache_clear()
    yara_rules.reset_cache()
    (tmp_path / "custom").mkdir()
    yield tmp_path
    get_settings.cache_clear()
    yara_rules.reset_cache()


def _analyzer(payload: bytes | None, **options: object) -> YaraLocalAnalyzer:
    sample = (
        None
        if payload is None
        else SampleAccess(sha256=_SHA, file_name="s.bin", read_local=lambda: payload)
    )
    return YaraLocalAnalyzer(options=dict(options), sample=sample)


def _observable() -> Observable:
    return Observable(value=_SHA, type=ObservableType.FILE)


async def test_one_match_is_suspicious(rules_dir: Path) -> None:
    (rules_dir / "custom" / "a.yar").write_text(_GOOD)
    result = await _analyzer(b"xx EVIL_MARKER_A xx").execute(_observable())
    summary = result.summary.as_dict()
    assert result.status is ReportStatus.SUCCESS
    assert summary["verdict"] == Verdict.SUSPICIOUS.value
    assert summary["extra"]["matched_rules"] == ["marker_a"]


async def test_several_distinct_rules_are_malicious(rules_dir: Path) -> None:
    for name, rule in (("a", _GOOD), ("b", _GOOD_B), ("c", _GOOD_C)):
        (rules_dir / "custom" / f"{name}.yar").write_text(rule)
    payload = b"EVIL_MARKER_A EVIL_MARKER_B EVIL_MARKER_C"
    result = await _analyzer(payload).execute(_observable())
    assert result.summary.as_dict()["verdict"] == Verdict.MALICIOUS.value


async def test_no_match_is_unknown_not_clean(rules_dir: Path) -> None:
    (rules_dir / "custom" / "a.yar").write_text(_GOOD)
    result = await _analyzer(b"harmless").execute(_observable())
    assert result.status is ReportStatus.SUCCESS
    assert result.summary.as_dict()["verdict"] == Verdict.UNKNOWN.value


async def test_a_broken_file_is_reported_and_does_not_stop_the_others(rules_dir: Path) -> None:
    (rules_dir / "custom" / "a.yar").write_text(_GOOD)
    (rules_dir / "custom" / "bad.yar").write_text(_BROKEN)
    result = await _analyzer(b"EVIL_MARKER_A").execute(_observable())
    assert result.status is ReportStatus.SUCCESS
    assert result.raw_output["rule_files_with_errors"] == 1
    assert yara_rules.load().files == 1


async def test_externals_used_by_community_rules_compile(rules_dir: Path) -> None:
    (rules_dir / "custom" / "ext.yar").write_text(_EXTERNAL)
    assert yara_rules.load().files == 1


async def test_without_any_rule_the_run_fails_with_a_hint(rules_dir: Path) -> None:
    result = await _analyzer(b"data").execute(_observable())
    assert result.status is ReportStatus.FAILED
    assert "Admin" in (result.error or "")


async def test_without_a_file_the_analyzer_skips(rules_dir: Path) -> None:
    result = await _analyzer(None).execute(_observable())
    assert result.status is ReportStatus.SKIPPED


async def test_it_scans_even_when_files_may_not_leave(rules_dir: Path) -> None:
    (rules_dir / "custom" / "a.yar").write_text(_GOOD)
    # read_bytes is None: the instance forbids sending files to providers.
    result = await _analyzer(b"EVIL_MARKER_A").execute(_observable())
    assert result.status is ReportStatus.SUCCESS


async def test_an_edited_rule_is_picked_up(rules_dir: Path) -> None:
    rule = rules_dir / "custom" / "a.yar"
    rule.write_text(_GOOD)
    first = yara_rules.load()
    assert yara_rules.load() is first  # unchanged: cached
    rule.write_text(_GOOD + _GOOD_B)
    assert yara_rules.load() is not first


# -- pulled rulesets -----------------------------------------------------------


def _zip(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return buffer.getvalue()


_SOURCE = yara_rules.SOURCES[0]
_PREFIX = _SOURCE.include_prefix


def test_extract_keeps_only_rule_files_under_the_prefix(tmp_path: Path) -> None:
    payload = _zip(
        {
            f"{_PREFIX}a.yar": _GOOD.encode(),
            f"{_PREFIX}notes.txt": b"x",
            "elsewhere/b.yar": _GOOD_B.encode(),
        }
    )
    kept, rejected = yara_rules.extract_rules(payload, _SOURCE, tmp_path)
    assert kept == 1
    assert rejected == []
    assert [path.name for path in tmp_path.iterdir()] == ["00000_a.yar"]


def test_extract_never_uses_a_member_name_as_a_path(tmp_path: Path) -> None:
    payload = _zip({f"{_PREFIX}../../../escape.yar": _GOOD.encode()})
    target = tmp_path / "out"
    target.mkdir()
    yara_rules.extract_rules(payload, _SOURCE, target)
    assert not (tmp_path / "escape.yar").exists()
    assert all(path.parent == target for path in target.iterdir())


def test_extract_rejects_an_oversized_rule_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(yara_rules, "MAX_RULE_FILE_BYTES", 10)
    kept, rejected = yara_rules.extract_rules(
        _zip({f"{_PREFIX}big.yar": b"x" * 50}), _SOURCE, tmp_path
    )
    assert kept == 0
    assert "larger" in rejected[0]


def test_extract_refuses_an_archive_that_expands_too_far(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(yara_rules, "MAX_EXPANDED_BYTES", 30)
    payload = _zip({f"{_PREFIX}a.yar": b"x" * 20, f"{_PREFIX}b.yar": b"x" * 20})
    with pytest.raises(yara_rules.PullError):
        yara_rules.extract_rules(payload, _SOURCE, tmp_path)


def test_extract_rejects_something_that_is_not_a_zip(tmp_path: Path) -> None:
    with pytest.raises(yara_rules.PullError):
        yara_rules.extract_rules(b"not a zip", _SOURCE, tmp_path)


async def test_a_pull_installs_validates_enables_and_records_the_digest(
    rules_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = _zip({f"{_PREFIX}ok.yar": _GOOD.encode(), f"{_PREFIX}bad.yar": _BROKEN.encode()})

    async def fake_get_bytes(url: str, **_: object) -> tuple[bytes, str]:
        assert url == _SOURCE.url
        return payload, "application/zip"

    monkeypatch.setattr(yara_rules.http_client, "get_bytes", fake_get_bytes)
    meta = await yara_rules.pull(_SOURCE.id)

    assert meta["files"] == 2
    assert meta["compiled"] == 1
    assert len(meta["archive_sha256"]) == 64
    assert any("bad.yar" in item for item in meta["rejected"])
    overview = yara_rules.overview()
    entry = next(item for item in overview["sources"] if item["id"] == _SOURCE.id)
    assert entry["enabled"] is True
    assert yara_rules.load().files == 1

    result = await _analyzer(b"EVIL_MARKER_A").execute(_observable())
    assert result.summary.as_dict()["verdict"] == Verdict.SUSPICIOUS.value

    yara_rules.remove_source(_SOURCE.id)
    assert yara_rules.load().rules is None


async def test_a_failed_download_installs_nothing(
    rules_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def refused(url: str, **_: object) -> None:
        return None

    monkeypatch.setattr(yara_rules.http_client, "get_bytes", refused)
    with pytest.raises(yara_rules.PullError):
        await yara_rules.pull(_SOURCE.id)
    assert not (rules_dir / "sources" / _SOURCE.id).exists()


async def test_an_unknown_ruleset_is_refused(rules_dir: Path) -> None:
    with pytest.raises(yara_rules.PullError):
        await yara_rules.pull("../../etc")


def test_every_public_source_is_a_safe_id_pinned_to_codeload_with_a_folder_prefix() -> None:
    ids = [source.id for source in yara_rules.SOURCES]
    assert len(ids) == len(set(ids))
    for source in yara_rules.SOURCES:
        assert yara_rules._SAFE_ID.match(source.id), source.id
        assert source.url.startswith("https://codeload.github.com/"), source.id
        assert source.include_prefix.endswith("/"), source.id
        assert not source.include_prefix.startswith("/"), source.id
        assert ".." not in source.include_prefix, source.id
        assert source.licence.strip(), source.id
