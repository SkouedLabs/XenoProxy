"""A scan can be forced through chosen proxy profiles.

Covers the routing choice (which profile an analyzer lands on) and the
validation of the choice at submission, with no database.
"""

from __future__ import annotations

import pytest

from app.core import http_client
from app.core.errors import ValidationFailedError
from app.models.job import Tlp
from app.services import orchestrator


@pytest.fixture
def profiles(monkeypatch):
    monkeypatch.setattr(http_client, "available_profiles", lambda: [("tor", False), ("corp", True)])


def test_no_box_ticked_changes_nothing(profiles) -> None:
    assert orchestrator._validate_proxy_route(False, ["tor"], Tlp.AMBER) == []


def test_a_ticked_box_without_a_name_means_every_profile(profiles) -> None:
    assert orchestrator._validate_proxy_route(True, None, Tlp.AMBER) == ["corp", "tor"]


def test_chosen_profiles_are_kept_once_each(profiles) -> None:
    assert orchestrator._validate_proxy_route(True, ["tor", "tor"], Tlp.AMBER) == ["tor"]


def test_an_unknown_profile_is_refused(profiles) -> None:
    with pytest.raises(ValidationFailedError):
        orchestrator._validate_proxy_route(True, ["nope"], Tlp.AMBER)


def test_red_needs_an_approved_profile(profiles) -> None:
    with pytest.raises(ValidationFailedError):
        orchestrator._validate_proxy_route(True, ["tor"], Tlp.RED)
    assert orchestrator._validate_proxy_route(True, ["corp"], Tlp.RED) == ["corp"]


def test_no_profile_configured_is_refused(monkeypatch) -> None:
    monkeypatch.setattr(http_client, "available_profiles", lambda: [])
    with pytest.raises(ValidationFailedError):
        orchestrator._validate_proxy_route(True, None, Tlp.AMBER)


def test_the_job_choice_beats_assignments_and_is_stable(monkeypatch) -> None:
    a = http_client._Profile("a", "socks5h://a:1", False)
    b = http_client._Profile("b", "socks5h://b:1", False)
    monkeypatch.setattr(http_client, "_profiles", {"a": a, "b": b})
    monkeypatch.setattr(http_client, "_assignments", {"vt": "a"})
    monkeypatch.setattr(http_client, "_default_profile", "a")
    with http_client.analyzer_scope("vt", Tlp.AMBER, ("b",)):
        assert http_client._chosen_profile() is b
    with http_client.analyzer_scope("vt", Tlp.AMBER):
        assert http_client._chosen_profile() is a
    with http_client.analyzer_scope("vt", Tlp.AMBER, ("a", "b")):
        first = http_client._chosen_profile()
    with http_client.analyzer_scope("vt", Tlp.AMBER, ("a", "b")):
        assert http_client._chosen_profile() is first
