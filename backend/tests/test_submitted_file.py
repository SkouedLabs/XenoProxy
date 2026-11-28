"""Submitted files: the upload body limit, and which analyzers may send the file out.

The body limit is checked on a small app carrying the real middleware, so the
test does not need a database. The send rule is a pure function.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route

from app.api import middleware
from app.plugins.base.plugin import SampleAccess
from app.services.plugin_runtime import sample_for_options

MIB = 1024 * 1024


def _ok(request):
    return PlainTextResponse("ok")


@pytest.fixture
def client(monkeypatch):
    settings = SimpleNamespace(max_body_bytes=2 * MIB, max_upload_bytes=32 * MIB)
    monkeypatch.setattr(middleware, "get_settings", lambda: settings)
    app = Starlette(
        routes=[
            Route("/api/v1/jobs/file", _ok, methods=["POST"]),
            Route("/api/v1/admin/plugin-packages", _ok, methods=["POST"]),
            Route("/api/v1/jobs", _ok, methods=["POST"]),
        ],
    )
    app.add_middleware(middleware.BodyLimitMiddleware)
    return TestClient(app)


@pytest.mark.parametrize("path", ["/api/v1/jobs/file", "/api/v1/admin/plugin-packages"])
def test_a_file_bigger_than_the_ordinary_limit_is_accepted_on_upload_routes(client, path) -> None:
    response = client.post(path, content=b"x" * (3 * MIB))
    assert response.status_code == 200


@pytest.mark.parametrize("path", ["/api/v1/jobs/file", "/api/v1/admin/plugin-packages"])
def test_an_upload_past_its_own_cap_is_refused(client, path) -> None:
    response = client.post(path, content=b"x" * (32 * MIB + 2 * MIB))
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "BODY_TOO_LARGE"


def test_other_routes_keep_the_small_limit(client) -> None:
    response = client.post("/api/v1/jobs", content=b"x" * (3 * MIB))
    assert response.status_code == 413


def _sample(**overrides) -> SampleAccess:
    fields = {
        "sha256": "a" * 64,
        "read_bytes": lambda: b"sent",
        "read_local": lambda: b"local",
    }
    fields.update(overrides)
    return SampleAccess(**fields)


def test_no_sample_stays_no_sample() -> None:
    assert sample_for_options(None, {"send_file": True}) is None


def test_bytes_are_withdrawn_from_an_analyzer_that_was_not_told_to_send() -> None:
    kept = sample_for_options(_sample(), {})
    assert kept is not None
    assert kept.read_bytes is None
    assert not kept.may_leave
    # Local analysis is not a disclosure, so it keeps its access.
    assert kept.read_local is not None and kept.read_local() == b"local"


def test_an_analyzer_that_is_off_for_sending_is_withdrawn() -> None:
    kept = sample_for_options(_sample(), {"send_file": False})
    assert kept is not None and kept.read_bytes is None


def test_bytes_stay_when_the_analyzer_asks_for_them() -> None:
    kept = sample_for_options(_sample(), {"send_file": True})
    assert kept is not None and kept.may_leave
    assert kept.read_bytes is not None and kept.read_bytes() == b"sent"


def test_a_truthy_non_boolean_does_not_count_as_consent() -> None:
    kept = sample_for_options(_sample(), {"send_file": "yes"})
    assert kept is not None and kept.read_bytes is None


def test_nothing_to_withdraw_when_the_instance_already_keeps_the_file() -> None:
    no_bytes = _sample(read_bytes=None)
    assert sample_for_options(no_bytes, {"send_file": True}) is no_bytes
