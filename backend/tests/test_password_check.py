"""Password breach check: only the 5-character prefix leaves, the gate, and the result.

The upstream is replaced by a stub; no request reaches the real range service.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from app.api.v1 import passwords as passwords_api
from app.core import http_client
from app.core.errors import ForbiddenError
from app.schemas.passwords import PasswordCheckRequest
from app.services import password_check

# SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
_SUFFIX = "1E4C9B93F3F0682250B6CF8331B7EE68FD8"
_BODY = f"0000000000000000000000000000000000A:0\n{_SUFFIX}:3861493\nFFFF:0\n"


def test_only_the_five_character_prefix_is_split_out_for_upstream() -> None:
    assert password_check.split_hash("password") == ("5BAA6", _SUFFIX)


def test_a_suffix_in_the_range_is_counted_and_padding_is_not() -> None:
    assert password_check.occurrences(_BODY, _SUFFIX) == 3861493
    assert password_check.occurrences(_BODY, "DEADBEEF" * 4) == 0


async def test_the_request_carries_the_prefix_and_padding_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, Any] = {}

    async def fake_get(url: str, **kwargs: Any) -> SimpleNamespace:
        seen["url"] = url
        seen["headers"] = kwargs["headers"]
        return SimpleNamespace(ok=True, status_code=200, text=_BODY)

    monkeypatch.setattr(http_client, "get", fake_get)
    assert await password_check.breach_count("password") == 3861493
    assert seen["url"] == "https://api.pwnedpasswords.com/range/5BAA6"
    assert _SUFFIX not in seen["url"].upper()
    assert seen["headers"]["Add-Padding"] == "true"


async def test_an_upstream_error_is_reported_not_treated_as_clean(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def down(url: str, **kwargs: Any) -> SimpleNamespace:
        return SimpleNamespace(ok=False, status_code=503, text="")

    monkeypatch.setattr(http_client, "get", down)
    with pytest.raises(password_check.PasswordCheckUnavailable):
        await password_check.breach_count("password")


async def test_the_endpoint_is_refused_while_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        passwords_api, "get_settings", lambda: SimpleNamespace(hibp_passwords_enabled=False)
    )
    with pytest.raises(ForbiddenError):
        await passwords_api.check_password(
            PasswordCheckRequest(password="password"), SimpleNamespace(username="a")
        )


async def test_the_endpoint_reports_a_hit_as_suspicious(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        passwords_api, "get_settings", lambda: SimpleNamespace(hibp_passwords_enabled=True)
    )

    async def fake_get(url: str, **kwargs: Any) -> SimpleNamespace:
        return SimpleNamespace(ok=True, status_code=200, text=_BODY)

    monkeypatch.setattr(http_client, "get", fake_get)
    out = await passwords_api.check_password(
        PasswordCheckRequest(password="password"), SimpleNamespace(username="a")
    )
    assert out.breached is True
    assert out.verdict == "suspicious"
