"""The address allow-list that can restrict public submission."""

from __future__ import annotations

import pytest

from app.api.v1.public import address_allowed
from app.core.errors import ValidationFailedError
from app.services.settings_store import BY_KEY, _coerce


def test_an_empty_list_allows_everyone() -> None:
    assert address_allowed("", "203.0.113.9")
    assert address_allowed("   ", None)


def test_addresses_and_networks_are_matched() -> None:
    allowed = "192.0.2.0/24, 203.0.113.7 2001:db8::/32"
    assert address_allowed(allowed, "192.0.2.200")
    assert address_allowed(allowed, "203.0.113.7")
    assert address_allowed(allowed, "2001:db8::1")
    assert not address_allowed(allowed, "203.0.113.8")
    assert not address_allowed(allowed, "198.51.100.1")


def test_an_unknown_caller_is_refused_when_a_list_is_set() -> None:
    assert not address_allowed("192.0.2.0/24", None)
    assert not address_allowed("192.0.2.0/24", "not-an-ip")


def test_the_setting_normalises_valid_input_and_rejects_a_bad_token() -> None:
    spec = BY_KEY["public_allowed_networks"]
    assert _coerce(spec, "192.0.2.0/24,203.0.113.7") == "192.0.2.0/24 203.0.113.7"
    assert _coerce(spec, "") == ""
    with pytest.raises(ValidationFailedError):
        _coerce(spec, "192.0.2.0/24 nope")
