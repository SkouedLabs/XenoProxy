"""Admin-configured infrastructure may be internal; observable scanning may not."""

from __future__ import annotations

import pytest

from app.core.http_client import OutboundRequestError, validate_destination
from app.services import oidc
from app.services.settings_sections import OidcSettings


def test_an_internal_identity_provider_is_reachable() -> None:
    validate_destination("https://idp.corp.local:8443/realms/main", allow_private=True)
    validate_destination("https://10.1.2.3/.well-known/openid-configuration", allow_private=True)


def test_the_default_policy_still_refuses_internal_addresses() -> None:
    with pytest.raises(OutboundRequestError):
        validate_destination("https://10.1.2.3/", allow_private=False)


@pytest.mark.parametrize(
    "url", ["http://169.254.169.254/latest/", "http://metadata.google.internal/"]
)
def test_cloud_metadata_stays_blocked_for_infrastructure(url: str) -> None:
    with pytest.raises(OutboundRequestError):
        validate_destination(url, allow_private=True)


def _config(**overrides: object) -> OidcSettings:
    base: dict[str, object] = {
        "enabled": True,
        "issuer": "https://idp.example.com",
        "client_id": "xenoproxy",
        "client_secret": "s3cret",
    }
    return OidcSettings.model_validate({**base, **overrides})


def test_the_button_is_offered_when_enabled_and_complete() -> None:
    assert oidc.is_available(_config())


@pytest.mark.parametrize(
    "overrides",
    [{"enabled": False}, {"issuer": ""}, {"client_id": ""}, {"client_secret": ""}],
)
def test_the_button_is_hidden_when_disabled_or_incomplete(overrides: dict[str, object]) -> None:
    assert not oidc.is_available(_config(**overrides))
