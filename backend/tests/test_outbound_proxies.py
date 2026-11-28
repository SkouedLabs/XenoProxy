"""Per-analyzer proxy profiles: routing, TLP RED refusal, and secret handling."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.core import http_client
from app.core.http_client import OutboundRequestError
from app.models.job import Tlp
from app.services import app_settings
from app.services.settings_sections import NetworkSettings, ProxyProfile


def _network(**overrides) -> NetworkSettings:
    base = {
        "proxy_profiles": [
            {
                "name": "tor",
                "url": "socks5h://tor.internal:9050",
                "username": "",
                "red_approved": False,
            },
            {
                "name": "egress",
                "url": "socks5://egress.internal:1080",
                "username": "analyst",
                "red_approved": True,
            },
            {"name": "gateway", "url": "http://gateway.internal:3128"},
        ],
        "proxy_passwords": {"egress": "s3cret-pass"},
        "proxy_default": "gateway",
        "proxy_assignments": {"shodan": "egress", "otx": "tor"},
    }
    base.update(overrides)
    return NetworkSettings.model_validate(base)


@pytest.fixture(autouse=True)
def _reset_routes():
    http_client.set_network(None)
    yield
    http_client.set_network(None)


def _resolved(analyzer: str, tlp: Tlp | str = Tlp.AMBER) -> str | None:
    with http_client.analyzer_scope(analyzer, tlp):
        return http_client._client_kwargs(5.0, url="https://api.example.com/").get("proxy")


def test_assigned_analyzer_uses_its_profile_with_credentials():
    http_client.set_network(_network())
    proxy = _resolved("shodan")
    assert proxy == "socks5://analyst:s3cret-pass@egress.internal:1080"


def test_unassigned_analyzer_falls_back_to_the_default_profile():
    http_client.set_network(_network())
    assert _resolved("greynoise") == "http://gateway.internal:3128"


def test_socks5h_keeps_remote_name_resolution_scheme():
    http_client.set_network(_network())
    assert _resolved("otx") == "socks5h://tor.internal:9050"


def test_request_outside_an_analyzer_uses_the_default_profile():
    http_client.set_network(_network())
    assert http_client._client_kwargs(5.0, url="https://api.example.com/")["proxy"] == (
        "http://gateway.internal:3128"
    )


def test_red_job_refused_through_a_profile_not_approved_for_red():
    http_client.set_network(_network())
    with pytest.raises(OutboundRequestError, match="not approved for TLP:RED"):
        _resolved("otx", Tlp.RED)


def test_red_job_allowed_through_an_approved_profile():
    http_client.set_network(_network())
    assert _resolved("shodan", "red") == "socks5://analyst:s3cret-pass@egress.internal:1080"


def test_red_job_with_no_profile_keeps_the_direct_route():
    http_client.set_network(_network(proxy_default="", proxy_assignments={}))
    assert _resolved("otx", Tlp.RED) is None


def test_no_proxy_configured_means_no_proxy():
    http_client.set_network(NetworkSettings())
    assert _resolved("shodan") is None


def test_scope_is_reset_after_the_block():
    http_client.set_network(_network())
    _resolved("shodan")
    assert http_client._client_kwargs(5.0, url="https://api.example.com/").get("proxy") == (
        "http://gateway.internal:3128"
    )


@pytest.mark.parametrize(
    "url",
    ["socks5://h:1080", "socks5h://h:9050", "http://h:3128", "https://h:3129"],
)
def test_every_supported_kind_is_accepted(url):
    assert ProxyProfile(name="p", url=url).url == url


@pytest.mark.parametrize(
    "url", ["ftp://h:21", "socks5://user:pass@h:1080", "h:1080", "javascript:x"]
)
def test_unsupported_or_credentialed_urls_are_rejected(url):
    with pytest.raises(ValidationError):
        ProxyProfile(name="p", url=url)


def test_profile_name_must_be_unique_and_referenced_profiles_must_exist():
    with pytest.raises(ValidationError, match="share a name"):
        NetworkSettings.model_validate(
            {
                "proxy_profiles": [
                    {"name": "a", "url": "http://a:1"},
                    {"name": "a", "url": "http://b:1"},
                ]
            }
        )
    with pytest.raises(ValidationError, match="unknown proxy profile"):
        NetworkSettings.model_validate({"proxy_default": "missing"})


def test_password_for_a_removed_profile_is_refused():
    with pytest.raises(ValidationError, match="does not exist"):
        NetworkSettings.model_validate({"proxy_passwords": {"ghost": "x"}})


def test_public_view_never_contains_a_proxy_password():
    value = _network()
    public = app_settings.public("network", value)
    assert public["proxy_passwords"] == {}
    assert public["proxy_passwords_set"] == ["egress"]
    assert "s3cret-pass" not in repr(public)


def test_audit_view_masks_proxy_passwords():
    audited = app_settings.audit_safe("network", _network())
    assert audited["proxy_passwords"] == {"egress": "***"}
    assert "s3cret-pass" not in repr(audited)


def test_an_empty_password_entry_keeps_the_stored_one():
    current = _network()
    incoming = {
        "proxy_profiles": [{"name": "egress", "url": "socks5://egress.internal:1080"}],
        "proxy_passwords": {"egress": ""},
        "proxy_default": "",
        "proxy_assignments": {},
    }
    merged = app_settings.merge_secrets("network", incoming, current)
    assert merged["proxy_passwords"] == {"egress": "s3cret-pass"}


def test_a_new_password_replaces_the_stored_one_and_removed_profiles_are_dropped():
    current = _network()
    incoming = {
        "proxy_profiles": [{"name": "egress", "url": "socks5://egress.internal:1080"}],
        "proxy_passwords": {"egress": "rotated-pass"},
        "proxy_default": "",
        "proxy_assignments": {},
    }
    merged = app_settings.merge_secrets("network", incoming, current)
    assert merged["proxy_passwords"] == {"egress": "rotated-pass"}
