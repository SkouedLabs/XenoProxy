"""OIDC authorization code flow with PKCE.

Discovery, JWKS and the token endpoint are reached through the shared HTTP
client, so the proxy and internal certificate authority apply here too. The
identity provider is infrastructure an administrator chose, not a target an
analyst submitted, so it may live on the internal network: the non-routable
restriction that protects scans does not apply to it, while cloud metadata
endpoints stay refused. The `state`, `nonce` and PKCE verifier live in a
short-lived signed cookie rather than in server memory, so the flow survives a
restart and several API replicas.

The configuration is the `oidc` settings section, with any field pinned by a
`BACKEND_OIDC_*` variable taking precedence, so the interface and a headless
deployment drive the same flow.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

from joserfc import jwt
from joserfc.jwk import KeySet
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.errors import AppError, UnauthorizedError
from app.core.http_client import get, post
from app.core.logging import get_logger
from app.services import app_settings
from app.services.settings_sections import OidcSettings

logger = get_logger(__name__)

STATE_COOKIE = "__Host-oidc-state"
STATE_TTL_SECONDS = 600
_DISCOVERY_PATH = "/.well-known/openid-configuration"

# Keyed by issuer, so pointing the instance at another provider never serves
# the previous provider's endpoints or keys.
_metadata_cache: dict[str, tuple[float, dict[str, Any]]] = {}
_jwks_cache: dict[str, tuple[float, Any]] = {}
_CACHE_TTL_SECONDS = 3600

# Section field -> configuration attribute that pins it from the environment.
_ENVIRONMENT_FIELDS = {
    "enabled": "oidc_enabled",
    "issuer": "oidc_issuer",
    "client_id": "oidc_client_id",
    "client_secret": "oidc_client_secret",
    "scopes": "oidc_scopes",
    "admin_group": "oidc_admin_group",
}


class OidcNotConfiguredError(AppError):
    status_code = 503
    code = "OIDC_NOT_CONFIGURED"


@dataclass(frozen=True)
class OidcIdentity:
    """The claims XenoProxy maps onto a user account."""

    subject: str
    username: str
    email: str | None
    display_name: str | None
    groups: list[str]


async def effective_config(session: AsyncSession) -> OidcSettings:
    """The stored section, overlaid with the fields the environment pins."""
    section: OidcSettings = await app_settings.load(session, "oidc")
    settings = get_settings()
    pinned: dict[str, Any] = {
        field: getattr(settings, attribute)
        for field, attribute in _ENVIRONMENT_FIELDS.items()
        if settings.managed_by_environment(attribute) and getattr(settings, attribute) is not None
    }
    if not pinned:
        return section
    return OidcSettings.model_validate({**section.model_dump(), **pinned})


def is_available(config: OidcSettings) -> bool:
    """Whether the sign-in page should offer single sign-on."""
    return config.enabled and bool(config.issuer and config.client_id and config.client_secret)


def _require_config(config: OidcSettings) -> tuple[str, str, str]:
    if not config.enabled:
        raise OidcNotConfiguredError("Single sign-on is not enabled on this instance.")
    if not is_available(config):
        raise OidcNotConfiguredError(
            "Single sign-on is enabled but the issuer, client id or client secret is missing."
        )
    return config.issuer.rstrip("/"), config.client_id, config.client_secret


async def _metadata(issuer: str) -> dict[str, Any]:
    """Fetch and cache the provider discovery document."""
    now = time.monotonic()
    cached = _metadata_cache.get(issuer)
    if cached and now - cached[0] < _CACHE_TTL_SECONDS:
        return cached[1]

    response = await get(f"{issuer}{_DISCOVERY_PATH}", timeout=15, allow_private=True)
    if not response.ok or not isinstance(response.json_body, dict):
        raise OidcNotConfiguredError("The provider discovery document could not be read.")
    _metadata_cache[issuer] = (now, response.json_body)
    return response.json_body


async def _jwks(issuer: str) -> Any:
    now = time.monotonic()
    cached = _jwks_cache.get(issuer)
    if cached and now - cached[0] < _CACHE_TTL_SECONDS:
        return cached[1]

    metadata = await _metadata(issuer)
    jwks_uri = str(metadata.get("jwks_uri") or "")
    if not jwks_uri:
        raise OidcNotConfiguredError("The provider advertises no JWKS endpoint.")
    response = await get(jwks_uri, timeout=15, allow_private=True)
    if not response.ok or not isinstance(response.json_body, dict):
        raise OidcNotConfiguredError("The provider signing keys could not be read.")
    key_set = KeySet.import_key_set(response.json_body)
    _jwks_cache[issuer] = (now, key_set)
    return key_set


def _sign(payload: bytes) -> str:
    key = get_settings().secret_key.encode("utf-8")
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def seal_state(data: dict[str, str]) -> str:
    """Sign the flow state so the callback can trust what the browser returns."""
    payload = json.dumps({**data, "ts": int(time.time())}, separators=(",", ":")).encode()
    body = base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
    return f"{body}.{_sign(payload)}"


def open_state(token: str) -> dict[str, str]:
    try:
        body, signature = token.split(".", 1)
        payload = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
    except (ValueError, TypeError) as exc:
        raise UnauthorizedError("The sign-on state is malformed.") from exc

    if not hmac.compare_digest(signature, _sign(payload)):
        raise UnauthorizedError("The sign-on state could not be verified.")

    data: dict[str, Any] = json.loads(payload)
    if int(time.time()) - int(data.get("ts", 0)) > STATE_TTL_SECONDS:
        raise UnauthorizedError("The sign-on attempt expired; start again.")
    return {key: str(value) for key, value in data.items()}


async def build_authorization_url(config: OidcSettings, redirect_uri: str) -> tuple[str, str]:
    """Return the provider URL to redirect to, and the state to store in a cookie."""
    issuer, client_id, _ = _require_config(config)
    metadata = await _metadata(issuer)
    endpoint = str(metadata.get("authorization_endpoint") or "")
    if not endpoint:
        raise OidcNotConfiguredError("The provider advertises no authorization endpoint.")

    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)
    verifier = secrets.token_urlsafe(48)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .decode("ascii")
        .rstrip("=")
    )

    query = urlencode(
        {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": config.scopes,
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
    )
    sealed = seal_state({"state": state, "nonce": nonce, "verifier": verifier})
    return f"{endpoint}?{query}", sealed


async def exchange_code(
    config: OidcSettings,
    *,
    code: str,
    redirect_uri: str,
    state_token: str,
    returned_state: str,
) -> OidcIdentity:
    """Validate the callback, exchange the code and verify the identity token."""
    issuer, client_id, client_secret = _require_config(config)
    stored = open_state(state_token)
    if not hmac.compare_digest(stored.get("state", ""), returned_state):
        raise UnauthorizedError("The sign-on state does not match.")

    metadata = await _metadata(issuer)
    token_endpoint = str(metadata.get("token_endpoint") or "")
    if not token_endpoint:
        raise OidcNotConfiguredError("The provider advertises no token endpoint.")

    response = await post(
        token_endpoint,
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
            "client_secret": client_secret,
            "code_verifier": stored.get("verifier", ""),
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=20,
        allow_private=True,
    )
    if not response.ok or not isinstance(response.json_body, dict):
        logger.warning("oidc_token_exchange_failed", status_code=response.status_code)
        raise UnauthorizedError("The identity provider refused the sign-on.")

    id_token = str(response.json_body.get("id_token") or "")
    if not id_token:
        raise UnauthorizedError("The identity provider returned no identity token.")

    algorithms = [
        str(algorithm)
        for algorithm in metadata.get("id_token_signing_alg_values_supported") or ["RS256"]
        if str(algorithm) != "none"
    ]
    try:
        token = jwt.decode(id_token, await _jwks(issuer), algorithms=algorithms)
        claims = token.claims
    except Exception as exc:
        logger.warning("oidc_id_token_invalid", error=str(exc))
        raise UnauthorizedError("The identity token could not be verified.") from exc

    if str(claims.get("iss", "")).rstrip("/") != issuer:
        raise UnauthorizedError("The identity token was issued by another provider.")
    audience = claims.get("aud")
    audiences = audience if isinstance(audience, list) else [audience]
    if client_id not in [str(entry) for entry in audiences]:
        raise UnauthorizedError("The identity token was issued for another client.")
    if str(claims.get("nonce", "")) != stored.get("nonce", ""):
        raise UnauthorizedError("The identity token nonce does not match.")
    expiry = claims.get("exp")
    if not isinstance(expiry, int) or expiry < int(time.time()):
        raise UnauthorizedError("The identity token has expired.")

    groups_claim = claims.get(config.groups_claim) or claims.get("roles") or []
    groups = [str(group) for group in groups_claim] if isinstance(groups_claim, list) else []

    username = str(
        claims.get("preferred_username") or claims.get("email") or claims.get("sub") or ""
    )
    return OidcIdentity(
        subject=str(claims.get("sub") or ""),
        username=username,
        email=str(claims["email"]) if claims.get("email") else None,
        display_name=str(claims["name"]) if claims.get("name") else None,
        groups=groups,
    )


def safe_next_path(candidate: str | None) -> str:
    """Accept only a relative path, which closes the open-redirect hole."""
    if not candidate:
        return "/"
    if not candidate.startswith("/") or candidate.startswith("//"):
        return "/"
    return candidate[:512]
