"""Signed outbound webhook helper, shared by the webhook-shaped plugins.

Every outbound webhook (critical-threat alerts, notifications) authenticates the
same way. The signing scheme lives here so the senders cannot drift apart, which
would silently break whichever receiver was written against them.

The signature covers `"{timestamp}.{body}"` with HMAC-SHA256, so a receiver can
reject a replayed payload by checking the timestamp window as well as the
digest.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any

from app.core import http_client

SIGNATURE_HEADER = "X-XenoProxy-Signature"
TIMESTAMP_HEADER = "X-XenoProxy-Timestamp"


def canonical_body(payload: dict[str, Any]) -> str:
    """Serialise a payload deterministically, so the digest is reproducible."""
    return json.dumps(payload, separators=(",", ":"), sort_keys=True, default=str)


def signature_headers(body: str, signing_key: str) -> dict[str, str]:
    """Build the timestamp and signature headers for a body."""
    timestamp = str(int(time.time()))
    digest = hmac.new(
        signing_key.encode("utf-8"),
        f"{timestamp}.{body}".encode(),
        hashlib.sha256,
    ).hexdigest()
    return {TIMESTAMP_HEADER: timestamp, SIGNATURE_HEADER: f"sha256={digest}"}


async def post_signed(
    url: str,
    payload: dict[str, Any],
    *,
    # The provider deadline the plugin was configured with, handed to the HTTP
    # client; this is not a cancellation scope, so asyncio.timeout does not apply.
    timeout: int,  # noqa: ASYNC109
    allow_private: bool,
    signing_key: str | None = None,
    auth_header: str | None = None,
    auth_token: str | None = None,
) -> http_client.HttpResult:
    """POST a JSON payload, signed and authenticated as configured."""
    body = canonical_body(payload)
    headers = {"Content-Type": "application/json"}
    if auth_token and auth_header:
        headers[auth_header] = auth_token
    if signing_key:
        headers.update(signature_headers(body, signing_key))

    return await http_client.post(
        url,
        content=body,
        headers=headers,
        timeout=timeout,
        allow_private=allow_private,
    )
