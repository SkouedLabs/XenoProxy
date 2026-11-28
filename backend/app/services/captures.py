"""Browser screenshots: request one, run it in the worker, read the image back.

The API only records the request and queues it. The worker does the work: it
checks the destination, chooses the proxy, and calls the screenshot service over
the internal `capture` network with the shared token. The service answers with a
PNG; the worker checks the image and stores it on the row.

Nothing here runs a browser. The browser is in its own container, which is what
lets this process keep the process-creation guard of the backend.
"""

from __future__ import annotations

import base64
import hashlib
import struct
import uuid
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core import http_client
from app.core.config import get_settings
from app.core.errors import ValidationFailedError
from app.core.logging import get_logger
from app.models.capture import Capture, CaptureStatus
from app.models.job import Tlp

logger = get_logger(__name__)

MAX_URL_LENGTH = 2048
MAX_PNG_BYTES = 4 * 1024 * 1024
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
# A page is given the service's whole navigation budget plus a margin for the
# browser to start and to take the picture.
SERVICE_TIMEOUT_SECONDS = 90.0


class CaptureError(RuntimeError):
    """The service answered, but not with an image."""


def check_submitted_url(url: str) -> str:
    """Syntax only, checked in the API. Destination checks need DNS and run in the worker."""
    url = url.strip()
    if not url or len(url) > MAX_URL_LENGTH:
        raise ValidationFailedError("The address must be between 1 and 2048 characters.")
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"}:
        raise ValidationFailedError("Only http and https addresses can be captured.")
    if not parts.hostname:
        raise ValidationFailedError("The address has no host name.")
    if parts.username or parts.password:
        raise ValidationFailedError(
            "Credentials do not belong in the address; a capture never sends them."
        )
    return url


def playwright_proxy_fields(proxy_url: str | None) -> dict[str, str] | None:
    """The proxy as the service takes it: a server, and its credentials as separate fields.

    Credentials are never sent in the URL, which keeps them out of the service's logs
    and out of any error text that echoes its request.
    """
    if not proxy_url:
        return None
    parts = urlsplit(proxy_url)
    if parts.scheme not in {"http", "https", "socks5", "socks5h"}:
        raise CaptureError("The proxy scheme is not supported for screenshots.")
    if not parts.hostname or not parts.port:
        raise CaptureError("The proxy needs a host and a port.")
    scheme = "socks5" if parts.scheme == "socks5h" else parts.scheme
    host = f"[{parts.hostname}]" if ":" in parts.hostname else parts.hostname
    fields = {"server": f"{scheme}://{host}:{parts.port}"}
    if parts.username:
        fields["username"] = parts.username
        fields["password"] = parts.password or ""
    return fields


def parse_service_reply(payload: dict[str, Any]) -> dict[str, Any]:
    """Check what the service sent back before anything is stored.

    The image must be a PNG of a bounded size; the rest is text kept short.
    """
    encoded = payload.get("png_base64")
    if not isinstance(encoded, str):
        raise CaptureError("The screenshot service sent no image.")
    try:
        image = base64.b64decode(encoded, validate=True)
    except ValueError as exc:
        raise CaptureError("The screenshot service sent an invalid image.") from exc
    if not image.startswith(PNG_SIGNATURE) or len(image) < 24:
        raise CaptureError("The screenshot service sent something other than a PNG.")
    if len(image) > MAX_PNG_BYTES:
        raise CaptureError("The screenshot is larger than the allowed size.")
    width, height = struct.unpack(">II", image[16:24])
    final_url = payload.get("final_url")
    title = payload.get("title")
    blocked = payload.get("blocked_requests")
    return {
        "image": image,
        "width": width,
        "height": height,
        "final_url": final_url[:MAX_URL_LENGTH] if isinstance(final_url, str) else "",
        "title": title[:200] if isinstance(title, str) else "",
        "blocked_requests": blocked if isinstance(blocked, int) and blocked >= 0 else 0,
    }


async def _call_service(url: str, proxy: dict[str, str] | None) -> dict[str, Any]:
    settings = get_settings()
    token = settings.capture_token
    if not token:
        raise CaptureError("The screenshot service has no token configured.")
    body: dict[str, Any] = {"url": url, "proxy": proxy}
    # The service sits on the internal capture network, so this client takes no
    # outbound route, no proxy and no CA bundle of its own.
    async with httpx.AsyncClient(
        timeout=SERVICE_TIMEOUT_SECONDS, trust_env=False, follow_redirects=False
    ) as client:
        try:
            response = await client.post(
                f"{settings.capture_service_url.rstrip('/')}/capture",
                json=body,
                headers={"Authorization": f"Bearer {token}"},
            )
        except httpx.HTTPError as exc:
            raise CaptureError("The screenshot service did not answer.") from exc
    try:
        payload = response.json()
    except ValueError as exc:
        raise CaptureError("The screenshot service answered with something unreadable.") from exc
    if response.status_code != 200:
        message = payload.get("error") if isinstance(payload, dict) else None
        raise CaptureError(
            str(message or f"The screenshot service answered {response.status_code}.")
        )
    if not isinstance(payload, dict):
        raise CaptureError("The screenshot service answered with something unreadable.")
    return payload


async def run(session_factory: async_sessionmaker[AsyncSession], capture_id: uuid.UUID) -> None:
    """Make one capture. Idempotent: a row that is no longer queued is left alone."""
    async with session_factory() as session:
        capture = await session.get(Capture, capture_id)
        if capture is None or capture.status != CaptureStatus.QUEUED:
            return
        capture.status = CaptureStatus.RUNNING
        await session.commit()
        tlp = Tlp(capture.tlp)

        try:
            proxy_url = http_client.capture_proxy(tlp)
            http_client.validate_destination(capture.url)
            reply = await _call_service(capture.url, playwright_proxy_fields(proxy_url))
            result = parse_service_reply(reply)
            if result["final_url"] and result["final_url"] != capture.url:
                # The page may have redirected: the place it ended up is checked too.
                http_client.validate_destination(result["final_url"])
        except http_client.OutboundRequestError as exc:
            _finish(capture, CaptureStatus.REFUSED, error=str(exc))
            logger.info("capture_refused", capture=str(capture.id), reason=str(exc))
        except CaptureError as exc:
            _finish(capture, CaptureStatus.FAILED, error=str(exc))
            logger.warning("capture_failed", capture=str(capture.id), reason=str(exc))
        else:
            capture.image = result["image"]
            capture.image_sha256 = hashlib.sha256(result["image"]).hexdigest()
            capture.width = result["width"]
            capture.height = result["height"]
            capture.final_url = result["final_url"]
            capture.title = result["title"]
            capture.blocked_requests = result["blocked_requests"]
            _finish(capture, CaptureStatus.DONE)
            logger.info("capture_done", capture=str(capture.id))
        await session.commit()


def _finish(capture: Capture, status: str, *, error: str = "") -> None:
    capture.status = status
    capture.error = error[:1000]
    capture.finished_at = datetime.now(UTC)


async def get_for_owner(
    session: AsyncSession, user_id: uuid.UUID, capture_id: uuid.UUID
) -> Capture | None:
    """Someone else's capture is reported as missing, as conversations are."""
    return (
        await session.execute(
            select(Capture).where(Capture.id == capture_id, Capture.user_id == user_id)
        )
    ).scalar_one_or_none()


def view(capture: Capture) -> dict[str, Any]:
    """What the API returns. The image itself is fetched separately."""
    return {
        "id": str(capture.id),
        "url": capture.url,
        "tlp": capture.tlp,
        "status": capture.status,
        "final_url": capture.final_url,
        "title": capture.title,
        "width": capture.width,
        "height": capture.height,
        "image_sha256": capture.image_sha256,
        "blocked_requests": capture.blocked_requests,
        "error": capture.error,
        "requested_by": capture.requested_by,
        "created_at": capture.created_at,
        "finished_at": capture.finished_at,
        "image_url": (
            f"/api/v1/captures/{capture.id}/image" if capture.status == CaptureStatus.DONE else None
        ),
    }
