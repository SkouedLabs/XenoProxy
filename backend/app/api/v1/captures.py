"""Browser screenshots: request one, follow it, fetch the image.

Alpha. A capture is made by the worker, through the screenshot service, and
only when the instance runs that service (`BACKEND_CAPTURE_ENABLED`). The image
is served to its owner alone, as a PNG, never as a page.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request, status
from fastapi.responses import Response
from pydantic import Field
from sqlalchemy import select
from sqlalchemy.orm import defer

from app.api.deps import DbSession, client_ip, require
from app.core.config import get_settings
from app.core.errors import NotFoundError, ValidationFailedError
from app.models.capture import Capture, CaptureStatus
from app.models.job import Tlp
from app.models.user import User
from app.schemas.common import StrictModel
from app.services import audit, captures

router = APIRouter(prefix="/captures", tags=["captures"])

Requester = Annotated[User, Depends(require("jobs:read"))]
Submitter = Annotated[User, Depends(require("jobs:write"))]


class CaptureCreate(StrictModel):
    url: str = Field(min_length=1, max_length=captures.MAX_URL_LENGTH)
    tlp: Tlp = Tlp.AMBER


def _ensure_enabled() -> None:
    if not get_settings().capture_enabled:
        raise ValidationFailedError("Screenshots are not enabled on this instance.")


@router.post(
    "",
    response_model=dict,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Request a screenshot of a page",
)
async def request_capture(
    payload: CaptureCreate,
    request: Request,
    session: DbSession,
    user: Submitter,
) -> dict[str, Any]:
    _ensure_enabled()
    url = captures.check_submitted_url(payload.url)
    capture = Capture(
        user_id=user.id,
        requested_by=user.username,
        url=url,
        tlp=payload.tlp.value,
        status=CaptureStatus.QUEUED,
    )
    session.add(capture)
    await session.flush()
    await audit.record(
        session,
        action="capture.request",
        actor=user.username,
        actor_id=user.id,
        target=str(capture.id),
        ip_address=client_ip(request),
        # The address is left out of the trail on purpose: the capture row holds it
        # for its owner, and the audit log is read by more people than that.
        details={"tlp": payload.tlp.value},
    )
    await session.commit()
    await request.app.state.queue.enqueue_job("capture_url", str(capture.id))
    return captures.view(capture)


@router.get("", response_model=list, summary="Your screenshots")
async def list_captures(session: DbSession, user: Requester) -> list[dict[str, Any]]:
    rows = (
        await session.execute(
            select(Capture)
            # The image is read only when someone asks for it, not for a list.
            .options(defer(Capture.image))
            .where(Capture.user_id == user.id)
            .order_by(Capture.created_at.desc())
            .limit(50)
        )
    ).scalars()
    return [captures.view(capture) for capture in rows]


@router.get("/{capture_id}", response_model=dict, summary="One screenshot and its status")
async def read_capture(
    capture_id: uuid.UUID, session: DbSession, user: Requester
) -> dict[str, Any]:
    capture = await captures.get_for_owner(session, user.id, capture_id)
    if capture is None:
        raise NotFoundError("The screenshot does not exist.", code="CAPTURE_NOT_FOUND")
    return captures.view(capture)


@router.get(
    "/{capture_id}/image",
    summary="The PNG of a finished screenshot",
    responses={200: {"content": {"image/png": {}}}},
)
async def read_capture_image(
    capture_id: uuid.UUID, session: DbSession, user: Requester
) -> Response:
    capture = await captures.get_for_owner(session, user.id, capture_id)
    if capture is None or capture.status != CaptureStatus.DONE or capture.image is None:
        raise NotFoundError("No image is available for this screenshot.", code="CAPTURE_NO_IMAGE")
    return Response(
        content=capture.image,
        media_type="image/png",
        headers={
            # A PNG that a browser could sniff as HTML is the risk here: the type is
            # fixed, nosniff stops reinterpretation, and nothing is cached.
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "private, no-store",
            "Content-Disposition": "inline; filename=capture.png",
            "Content-Security-Policy": "default-src 'none'; img-src 'self' data:",
        },
    )
