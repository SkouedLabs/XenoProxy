"""Password breach check (alpha): k-anonymity, nothing stored, off unless enabled."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from app.api.deps import require
from app.core.config import get_settings
from app.core.errors import ForbiddenError
from app.core.logging import get_logger
from app.models.user import User
from app.schemas.passwords import PasswordCheckOut, PasswordCheckRequest
from app.services import password_check

logger = get_logger(__name__)
router = APIRouter(prefix="/passwords", tags=["passwords"])

AnalystUser = Annotated[User, Depends(require("jobs:read"))]


@router.post(
    "/check",
    response_model=PasswordCheckOut,
    summary="Is this password in a known breach? (alpha, k-anonymity)",
)
async def check_password(payload: PasswordCheckRequest, user: AnalystUser) -> PasswordCheckOut:
    if not get_settings().hibp_passwords_enabled:
        raise ForbiddenError("The password breach check is disabled on this instance.")
    count = await password_check.breach_count(payload.password)
    # The password, its hash and its prefix are never logged; only the outcome is.
    logger.info("password_checked", requested_by=user.username, breached=count > 0)
    return PasswordCheckOut(
        breached=count > 0,
        occurrences=count,
        verdict="suspicious" if count > 0 else "unknown",
    )
