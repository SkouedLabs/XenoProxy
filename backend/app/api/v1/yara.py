"""Administration of the local YARA rulesets: see them, pull one, switch one off.

The API never downloads anything: it lives on networks with no outbound route.
A pull is queued for the worker, which does, and the interface polls the status
file the worker writes.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request, status

from app.api.deps import DbSession, client_ip, require
from app.core.config import get_settings
from app.core.errors import ForbiddenError, NotFoundError
from app.models.user import User
from app.services import audit, yara_rules

router = APIRouter(prefix="/admin/yara", tags=["admin"])

YaraAdmin = Annotated[User, Depends(require("plugins:manage"))]


def _require_source(source_id: str) -> yara_rules.RuleSource:
    source = yara_rules.source_by_id(source_id)
    if source is None:
        raise NotFoundError(f"Unknown ruleset '{source_id}'.")
    return source


@router.get("", response_model=dict, summary="YARA rulesets and the last pull")
async def get_overview(_user: YaraAdmin) -> dict[str, Any]:
    return yara_rules.overview()


@router.post(
    "/sources/{source_id}/pull",
    response_model=dict,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Pull a public ruleset (runs in the worker)",
)
async def pull_source(
    source_id: str, request: Request, session: DbSession, user: YaraAdmin
) -> dict[str, Any]:
    source = _require_source(source_id)
    if not get_settings().yara_pull_enabled:
        raise ForbiddenError("Pulling rulesets is disabled on this instance.")
    yara_rules.write_status(source=source.id, state="queued")
    await request.app.state.queue.enqueue_job("pull_yara_ruleset", source.id)
    await audit.record(
        session,
        action="yara.pull",
        actor=user.username,
        actor_id=user.id,
        target=source.id,
        ip_address=client_ip(request),
        details={"url": source.url},
    )
    return yara_rules.overview()


@router.put("/sources/{source_id}/enabled", response_model=dict, summary="Enable or disable")
async def set_enabled(
    source_id: str, enabled: bool, request: Request, session: DbSession, user: YaraAdmin
) -> dict[str, Any]:
    source = _require_source(source_id)
    yara_rules.set_enabled(source.id, enabled)
    await audit.record(
        session,
        action="yara.enable" if enabled else "yara.disable",
        actor=user.username,
        actor_id=user.id,
        target=source.id,
        ip_address=client_ip(request),
    )
    return yara_rules.overview()


@router.delete("/sources/{source_id}", response_model=dict, summary="Remove a pulled ruleset")
async def remove_source(
    source_id: str, request: Request, session: DbSession, user: YaraAdmin
) -> dict[str, Any]:
    source = _require_source(source_id)
    yara_rules.remove_source(source.id)
    await audit.record(
        session,
        action="yara.remove",
        actor=user.username,
        actor_id=user.id,
        target=source.id,
        ip_address=client_ip(request),
    )
    return yara_rules.overview()
