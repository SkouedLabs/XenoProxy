"""Plain-text blocklists built from stored verdicts, for firewalls and EDR tooling (alpha).

Authenticated like every other read: the caller's token decides which jobs are visible,
using the same visibility rule as the job list. Only the verdict and the observable are
read; no provider is called.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query
from fastapi.responses import PlainTextResponse

from app.api.deps import DbSession, require
from app.api.v1.jobs import _visible_jobs
from app.core.logging import get_logger
from app.models.job import Job, ObservableType
from app.models.user import User
from app.services import blocklist

logger = get_logger(__name__)
router = APIRouter(prefix="/blocklist", tags=["blocklist"])

ExporterUser = Annotated[User, Depends(require("jobs:export"))]
_SCAN_LIMIT = 100_000  # bounds the rows read per request


@router.get(
    "/{kind}",
    response_class=PlainTextResponse,
    summary="Plain-text blocklist of malicious IPs or domains (alpha)",
)
async def get_blocklist(
    kind: Literal["ip", "domain"],
    session: DbSession,
    user: ExporterUser,
    days: int = Query(30, ge=1, le=365, description="Look-back window in days."),
    min_verdict: Literal["malicious", "suspicious"] = "malicious",
) -> PlainTextResponse:
    since = datetime.now(UTC) - timedelta(days=days)
    statement = (
        _visible_jobs(user)
        .with_only_columns(
            Job.observable_value,
            Job.observable_type,
            Job.verdict,
            Job.tlp,
            Job.created_at,
        )
        .where(
            Job.observable_type == ObservableType(kind),
            Job.created_at >= since,
            Job.verdict.in_(blocklist.ALLOWED_VERDICTS[min_verdict]),
            Job.tlp.in_(blocklist.EXPORT_TLPS),
        )
        .order_by(Job.created_at.desc())
        .limit(_SCAN_LIMIT)
    )
    rows = (await session.execute(statement)).all()
    candidates = [
        blocklist.Candidate(
            value=row.observable_value,
            observable_type=row.observable_type,
            verdict=row.verdict,
            tlp=row.tlp,
            created_at=row.created_at,
        )
        for row in rows
    ]
    entries, omitted = blocklist.build_entries(candidates, kind, min_verdict)
    logger.info("blocklist_exported", kind=kind, entries=len(entries), omitted=omitted)
    body = blocklist.render(entries, kind, min_verdict, omitted, datetime.now(UTC))
    return PlainTextResponse(body, headers={"Cache-Control": "no-store"})
