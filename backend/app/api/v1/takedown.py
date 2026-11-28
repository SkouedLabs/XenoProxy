"""Abuse-report draft for a job (alpha). Returns text; sends nothing."""

from __future__ import annotations

import uuid
from typing import Annotated, Literal

from fastapi import APIRouter, Depends
from fastapi.responses import PlainTextResponse

from app.api.deps import DbSession, require
from app.api.v1.jobs import _load_job
from app.core.errors import AppError
from app.models.job import ObservableType, ReportStatus
from app.models.user import User
from app.services import takedown

router = APIRouter(prefix="/jobs", tags=["takedown"])
ExporterUser = Annotated[User, Depends(require("jobs:export"))]


@router.get(
    "/{job_id}/takedown-draft",
    response_class=PlainTextResponse,
    summary="Abuse-report draft for a registrar or host; nothing is sent (alpha)",
)
async def takedown_draft(
    job_id: uuid.UUID,
    session: DbSession,
    user: ExporterUser,
    recipient: Literal["registrar", "hosting"] = "hosting",
) -> PlainTextResponse:
    job = await _load_job(session, job_id, user)
    if job.tlp not in takedown.DRAFTABLE_TLPS:
        raise AppError(
            "A takedown draft is only produced for TLP:CLEAR or TLP:GREEN jobs; the report "
            "would disclose the evidence to a third party.",
            code="TLP_RESTRICTED",
            status_code=403,
        )
    if job.observable_type not in takedown.REPORTABLE:
        raise AppError("Only IP, domain and URL observables can be reported.", status_code=422)
    if recipient == "registrar" and job.observable_type is not ObservableType.DOMAIN:
        raise AppError("A registrar report is only for a domain.", status_code=422)

    evidence = [
        takedown.Evidence(plugin=report.plugin_name, headline=str(report.summary_data["headline"]))
        for report in job.reports
        if report.status is ReportStatus.SUCCESS and report.summary_data.get("headline")
    ]
    body = takedown.render_draft(
        value=job.observable_value,
        observable_type=job.observable_type,
        verdict=job.verdict,
        first_seen=job.created_at,
        evidence=evidence,
        recipient=recipient,
    )
    return PlainTextResponse(body, headers={"Cache-Control": "no-store"})
