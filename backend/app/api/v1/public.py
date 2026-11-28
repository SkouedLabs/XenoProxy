"""Public submission: an observable sent without an account.

Off unless the deployment sets BACKEND_PUBLIC_SUBMISSION_ENABLED. The route ignores
every selection a client could send and always runs the "Public submission"
playbook at TLP:CLEAR, so an anonymous caller cannot choose internal sources,
connectors (which publish outside the instance) or pivots. Jobs are stored with
the PUBLIC origin, so signed-in users can filter them in the history.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Request, status
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.api.deps import DbSession, client_ip
from app.core.config import get_settings
from app.core.errors import NotFoundError, ValidationFailedError
from app.models.job import Job, JobOrigin, PluginKind, Tlp
from app.schemas.public import PublicSourceOut, PublicSubmissionIn, PublicSubmissionOut
from app.services import audit, orchestrator

router = APIRouter(prefix="/public", tags=["public"])

PUBLIC_PLAYBOOK = "Public submission"


def _require_enabled() -> None:
    if not get_settings().public_submission_enabled:
        # Reported as missing, so a disabled deployment does not advertise the route.
        raise NotFoundError("The public submission service is not enabled.")


def _public_view(job: Job) -> PublicSubmissionOut:
    return PublicSubmissionOut(
        id=job.id,
        value=job.observable_value,
        type=job.observable_type.value,
        status=job.status.value,
        verdict=job.verdict.value,
        created_at=job.created_at,
        finished_at=job.finished_at,
        sources=[
            PublicSourceOut(
                name=report.plugin_name,
                status=report.status.value,
                verdict=str((report.summary_data or {}).get("verdict") or "unknown"),
            )
            for report in job.reports
            if report.plugin_type is PluginKind.ANALYZER
        ],
    )


@router.post(
    "/submissions",
    response_model=PublicSubmissionOut,
    status_code=status.HTTP_201_CREATED,
    summary="Submit an observable without an account",
)
async def submit(
    payload: PublicSubmissionIn, request: Request, session: DbSession
) -> PublicSubmissionOut:
    _require_enabled()
    job_request = await orchestrator.resolve_selection(
        session,
        raw_observable=payload.value,
        analyzers=None,
        connectors=None,
        pivots=None,
        plugins=None,
        playbook_name=PUBLIC_PLAYBOOK,
        tags=[],
        tlp=Tlp.CLEAR,
        scan_mode=None,
        scan_check_minutes=None,
        runtime_configuration=None,
    )
    if job_request.observable.is_private:
        raise ValidationFailedError("Private addresses cannot be submitted publicly.")

    job = await orchestrator.create_job(
        session,
        job_request,
        requested_by=None,
        requested_by_name="public",
        origin=JobOrigin.PUBLIC,
    )
    await audit.record(
        session,
        action="job.create_public",
        actor="public",
        target=str(job.id),
        ip_address=client_ip(request),
        details={
            "observable_type": job.observable_type.value,
            "analyzers": job_request.selection.analyzers,
        },
    )
    await session.commit()

    await request.app.state.queue.enqueue_job("run_job", str(job.id))
    await session.refresh(job, ["reports"])
    return _public_view(job)


@router.get(
    "/submissions/{job_id}",
    response_model=PublicSubmissionOut,
    summary="Read the result of a public submission",
)
async def read_submission(job_id: uuid.UUID, session: DbSession) -> PublicSubmissionOut:
    """The identifier returned by the submission is the only key: it is a random UUID."""
    _require_enabled()
    job = (
        await session.execute(
            select(Job)
            .where(Job.id == job_id, Job.origin == JobOrigin.PUBLIC)
            .options(selectinload(Job.reports))
        )
    ).scalar_one_or_none()
    if job is None:
        raise NotFoundError("The submission does not exist.")
    return _public_view(job)
