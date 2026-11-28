"""Recording a submitted file, so its identity and its trail are kept with the job.

Called at intake, right after the bytes are stored. The first submission of a
content creates the row; later ones only add to its counter and its last-seen time,
so a file pushed three times is one record with three submissions.

The record is built from the bytes that were received, never from the name the
uploader gave, which is only kept for display.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.models.sample import Sample
from app.services import file_identity, inspection
from app.services.uploads import StoredSample

logger = get_logger(__name__)


async def record(
    session: AsyncSession,
    *,
    payload: bytes,
    stored: StoredSample,
    submitted_name: str | None,
    actor: str,
) -> Sample:
    profile = file_identity.describe(payload, submitted_name=submitted_name)
    now = datetime.now(UTC)
    # Inserted only when absent: two identical uploads racing each other must not
    # produce two rows, so the uniqueness is left to the database.
    await session.execute(
        insert(Sample)
        .values(
            sha256=profile["sha256"],
            sha1=profile["sha1"],
            md5=profile["md5"],
            size=profile["size"],
            kind=profile["kind"],
            mime=profile["mime"],
            entropy=profile["entropy"],
            magic_hex=profile["magic_hex"],
            extension=profile["extension"],
            extension_mismatch=profile["extension_mismatch"],
            details=_details(profile),
            stored_path=stored.path,
            first_name=stored.display_name,
            first_submitted_by=actor[:128],
            # Counted by the update below, so a new row and a repeat are counted alike.
            submission_count=0,
            first_submitted_at=now,
            last_submitted_at=now,
        )
        .on_conflict_do_nothing(index_elements=[Sample.sha256])
    )
    await session.execute(
        update(Sample)
        .where(Sample.sha256 == profile["sha256"])
        .values(submission_count=Sample.submission_count + 1, last_submitted_at=now)
        .execution_options(synchronize_session=False)
    )
    row = (
        await session.execute(select(Sample).where(Sample.sha256 == profile["sha256"]))
    ).scalar_one()
    return row


async def attach_inspection(sample: Sample, *, payload: bytes, submitted_name: str | None) -> None:
    """Static inspection of the content, stored once on the record.

    A content already inspected is not inspected again: the result depends only on
    the bytes. A failure never fails the upload; it is recorded as unknown.
    """
    if "inspection" in (sample.details or {}):
        return
    try:
        result = await inspection.inspect_file(payload, submitted_name=submitted_name)
    except Exception as exc:
        logger.warning("inspection_failed", sha256=sample.sha256, error=str(exc)[:160])
        result = inspection.failed("The inspection could not be completed.")
    # A new dict: assigning a mutated one would not mark the JSONB column as changed.
    sample.details = {**(sample.details or {}), "inspection": result}


def _details(profile: dict[str, Any]) -> dict[str, Any]:
    return {"pe": profile["pe"]} if profile["pe"] else {}
