"""What an anonymous submitter sends, and the only view of a result they get back."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field


class PublicSubmissionIn(BaseModel):
    value: str = Field(min_length=1, max_length=2048, description="An IP, domain, URL or hash")


class PublicQuotaOut(BaseModel):
    """How many anonymous submissions this caller may still make in the current window."""

    limit: int
    remaining: int
    window_seconds: int
    reset_seconds: int


class PublicSourceOut(BaseModel):
    name: str
    status: str
    verdict: str


class PublicSubmissionOut(BaseModel):
    """The important part of a result: the verdict and what each source said.

    Internal fields (requester, groups, raw responses, stored paths) are never part of it.
    """

    id: uuid.UUID
    value: str
    type: str
    status: str
    verdict: str
    created_at: datetime | None
    finished_at: datetime | None
    sources: list[PublicSourceOut]
