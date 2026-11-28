"""Request and response for the password breach check."""

from __future__ import annotations

from pydantic import BaseModel, Field


class PasswordCheckRequest(BaseModel):
    password: str = Field(min_length=1, max_length=256)


class PasswordCheckOut(BaseModel):
    breached: bool
    occurrences: int
    verdict: str  # the standard vocabulary: "suspicious" on a hit, "unknown" otherwise
