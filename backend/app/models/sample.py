"""A file submitted for analysis, recorded once per content.

The row is keyed by SHA-256, so the same bytes submitted twice are one sample with
two submissions, not two samples. Hashes, size and the format are what another
analyst searches on; the submitted names and the counters are the trail of who
pushed it and when. Each individual submission is also in the audit log.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, Boolean, DateTime, Float, Integer, String, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class Sample(Base):
    __tablename__ = "samples"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    sha256: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    sha1: Mapped[str] = mapped_column(String(40), nullable=False)
    md5: Mapped[str] = mapped_column(String(32), nullable=False)
    size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    mime: Mapped[str] = mapped_column(String(128), nullable=False)
    entropy: Mapped[float] = mapped_column(Float, nullable=False)
    magic_hex: Mapped[str] = mapped_column(String(32), nullable=False)
    extension: Mapped[str] = mapped_column(String(32), default="", nullable=False)
    extension_mismatch: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    # Format-specific facts (PE machine and compile time, ...), kept as read.
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    # Where the bytes sit on the uploads volume. Internal; never returned by the API.
    stored_path: Mapped[str] = mapped_column(String(512), nullable=False)
    first_name: Mapped[str] = mapped_column(String(256), nullable=False)
    first_submitted_by: Mapped[str] = mapped_column(String(128), nullable=False)
    submission_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    first_submitted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_submitted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
