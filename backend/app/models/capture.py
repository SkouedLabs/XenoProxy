"""A screenshot of a web page, requested by one analyst.

The image is kept in the row, not on a volume: it is bounded in size, it belongs
to one owner, and a worker that stores files would need a writable mount that
nothing else needs. The owner reads it back through the API only.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, LargeBinary, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class CaptureStatus:
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    # Not attempted, or stopped: a destination refused by policy, or a RED job
    # with no proxy approved for it.
    REFUSED = "refused"


class Capture(Base):
    __tablename__ = "captures"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    requested_by: Mapped[str] = mapped_column(String(128), nullable=False)
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    # The TLP value ("clear" ... "red"), stored as text: the level caps the proxies used.
    tlp: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(16), default=CaptureStatus.QUEUED, nullable=False)
    final_url: Mapped[str] = mapped_column(String(2048), default="", nullable=False)
    title: Mapped[str] = mapped_column(String(200), default="", nullable=False)
    width: Mapped[int | None] = mapped_column(Integer, nullable=True)
    height: Mapped[int | None] = mapped_column(Integer, nullable=True)
    image: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    image_sha256: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    blocked_requests: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    error: Mapped[str] = mapped_column(Text, default="", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
