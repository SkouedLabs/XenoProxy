"""Submitted files are recorded: hashes, size, format and the trail of submissions.

One row per content, keyed by SHA-256. A job made from a file points at it.

Revision ID: 0014
Revises: 0013
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "samples",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("sha256", sa.String(64), nullable=False, unique=True),
        sa.Column("sha1", sa.String(40), nullable=False),
        sa.Column("md5", sa.String(32), nullable=False),
        sa.Column("size", sa.BigInteger(), nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("mime", sa.String(128), nullable=False),
        sa.Column("entropy", sa.Float(), nullable=False),
        sa.Column("magic_hex", sa.String(32), nullable=False),
        sa.Column("extension", sa.String(32), nullable=False, server_default=""),
        sa.Column("extension_mismatch", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("details", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("stored_path", sa.String(512), nullable=False),
        sa.Column("first_name", sa.String(256), nullable=False),
        sa.Column("first_submitted_by", sa.String(128), nullable=False),
        sa.Column("submission_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "first_submitted_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "last_submitted_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.add_column(
        "jobs",
        sa.Column(
            "sample_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("samples.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.create_index("ix_jobs_sample_id", "jobs", ["sample_id"])


def downgrade() -> None:
    op.drop_index("ix_jobs_sample_id", table_name="jobs")
    op.drop_column("jobs", "sample_id")
    op.drop_table("samples")
