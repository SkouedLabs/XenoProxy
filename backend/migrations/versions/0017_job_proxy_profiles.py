"""A job can be forced through chosen proxy profiles.

Guarded like every revision after the baseline; see `app.core.schema_guards`.

Revision ID: 0017
Revises: 0016
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from app.core import schema_guards as guards

revision = "0017"
down_revision = "0016"
branch_labels = None
depends_on = None


def upgrade() -> None:
    guards.add_column(
        "jobs",
        sa.Column(
            "proxy_profiles",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
    )


def downgrade() -> None:
    guards.drop_column("jobs", "proxy_profiles")
