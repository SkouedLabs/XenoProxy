"""Jobs can be submitted without an account: a new origin for the public route.

Revision ID: 0015
Revises: 0014
"""

from __future__ import annotations

from alembic import op

revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # SQLAlchemy stores an Enum by member name, so the label is "PUBLIC". A database
    # that ran an earlier copy of this revision gets it from 0018.
    op.execute("ALTER TYPE job_origin ADD VALUE IF NOT EXISTS 'PUBLIC'")


def downgrade() -> None:
    # PostgreSQL cannot remove a value from an enum type. Existing public jobs keep
    # their origin, which the application still reads.
    pass
