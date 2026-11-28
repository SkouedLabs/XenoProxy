"""The public origin under the label SQLAlchemy actually writes.

An earlier copy of 0015 added the lowercase label 'public', while SQLAlchemy
stores an Enum by member name ('PUBLIC'), so every public submission failed on
insert. The stray lowercase label is harmless and stays: PostgreSQL cannot drop
a value from an enum type.

Revision ID: 0018
Revises: 0017
"""

from __future__ import annotations

from alembic import op

revision = "0018"
down_revision = "0017"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TYPE job_origin ADD VALUE IF NOT EXISTS 'PUBLIC'")


def downgrade() -> None:
    pass
