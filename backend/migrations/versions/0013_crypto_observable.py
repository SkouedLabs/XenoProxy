"""Crypto addresses become a first-class observable type.

Same pattern as 0012: the type is a Postgres enum, stored by member name, so the value
added here is "CRYPTO". Guarded through `app.core.schema_guards`.

Revision ID: 0013
Revises: 0012
"""

from __future__ import annotations

from app.core import schema_guards as guards

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    guards.add_enum_value("observable_type", "CRYPTO")


def downgrade() -> None:
    # Postgres cannot drop an enum value in place; rows holding CRYPTO would need retyping
    # first, so the value stays on downgrade.
    pass
