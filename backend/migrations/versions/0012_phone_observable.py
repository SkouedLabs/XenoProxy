"""Phone numbers become a first-class observable type.

The observable type is stored as a Postgres enum, so a new member is a new value on
the type. Guarded like every revision after the baseline; see `app.core.schema_guards`.

Revision ID: 0012
Revises: 0011
"""

from __future__ import annotations

from app.core import schema_guards as guards

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # SQLAlchemy stores an Enum by member name, so the value is the name, not "phone".
    guards.add_enum_value("observable_type", "PHONE")


def downgrade() -> None:
    # Postgres cannot drop an enum value in place. Rows holding PHONE would have to be
    # removed or retyped first, so the value is left in place on downgrade.
    pass
