"""Directory accounts as a sign-in source.

A user who signs in through the LDAP directory is provisioned with the `LDAP`
auth source, so the same rules that already apply to single sign-on accounts
apply to them: no local password, no local second factor, groups and role
recomputed on every sign-in.

PostgreSQL cannot remove a value from an enum, so downgrading leaves the value
in place; the application then simply stops issuing it.

Revision ID: 0011
Revises: 0010
"""

from __future__ import annotations

from app.core import schema_guards as guards

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    guards.add_enum_value("auth_source", "LDAP")


def downgrade() -> None:
    """Intentionally empty: see the module docstring."""
