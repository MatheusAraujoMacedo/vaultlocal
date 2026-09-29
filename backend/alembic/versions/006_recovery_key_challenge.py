"""add recovery key verifier and one-time challenge state

Revision ID: 006_recovery_key_challenge
Revises: 005_add_recovery_and_reset
Create Date: 2026-09-27
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "006_recovery_key_challenge"
down_revision: str | None = "005_add_recovery_and_reset"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("users", sa.Column("recovery_verifier", sa.Text(), nullable=True))
    op.add_column("users", sa.Column("recovery_challenge_hash", sa.Text(), nullable=True))
    op.add_column(
        "users",
        sa.Column("recovery_challenge_expires_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("users", "recovery_challenge_expires_at")
    op.drop_column("users", "recovery_challenge_hash")
    op.drop_column("users", "recovery_verifier")
