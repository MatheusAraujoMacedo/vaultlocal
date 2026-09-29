"""add asymmetric recovery proof material

Revision ID: 007_recovery_signing_key
Revises: 006_recovery_key_challenge
Create Date: 2026-09-27
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "007_recovery_signing_key"
down_revision: str | None = "006_recovery_key_challenge"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("users", sa.Column("recovery_public_key", sa.Text(), nullable=True))
    op.add_column("users", sa.Column("recovery_wrapped_signing_key", sa.Text(), nullable=True))
    op.add_column("users", sa.Column("recovery_signing_nonce", sa.String(64), nullable=True))


def downgrade() -> None:
    op.drop_column("users", "recovery_signing_nonce")
    op.drop_column("users", "recovery_wrapped_signing_key")
    op.drop_column("users", "recovery_public_key")
