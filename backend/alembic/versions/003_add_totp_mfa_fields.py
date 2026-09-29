"""add totp mfa fields to users

Revision ID: 003_add_totp_mfa_fields
Revises: 002_add_health_reports
Create Date: 2026-09-23
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "003_add_totp_mfa_fields"
down_revision: str | None = "002_add_health_reports"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("auth_method", sa.Text(), nullable=False, server_default="local"),
    )
    op.add_column("users", sa.Column("totp_secret_enc", sa.LargeBinary(), nullable=True))
    op.add_column(
        "users",
        sa.Column("mfa_configured", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column(
        "users",
        sa.Column("totp_failed_attempts", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        "users", sa.Column("totp_locked_until", sa.DateTime(timezone=True), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("users", "totp_locked_until")
    op.drop_column("users", "totp_failed_attempts")
    op.drop_column("users", "mfa_configured")
    op.drop_column("users", "totp_secret_enc")
    op.drop_column("users", "auth_method")
