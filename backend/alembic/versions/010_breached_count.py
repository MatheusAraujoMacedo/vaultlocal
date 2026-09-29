"""add breached count to health reports

Revision ID: 010_breached_count
Revises: 009_webauthn_devices
Create Date: 2026-09-28
"""

from alembic import op
import sqlalchemy as sa

revision = "010_breached_count"
down_revision = "009_webauthn_devices"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "health_reports",
        sa.Column("breached_count", sa.Integer(), server_default="0", nullable=False),
    )


def downgrade() -> None:
    op.drop_column("health_reports", "breached_count")
