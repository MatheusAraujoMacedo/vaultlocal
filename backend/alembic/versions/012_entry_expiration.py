"""add entry expiration metadata

Revision ID: 012_entry_expiration
Revises: 011_security_events
Create Date: 2026-09-29
"""

import sqlalchemy as sa
from alembic import op

revision = "012_entry_expiration"
down_revision = "011_security_events"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "vault_entries",
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("vault_entries", "expires_at")
