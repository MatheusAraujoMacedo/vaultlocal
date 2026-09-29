"""add entry trash retention

Revision ID: 013_entry_trash
Revises: 012_entry_expiration
"""

import sqlalchemy as sa
from alembic import op

revision = "013_entry_trash"
down_revision = "012_entry_expiration"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("vault_entries", sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_vault_entries_deleted_at", "vault_entries", ["deleted_at"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_vault_entries_deleted_at", table_name="vault_entries")
    op.drop_column("vault_entries", "deleted_at")
