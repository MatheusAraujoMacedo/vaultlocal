"""add entry favorites

Revision ID: 014_entry_favorites
Revises: 013_entry_trash
"""

import sqlalchemy as sa
from alembic import op

revision = "014_entry_favorites"
down_revision = "013_entry_trash"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "vault_entries",
        sa.Column("favorite", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.create_index("ix_vault_entries_favorite", "vault_entries", ["favorite"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_vault_entries_favorite", table_name="vault_entries")
    op.drop_column("vault_entries", "favorite")
