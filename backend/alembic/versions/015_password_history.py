"""add encrypted password history

Revision ID: 015_password_history
Revises: 014_entry_favorites
"""

import sqlalchemy as sa
from alembic import op

revision = "015_password_history"
down_revision = "014_entry_favorites"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("vault_entries", sa.Column("password_history_enc", sa.Text(), nullable=True))
    op.add_column("vault_entries", sa.Column("nonce_password_history", sa.String(64), nullable=True))


def downgrade() -> None:
    op.drop_column("vault_entries", "nonce_password_history")
    op.drop_column("vault_entries", "password_history_enc")
