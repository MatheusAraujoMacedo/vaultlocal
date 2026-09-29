"""add encrypted custom fields

Revision ID: 016_custom_fields
Revises: 015_password_history
"""

import sqlalchemy as sa
from alembic import op

revision = "016_custom_fields"
down_revision = "015_password_history"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("vault_entries", sa.Column("custom_fields_enc", sa.Text(), nullable=True))
    op.add_column("vault_entries", sa.Column("nonce_custom_fields", sa.String(64), nullable=True))


def downgrade() -> None:
    op.drop_column("vault_entries", "nonce_custom_fields")
    op.drop_column("vault_entries", "custom_fields_enc")
