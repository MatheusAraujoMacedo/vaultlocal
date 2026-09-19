"""zero knowledge entries

Revision ID: 51459a466ecc
Revises: 9ed8100d85dc
Create Date: 2026-09-19 12:38:33.013943

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '51459a466ecc'
down_revision: Union[str, None] = '9ed8100d85dc'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # test/dev data only — the auth_hash/salts of every existing user were
    # computed under the old (server-derives-KEK) model and cannot be
    # reconciled with the new client-side derivation, so this migration
    # resets the vault instead of trying to migrate it in place.
    op.execute("DELETE FROM vault_entries")
    op.execute("DELETE FROM sessions")
    op.execute("DELETE FROM users")
    op.add_column("vault_entries", sa.Column("wrapped_data_key", sa.Text(), nullable=False))
    op.add_column("vault_entries", sa.Column("wrapped_nonce", sa.String(length=64), nullable=False))


def downgrade() -> None:
    op.drop_column("vault_entries", "wrapped_nonce")
    op.drop_column("vault_entries", "wrapped_data_key")
