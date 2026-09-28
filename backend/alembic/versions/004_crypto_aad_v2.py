"""add crypto version for authenticated envelope v2

Revision ID: 004_crypto_aad_v2
Revises: 003_add_totp_mfa_fields
Create Date: 2026-09-27
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "004_crypto_aad_v2"
down_revision: Union[str, None] = "003_add_totp_mfa_fields"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "vault_entries",
        sa.Column("crypto_version", sa.SmallInteger(), nullable=False, server_default="1"),
    )
    if op.get_bind().dialect.name != "sqlite":
        op.create_check_constraint(
            "ck_vault_entries_crypto_version",
            "vault_entries",
            "crypto_version IN (1, 2)",
        )


def downgrade() -> None:
    if op.get_bind().dialect.name != "sqlite":
        op.drop_constraint("ck_vault_entries_crypto_version", "vault_entries", type_="check")
    op.drop_column("vault_entries", "crypto_version")
