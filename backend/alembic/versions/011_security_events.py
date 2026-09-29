"""add security timeline events

Revision ID: 011_security_events
Revises: 010_breached_count
Create Date: 2026-09-28
"""

import sqlalchemy as sa
from alembic import op

revision = "011_security_events"
down_revision = "010_breached_count"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "security_events",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "user_id",
            sa.String(length=36),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("event_type", sa.String(length=40), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_security_events_user_id",
        "security_events",
        ["user_id"],
    )
    op.create_index(
        "ix_security_events_event_type",
        "security_events",
        ["event_type"],
    )
    op.create_index(
        "ix_security_events_created_at",
        "security_events",
        ["created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_security_events_created_at", table_name="security_events")
    op.drop_index("ix_security_events_event_type", table_name="security_events")
    op.drop_index("ix_security_events_user_id", table_name="security_events")
    op.drop_table("security_events")
