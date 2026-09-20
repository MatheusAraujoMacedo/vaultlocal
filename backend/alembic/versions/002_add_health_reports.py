"""002_add_health_reports

Revision ID: 002_add_health_reports
Revises: 51459a466ecc
Create Date: 2026-09-19
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = '002_add_health_reports'
down_revision: Union[str, None] = '51459a466ecc'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'health_reports',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column(
            'user_id',
            sa.String(36),
            sa.ForeignKey('users.id', ondelete='CASCADE'),
            nullable=False,
            unique=True,
        ),
        sa.Column('total_entries', sa.Integer, nullable=False),
        sa.Column('weak_count', sa.Integer, nullable=False),
        sa.Column('reused_count', sa.Integer, nullable=False),
        sa.Column('old_count', sa.Integer, nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint('total_entries >= 0', name='ck_health_total_nonneg'),
        sa.CheckConstraint('weak_count >= 0', name='ck_health_weak_nonneg'),
        sa.CheckConstraint('reused_count >= 0', name='ck_health_reused_nonneg'),
        sa.CheckConstraint('old_count >= 0', name='ck_health_old_nonneg'),
        sa.CheckConstraint('weak_count <= total_entries', name='ck_health_weak_le_total'),
        sa.CheckConstraint('reused_count <= total_entries', name='ck_health_reused_le_total'),
        sa.CheckConstraint('old_count <= total_entries', name='ck_health_old_le_total'),
    )


def downgrade() -> None:
    op.drop_table('health_reports')
