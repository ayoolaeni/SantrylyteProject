"""rule actions

Revision ID: c7d1e2f3a4b5
Revises: bed4bbe26c7d
Create Date: 2026-10-28 10:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'c7d1e2f3a4b5'
down_revision = 'bed4bbe26c7d'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('triage_rule', schema=None) as batch_op:
        batch_op.add_column(sa.Column('actions', sa.JSON(), nullable=True))


def downgrade():
    with op.batch_alter_table('triage_rule', schema=None) as batch_op:
        batch_op.drop_column('actions')
