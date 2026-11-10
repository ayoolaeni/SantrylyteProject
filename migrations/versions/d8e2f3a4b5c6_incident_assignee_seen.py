"""incident assignee_seen_at

Revision ID: d8e2f3a4b5c6
Revises: c7d1e2f3a4b5
Create Date: 2026-11-10 10:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'd8e2f3a4b5c6'
down_revision = 'c7d1e2f3a4b5'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('incident', schema=None) as batch_op:
        batch_op.add_column(sa.Column('assignee_seen_at', sa.DateTime(timezone=True), nullable=True))


def downgrade():
    with op.batch_alter_table('incident', schema=None) as batch_op:
        batch_op.drop_column('assignee_seen_at')
