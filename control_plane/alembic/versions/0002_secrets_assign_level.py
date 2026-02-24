from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0002_secrets_assign_level"
down_revision = "0001_init_vault"
branch_labels = None
depends_on = None

def upgrade():
    op.add_column("secrets", sa.Column("assign_level", sa.String(length=16), nullable=False, server_default="reader"))


def downgrade():
    op.drop_column("secrets", "assign_level")