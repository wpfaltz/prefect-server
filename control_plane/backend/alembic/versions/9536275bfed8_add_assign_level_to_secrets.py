"""add assign_level to secrets

Revision ID: 9536275bfed8
Revises: 0002_secrets_assign_level
Create Date: 2026-02-17 22:33:13.475500

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '9536275bfed8'
down_revision: Union[str, Sequence[str], None] = '0002_secrets_assign_level'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
