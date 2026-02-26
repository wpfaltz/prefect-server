from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0001_init_vault"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "principals",
        sa.Column("email", sa.String(length=320), primary_key=True),
        sa.Column("role", sa.String(length=32), nullable=False, server_default="user"),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="active"),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("updated_at", sa.BigInteger(), nullable=False),
        sa.Column("token_valid_after", sa.BigInteger(), nullable=False, server_default="0"),
    )

    op.create_table(
        "secrets",
        sa.Column("real_secret_name", sa.String(length=255), primary_key=True),
        sa.Column("ciphertext", sa.Text(), nullable=False),
        sa.Column("updated_at", sa.BigInteger(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
    )

    op.create_table(
        "secret_mapping",
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("generic_secret", sa.String(length=255), nullable=False),
        sa.Column("real_secret_name", sa.String(length=255), nullable=False),
        sa.Column("updated_at", sa.BigInteger(), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.PrimaryKeyConstraint("email", "generic_secret", name="pk_secret_mapping"),
        sa.ForeignKeyConstraint(["email"], ["principals.email"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["real_secret_name"], ["secrets.real_secret_name"], ondelete="RESTRICT"),
    )

    op.create_index("ix_secret_mapping_email", "secret_mapping", ["email"])
    op.create_index("ix_secret_mapping_generic", "secret_mapping", ["generic_secret"])

    op.create_table(
        "audit_log",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("ts", sa.BigInteger(), nullable=False),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("generic_secret", sa.String(length=255), nullable=True),
        sa.Column("real_secret_name", sa.String(length=255), nullable=True),
        sa.Column("details", sa.Text(), nullable=True),
    )

    op.create_index("ix_audit_log_ts", "audit_log", ["ts"])
    op.create_index("ix_audit_log_email", "audit_log", ["email"])

    # View: resolve (email, generic_secret) -> real_secret_name para usuários ativos e mappings ativos
    op.execute("""
    CREATE OR REPLACE VIEW v_secret_resolution AS
    SELECT
      m.email,
      m.generic_secret,
      m.real_secret_name
    FROM secret_mapping m
    JOIN principals p ON p.email = m.email
    WHERE m.active = TRUE
      AND p.status = 'active'
    """)


def downgrade():
    op.execute("DROP VIEW IF EXISTS v_secret_resolution")
    op.drop_index("ix_audit_log_email", table_name="audit_log")
    op.drop_index("ix_audit_log_ts", table_name="audit_log")
    op.drop_table("audit_log")

    op.drop_index("ix_secret_mapping_generic", table_name="secret_mapping")
    op.drop_index("ix_secret_mapping_email", table_name="secret_mapping")
    op.drop_table("secret_mapping")

    op.drop_table("secrets")
    op.drop_table("principals")
