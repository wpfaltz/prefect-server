from __future__ import annotations
from sqlalchemy import (
    Boolean, BigInteger, ForeignKey, Index, String, Text
)
from sqlalchemy.orm import Mapped, mapped_column
from app.db.session import Base

class Principal(Base):
    __tablename__ = "principals"

    email: Mapped[str] = mapped_column(String(320), primary_key=True)  # RFC max email len
    role: Mapped[str] = mapped_column(String(32), nullable=False, default="user")      # user/admin/service
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")  # active/disabled

    created_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
    updated_at: Mapped[int] = mapped_column(BigInteger, nullable=False)

    # opcional p/ revogação antecipada (recomendado)
    token_valid_after: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)

class Secret(Base):
    __tablename__ = "secrets"

    real_secret_name: Mapped[str] = mapped_column(String(255), primary_key=True)
    ciphertext: Mapped[str] = mapped_column(Text, nullable=False)
    updated_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    assign_level: Mapped[str] = mapped_column(String(16), nullable=False, default="reader")


class SecretMapping(Base):
    __tablename__ = "secret_mapping"

    email: Mapped[str] = mapped_column(
        String(320),
        ForeignKey("principals.email", ondelete="CASCADE"),
        primary_key=True,
    )
    generic_secret: Mapped[str] = mapped_column(String(255), primary_key=True)

    real_secret_name: Mapped[str] = mapped_column(
        String(255),
        ForeignKey("secrets.real_secret_name", ondelete="RESTRICT"),
        nullable=False,
    )

    updated_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

Index("ix_secret_mapping_email", SecretMapping.email)
Index("ix_secret_mapping_generic", SecretMapping.generic_secret)

class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    ts: Mapped[int] = mapped_column(BigInteger, nullable=False)

    email: Mapped[str] = mapped_column(String(320), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)   # read_secret, list_secrets, upsert_secret, set_mapping...
    status: Mapped[str] = mapped_column(String(32), nullable=False)   # ok/forbidden/not_found/error

    generic_secret: Mapped[str | None] = mapped_column(String(255), nullable=True)
    real_secret_name: Mapped[str | None] = mapped_column(String(255), nullable=True)

    details: Mapped[str | None] = mapped_column(Text, nullable=True)


Index("ix_audit_log_ts", AuditLog.ts)
Index("ix_audit_log_email", AuditLog.email)
