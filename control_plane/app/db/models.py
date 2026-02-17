from __future__ import annotations
from sqlalchemy import String, Integer, Boolean, ForeignKey, UniqueConstraint, Index
from sqlalchemy.orm import Mapped, mapped_column
from app.db.session import Base

class Secret(Base):
    __tablename__ = "secrets"

    secret_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    ciphertext: Mapped[str] = mapped_column(String, nullable=False)
    updated_at: Mapped[int] = mapped_column(Integer, nullable=False)
    deliverable: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

class Policy(Base):
    __tablename__ = "policies"
    __table_args__ = (
        UniqueConstraint("email", "secret_id", name="uq_policy_email_secret"),
        Index("ix_policy_email", "email"),
        Index("ix_policy_secret", "secret_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    email: Mapped[str] = mapped_column(String(320), nullable=False)   # max email length
    secret_id: Mapped[str] = mapped_column(String(255), ForeignKey("secrets.secret_id", ondelete="CASCADE"), nullable=False)

class AuditLog(Base):
    __tablename__ = "audit"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[int] = mapped_column(Integer, nullable=False)
    email: Mapped[str] = mapped_column(String(320), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    secret_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
