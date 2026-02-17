from __future__ import annotations

from sqlalchemy.orm import Session
from sqlalchemy import select, delete

from app.db.models import Secret, Policy, AuditLog

def upsert_secret(db: Session, *, secret_id: str, ciphertext: str, updated_at: int, deliverable: bool):
    obj = db.get(Secret, secret_id)
    if obj:
        obj.ciphertext = ciphertext
        obj.updated_at = updated_at
        obj.deliverable = deliverable
    else:
        db.add(Secret(secret_id=secret_id, ciphertext=ciphertext, updated_at=updated_at, deliverable=deliverable))
    db.commit()

def get_secret(db: Session, secret_id: str) -> Secret | None:
    return db.get(Secret, secret_id)

def grant(db: Session, email: str, secret_id: str):
    email = email.lower()
    # garante que o secret existe
    if not db.get(Secret, secret_id):
        raise ValueError("Secret not found.")
    # evita duplicar
    stmt = select(Policy).where(Policy.email == email, Policy.secret_id == secret_id)
    if db.execute(stmt).scalar_one_or_none() is None:
        db.add(Policy(email=email, secret_id=secret_id))
        db.commit()

def revoke(db: Session, email: str, secret_id: str):
    email = email.lower()
    stmt = delete(Policy).where(Policy.email == email, Policy.secret_id == secret_id)
    db.execute(stmt)
    db.commit()

def is_allowed(db: Session, email: str, secret_id: str) -> bool:
    email = email.lower()
    stmt = select(Policy.id).where(Policy.email == email, Policy.secret_id == secret_id).limit(1)
    return db.execute(stmt).first() is not None

def audit(db: Session, ts: int, email: str, action: str, secret_id: str | None, status: str):
    db.add(AuditLog(ts=ts, email=email.lower(), action=action, secret_id=secret_id, status=status))
    db.commit()

def list_audit(db: Session, limit: int = 200):
    stmt = select(AuditLog).order_by(AuditLog.ts.desc()).limit(limit)
    return list(db.execute(stmt).scalars().all())
