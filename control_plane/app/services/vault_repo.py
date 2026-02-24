from __future__ import annotations
from sqlalchemy.orm import Session
from sqlalchemy import select, delete, text
from app.db.models import Principal, Secret, SecretMapping, AuditLog

def ensure_principal(db: Session, email: str, *, role: str = "user", status: str = "active", now: int) -> Principal:
    email = email.lower()
    p = db.get(Principal, email)
    if p:
        if p.updated_at != now:
            p.updated_at = now
        return p
    p = Principal(email=email, role=role, status=status, created_at=now, updated_at=now, token_valid_after=0)
    db.add(p)
    db.commit()
    return p


def get_principal(db: Session, email: str) -> Principal | None:
    return db.get(Principal, email.lower())


def upsert_real_secret(
    db: Session,
    *,
    real_secret_name: str,
    ciphertext: str,
    updated_at: int,
    enabled: bool = True,
    assign_level: str = "reader",
) -> None:
    s = db.get(Secret, real_secret_name)
    if s:
        s.ciphertext = ciphertext
        s.updated_at = updated_at
        s.enabled = enabled
        # novo
        if hasattr(s, "assign_level"):
            s.assign_level = assign_level
    else:
        kwargs = dict(
            real_secret_name=real_secret_name,
            ciphertext=ciphertext,
            updated_at=updated_at,
            enabled=enabled,
        )
        # novo (se o model tiver)
        if "assign_level" in Secret.__table__.columns:
            kwargs["assign_level"] = assign_level

        db.add(Secret(**kwargs))
    db.commit()


def set_mapping(db: Session, *, email: str, generic_secret: str, real_secret_name: str, updated_at: int, active: bool = True) -> None:
    email = email.lower()
    m = db.get(SecretMapping, {"email": email, "generic_secret": generic_secret})
    if m:
        m.real_secret_name = real_secret_name
        m.updated_at = updated_at
        m.active = active
    else:
        db.add(
            SecretMapping(
                email=email,
                generic_secret=generic_secret,
                real_secret_name=real_secret_name,
                updated_at=updated_at,
                active=active,
            )
        )
    db.commit()


def resolve_real_secret_name(db: Session, *, email: str, generic_secret: str) -> str | None:
    # Usa a VIEW (v_secret_resolution)
    row = db.execute(
        text("SELECT real_secret_name FROM v_secret_resolution WHERE email=:email AND generic_secret=:gs LIMIT 1"),
        {"email": email.lower(), "gs": generic_secret},
    ).fetchone()
    return row[0] if row else None


def get_secret(db: Session, real_secret_name: str) -> Secret | None:
    return db.get(Secret, real_secret_name)


def audit(db: Session, *, ts: int, email: str, action: str, status: str,
          generic_secret: str | None = None, real_secret_name: str | None = None, details: str | None = None) -> None:
    db.add(
        AuditLog(
            ts=ts,
            email=email.lower(),
            action=action,
            status=status,
            generic_secret=generic_secret,
            real_secret_name=real_secret_name,
            details=details,
        )
    )
    db.commit()


def list_audit(db: Session, limit: int = 200) -> list[AuditLog]:
    stmt = select(AuditLog).order_by(AuditLog.ts.desc()).limit(limit)
    return list(db.execute(stmt).scalars().all())