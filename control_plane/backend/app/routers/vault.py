from __future__ import annotations
import time
from typing import Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.db.deps import get_db
from app.db.models import Principal, Secret, SecretMapping
from app.core.settings import settings
from app.services.jwt_service import verify_token
from app.services.vault_crypto import encrypt, decrypt
from app.services import vault_repo
from app.services.rbac import can_set_mapping, can_assign_secret, can_modify_principal, ROLE_RANK

router = APIRouter()

class RealSecretUpsert(BaseModel):
    real_secret_name: str
    value: str
    enabled: bool = True
    assign_level: str = "reader"  # reader|writer|admin


class PrincipalUpsert(BaseModel):
    email: str
    role: str = "user"      # user/reader/writer/admin/service (você decide)
    status: str = "active"  # active/disabled

class MappingItem(BaseModel):
    email: str
    generic_secret: str
    real_secret_name: str
    active: bool = True


class MappingsBulk(BaseModel):
    items: list[MappingItem]


def _get_identity(authorization: str | None) -> tuple[str, str, int]:
    """
    Returns: (email, role, iat)
    """
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token.")
    token = authorization.split(" ", 1)[1].strip()
    try:
        payload = verify_token(token)
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}")

    email = str(payload.get("email", "")).lower()
    role = str(payload.get("role", "user"))
    iat = int(payload.get("iat", 0))

    if not email:
        raise HTTPException(status_code=401, detail="Token missing email.")
    return email, role, iat

def _get_actor(
    db: Session,
    authorization: str | None,
) -> tuple[str, str, int, Principal]:
    """
    Returns: (email, effective_role_from_db, iat, principal)
    Token role is ignored for authorization; DB is the source of truth.
    """
    now = int(time.time())
    email, _role_from_token, iat = _get_identity(authorization)

    p = vault_repo.get_principal(db, email)

    is_bootstrap_admin = email in settings.VAULT_ADMIN_EMAILS

    if not p:
        p = vault_repo.ensure_principal(
            db,
            email,
            role=("admin" if is_bootstrap_admin else "user"),
            status="active",
            now=now,
        )
    else:
        # bootstrap: garante admin no DB (pra UI e consistência)
        if is_bootstrap_admin and p.role != "admin":
            p.role = "admin"
            p.status = "active"
            p.updated_at = now
            db.commit()

    # role efetiva SEMPRE do DB
    return p.email, p.role, iat, p

def _require_admin(email: str, role: str):
    # aceita role admin (service token) OU email listado
    if role == "admin":
        return
    if email not in settings.VAULT_ADMIN_EMAILS:
        raise HTTPException(status_code=403, detail="Admin permission required.")

@router.get("/me")
def me(
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    email, role, _iat, p = _get_actor(db, authorization)
    return {"email": p.email, "role": p.role, "status": p.status}

@router.get("/secrets/{generic_secret}")
def read_secret(
    generic_secret: str,
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    now = int(time.time())
    email, role, iat, p = _get_actor(db, authorization)

    if not p:
        # auto-register (MVP). Você pode mudar pra "admin cria principal" depois.
        p = vault_repo.ensure_principal(db, email, role="user", status="active", now=now)

    if p.status != "active":
        vault_repo.audit(db, ts=now, email=email, action="read_secret", status="forbidden_principal_disabled",
                         generic_secret=generic_secret)
        raise HTTPException(status_code=403, detail="Principal disabled.")

    # revogação antecipada (opcional): iat precisa ser >= token_valid_after
    if iat < int(p.token_valid_after or 0):
        vault_repo.audit(db, ts=now, email=email, action="read_secret", status="forbidden_token_revoked",
                         generic_secret=generic_secret)
        raise HTTPException(status_code=401, detail="Token revoked. Re-authenticate.")

    real_name = vault_repo.resolve_real_secret_name(db, email=email, generic_secret=generic_secret)
    if not real_name:
        vault_repo.audit(db, ts=now, email=email, action="read_secret", status="not_found_mapping",
                         generic_secret=generic_secret)
        raise HTTPException(status_code=404, detail="No mapping for this secret.")

    s = vault_repo.get_secret(db, real_name)
    if not s or not s.enabled:
        vault_repo.audit(db, ts=now, email=email, action="read_secret", status="not_found_secret",
                         generic_secret=generic_secret, real_secret_name=real_name)
        raise HTTPException(status_code=404, detail="Secret not found.")

    # entrega do valor (cuidado: isso é inevitável se o flow precisa usar)
    value = decrypt(s.ciphertext)

    vault_repo.audit(db, ts=now, email=email, action="read_secret", status="ok",
                     generic_secret=generic_secret, real_secret_name=real_name)
    return {"generic_secret": generic_secret, "real_secret_name": real_name, "value": value, "updated_at": s.updated_at}


@router.get("/secrets")
def read_secrets_bulk(
    names: str = Query(..., description="Comma-separated generic secret names"),
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    now = int(time.time())
    email, role, iat, p = _get_actor(db, authorization)
    
    if not p:
        p = vault_repo.ensure_principal(db, email, role="user", status="active", now=now)

    if p.status != "active":
        vault_repo.audit(db, ts=now, email=email, action="list_secrets", status="forbidden_principal_disabled")
        raise HTTPException(status_code=403, detail="Principal disabled.")

    if iat < int(p.token_valid_after or 0):
        vault_repo.audit(db, ts=now, email=email, action="list_secrets", status="forbidden_token_revoked")
        raise HTTPException(status_code=401, detail="Token revoked. Re-authenticate.")

    requested = [n.strip() for n in names.split(",") if n.strip()]
    result: dict[str, str] = {}

    for gs in requested:
        real_name = vault_repo.resolve_real_secret_name(db, email=email, generic_secret=gs)
        if not real_name:
            continue
        s = vault_repo.get_secret(db, real_name)
        if not s or not s.enabled:
            continue
        result[gs] = decrypt(s.ciphertext)

    vault_repo.audit(db, ts=now, email=email, action="list_secrets", status="ok", details=f"count={len(result)}")
    return {"secrets": result}


@router.post("/real-secrets")
def admin_upsert_real_secret(
    payload: RealSecretUpsert,
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    now = int(time.time())
    actor_email, actor_role, _iat, p = _get_actor(db, authorization)

    # 1) só quem pode "set mapping" pode também "gerir secrets" (writer/admin/service)
    if not can_set_mapping(actor_role):
        raise HTTPException(status_code=403, detail="Not allowed to manage secrets.")

    # 2) valida assign_level do payload
    assign_level = (payload.assign_level or "reader").strip().lower()
    if assign_level not in ("reader", "writer", "admin"):
        raise HTTPException(status_code=400, detail="assign_level must be one of: reader, writer, admin.")

    # 3) writer não pode criar/editar secrets com assign_level=admin
    if not can_assign_secret(actor_role, assign_level):
        raise HTTPException(status_code=403, detail="Not allowed to set this assign_level.")

    # 4) se já existe secret, writer também não pode "subir o nível" dele para admin
    existing = vault_repo.get_secret(db, payload.real_secret_name)
    if existing is not None:
        existing_level = getattr(existing, "assign_level", "admin")  # fallback caso campo não exista ainda
        # writer não pode editar secret que é "admin-only"
        if actor_role == "writer" and existing_level == "admin":
            raise HTTPException(status_code=403, detail="Writer cannot edit admin-level secrets.")

        # writer não pode promover assign_level para admin
        if actor_role == "writer" and assign_level == "admin":
            raise HTTPException(status_code=403, detail="Writer cannot promote secrets to admin level.")

    # 5) grava (precisa que vault_repo.upsert_real_secret suporte assign_level)
    vault_repo.upsert_real_secret(
        db,
        real_secret_name=payload.real_secret_name,
        ciphertext=encrypt(payload.value),
        updated_at=now,
        enabled=payload.enabled,
        assign_level=assign_level,  # <-- novo
    )

    vault_repo.audit(
        db,
        ts=now,
        email=actor_email,
        action="upsert_real_secret",
        status="ok",
        real_secret_name=payload.real_secret_name,
        details=f"enabled={payload.enabled} assign_level={assign_level} actor_role={actor_role}",
    )
    return {"status": "ok", "real_secret_name": payload.real_secret_name}



@router.get("/admin/audit")
def admin_audit(
    limit: int = 200,
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    actor_email, role, _iat, p = _get_actor(db, authorization)
    _require_admin(actor_email, role)

    rows = vault_repo.list_audit(db, limit=limit)
    return {
        "rows": [
            {
                "ts": r.ts,
                "email": r.email,
                "action": r.action,
                "status": r.status,
                "generic_secret": r.generic_secret,
                "real_secret_name": r.real_secret_name,
                "details": r.details,
            }
            for r in rows
        ]
    }


@router.get("/principals")
def admin_list_principals(
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    actor_email, actor_role, _iat, actor_p = _get_actor(db, authorization)
    rows = db.execute(select(Principal).order_by(Principal.email.asc())).scalars().all()

    def rank(r: str) -> int:
        return ROLE_RANK.get((r or "user").lower(), 0)

    actor_rank = rank(actor_role)

    return {
        "principals": [
            {
                "email": p.email,
                "role": p.role,
                "status": p.status,
                "created_at": p.created_at,
                "updated_at": p.updated_at,
                "token_valid_after": p.token_valid_after,
            }
            for p in rows
        ]
    }


@router.post("/principals")
def admin_upsert_principal(
    payload: PrincipalUpsert,
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    now = int(time.time())
    actor_email, actor_role, _iat, p = _get_actor(db, authorization)

    # reader/user não pode gerir usuários
    if actor_role not in ("admin", "service", "writer"):
        raise HTTPException(status_code=403, detail="Not allowed to manage users.")

    email = payload.email.strip().lower()
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="Invalid email.")

    new_role = payload.role.strip().lower()
    new_status = payload.status.strip().lower()

    if new_status not in ("active", "disabled"):
        raise HTTPException(status_code=400, detail="status must be active|disabled")

    if new_role not in ("user", "reader", "writer", "admin", "service"):
        raise HTTPException(status_code=400, detail="role must be user|reader|writer|admin|service")
    
    # não permitir atribuir role acima do ator
    if ROLE_RANK.get(new_role, 0) > ROLE_RANK.get(actor_role, 0):
        raise HTTPException(status_code=403, detail="Cannot assign a role higher than your own.")

    target = db.get(Principal, email)

    # se existe: não pode modificar alguém do mesmo nível ou superior
    if target:
        if not can_modify_principal(actor_role, target.role):
            raise HTTPException(status_code=403, detail="Cannot modify users with higher role.")

        target.role = new_role
        target.status = new_status
        target.updated_at = now
        p = target
    else:
        # criar novo usuário: ok, desde que role <= ator (já validado)
        p = Principal(
            email=email,
            role=new_role,
            status=new_status,
            created_at=now,
            updated_at=now,
            token_valid_after=0,
        )
        db.add(p)

    db.commit()

    vault_repo.audit(
        db,
        ts=now,
        email=actor_email,
        action="upsert_principal",
        status="ok",
        details=f"target={email} role={p.role} status={p.status}",
    )

    return {"status": "ok", "email": email}


@router.get("/real-secrets")
def admin_list_real_secrets(
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    actor_email, actor_role, _iat, _p = _get_actor(db, authorization)

    rows = db.execute(select(Secret).order_by(Secret.real_secret_name.asc())).scalars().all()

    filtered = [s for s in rows if can_assign_secret(actor_role, (s.assign_level or "admin"))]

    return {
        "secrets": [
            {
                "real_secret_name": s.real_secret_name,
                "enabled": s.enabled,
                "updated_at": s.updated_at,
                "assign_level": s.assign_level,
            }
            for s in filtered
        ]
    }


@router.get("/mappings")
def admin_list_mappings(
    target_email: str,
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    actor_email, actor_role, _iat, _p = _get_actor(db, authorization)

    email = target_email.strip().lower()
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="Invalid target_email.")

    target = vault_repo.get_principal(db, email)
    if not target:
        raise HTTPException(status_code=404, detail="Target principal not found.")

    # só pode acessar mappings de users com role <= a sua
    if ROLE_RANK.get(target.role, 0) > ROLE_RANK.get(actor_role, 0):
        raise HTTPException(status_code=403, detail="Not allowed to view mappings for this user.")

    rows = db.execute(
        select(SecretMapping)
        .where(SecretMapping.email == email)
        .order_by(SecretMapping.generic_secret.asc())
    ).scalars().all()

    return {
        "mappings": [
            {
                "email": m.email,
                "generic_secret": m.generic_secret,
                "real_secret_name": m.real_secret_name,
                "active": m.active,
                "updated_at": m.updated_at,
            }
            for m in rows
        ]
    }


@router.post("/mappings/bulk")
def admin_set_mappings_bulk(
    payload: MappingsBulk,
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    now = int(time.time())
    actor_email, actor_role, _iat, _p = _get_actor(db, authorization)

    if not can_set_mapping(actor_role):
        raise HTTPException(status_code=403, detail="Not allowed to change mappings.")

    if not payload.items:
        return {"status": "ok", "saved": 0}

    target_email = payload.items[0].email.strip().lower()
    if not target_email or "@" not in target_email:
        raise HTTPException(status_code=400, detail="Invalid email in items[0].")

    for it in payload.items:
        if it.email.strip().lower() != target_email:
            raise HTTPException(status_code=400, detail="Bulk must target a single email.")

    target = vault_repo.get_principal(db, target_email)
    if not target:
        # cria como user ativo
        target = vault_repo.ensure_principal(db, target_email, role="user", status="active", now=now)

    # não pode mexer em target de role superior
    if ROLE_RANK.get(target.role, 0) > ROLE_RANK.get(actor_role, 0):
        raise HTTPException(status_code=403, detail="Not allowed to modify mappings for this user.")

    saved = 0
    try:
        for it in payload.items:
            gs = it.generic_secret.strip()
            rs = it.real_secret_name.strip()
            if not gs or not rs:
                continue

            real = db.get(Secret, rs)
            if not real:
                raise HTTPException(status_code=404, detail=f"Real secret not found: {rs}")

            # não pode atribuir secret acima do nível do ator
            if not can_assign_secret(actor_role, real.assign_level):
                raise HTTPException(status_code=403, detail=f"Not allowed to assign secret: {rs}")

            key = {"email": target_email, "generic_secret": gs}
            m = db.get(SecretMapping, key)
            if m:
                m.real_secret_name = rs
                m.active = bool(it.active)
                m.updated_at = now
            else:
                db.add(
                    SecretMapping(
                        email=target_email,
                        generic_secret=gs,
                        real_secret_name=rs,
                        active=bool(it.active),
                        updated_at=now,
                    )
                )
            saved += 1

        db.commit()
    except HTTPException:
        db.rollback()
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Bulk save failed: {e}")

    vault_repo.audit(
        db,
        ts=now,
        email=actor_email,
        action="set_mappings_bulk",
        status="ok",
        details=f"target={target_email} saved={saved} actor_role={actor_role}",
    )

    return {"status": "ok", "saved": saved, "target_email": target_email}