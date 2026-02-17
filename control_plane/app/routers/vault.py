from __future__ import annotations
import time
from fastapi import APIRouter, HTTPException, Header, Depends
from sqlalchemy.orm import Session
from pydantic import BaseModel
from app.db.deps import get_db
from app.core.settings import settings
from app.services.jwt_service import verify_token
from app.services.vault_crypto import encrypt, decrypt
from app.services import vault_repo

router = APIRouter()

def _bearer_email_and_role(authorization: str | None) -> tuple[str, str]:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token.")
    token = authorization.split(" ", 1)[1].strip()
    try:
        payload = verify_token(token)
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}")
    return payload["email"].lower(), payload.get("role", "user")

def _require_admin(email: str, role: str):
    if role == "admin":
        return
    if email not in settings.VAULT_ADMIN_EMAILS:
        raise HTTPException(status_code=403, detail="Admin permission required.")

class SecretUpsert(BaseModel):
    secret_id: str
    value: str
    deliverable: bool = True

class PolicyChange(BaseModel):
    email: str
    secret_id: str

@router.post("/admin/secrets")
def admin_upsert(payload: SecretUpsert, authorization: str | None = Header(default=None)):
    email, role = _bearer_email_and_role(authorization)
    _require_admin(email, role)

    upsert_secret(payload.secret_id, encrypt(payload.value), int(time.time()), deliverable=payload.deliverable)
    audit(int(time.time()), email, "upsert_secret", payload.secret_id, "ok")
    return {"status": "ok", "secret_id": payload.secret_id}

@router.post("/admin/policies/grant")
def admin_grant(p: PolicyChange, authorization: str | None = Header(default=None)):
    email, role = _bearer_email_and_role(authorization)
    _require_admin(email, role)

    grant(p.email, p.secret_id)
    audit(int(time.time()), email, "grant", p.secret_id, "ok")
    return {"status": "ok"}

@router.post("/admin/policies/revoke")
def admin_revoke(p: PolicyChange, authorization: str | None = Header(default=None)):
    email, role = _bearer_email_and_role(authorization)
    _require_admin(email, role)

    revoke(p.email, p.secret_id)
    audit(int(time.time()), email, "revoke", p.secret_id, "ok")
    return {"status": "ok"}

@router.get("/admin/audit")
def admin_audit(limit: int = 200, authorization: str | None = Header(default=None)):
    email, role = _bearer_email_and_role(authorization)
    _require_admin(email, role)
    return {"rows": list_audit(limit=limit)}

@router.get("/secrets/{secret_id}")
def read_secret(secret_id: str, authorization: str | None = Header(default=None)):
    email, role = _bearer_email_and_role(authorization)

    row = get_secret_row(secret_id)
    if not row:
        audit(int(time.time()), email, "read_secret", secret_id, "not_found")
        raise HTTPException(status_code=404, detail="Secret not found.")

    ciphertext, updated_at, deliverable = row

    # regra: secrets "não deliverable" só para admin/service
    if not deliverable:
        if role != "admin" and email not in settings.VAULT_ADMIN_EMAILS:
            audit(int(time.time()), email, "read_secret", secret_id, "forbidden_not_deliverable")
            raise HTTPException(status_code=403, detail="Secret not deliverable.")

    # regra: policy por email (para deliverable=True)
    if deliverable:
        if role != "admin" and not is_allowed(email, secret_id):
            audit(int(time.time()), email, "read_secret", secret_id, "forbidden_policy")
            raise HTTPException(status_code=403, detail="Not allowed.")

    audit(int(time.time()), email, "read_secret", secret_id, "ok")
    return {"secret_id": secret_id, "value": decrypt(ciphertext), "updated_at": updated_at}
