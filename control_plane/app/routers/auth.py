from __future__ import annotations
import time
from fastapi import APIRouter, HTTPException, Header
from fastapi.responses import RedirectResponse, JSONResponse
from app.core.settings import settings
from app.services.ticket_store import create_ticket, get_ticket, set_ticket_jwt
from app.services.google_oauth import google_auth_url, exchange_code_for_access_token, fetch_user_email
from app.services.jwt_service import sign_user_token, sign_service_token, public_key_pem

router = APIRouter()

@router.post("/ticket")
def ticket():
    if not settings.GOOGLE_CLIENT_ID or not settings.GOOGLE_CLIENT_SECRET:
        raise HTTPException(status_code=500, detail="Google OAuth not configured.")
    tid = create_ticket()
    return {"ticket_id": tid, "login_url": f"{settings.BASE_URL}/auth/login?ticket_id={tid}"}

@router.get("/login")
def login(ticket_id: str):
    if not get_ticket(ticket_id):
        raise HTTPException(status_code=404, detail="Invalid ticket.")
    return RedirectResponse(google_auth_url(state=ticket_id))

@router.get("/callback")
def callback(code: str, state: str):
    ticket_id = state
    if not get_ticket(ticket_id):
        raise HTTPException(status_code=404, detail="Invalid ticket (state).")
    try:
        access_token = exchange_code_for_access_token(code)
        email = fetch_user_email(access_token)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Google login failed: {e}")

    if settings.ALLOWED_DOMAIN and not email.lower().endswith("@" + settings.ALLOWED_DOMAIN):
        raise HTTPException(status_code=403, detail="Email domain not allowed.")

    token = sign_user_token(email)
    set_ticket_jwt(ticket_id, token)
    return JSONResponse({
        "status": "ok",
        "message": "Login concluído. Você pode fechar esta aba e voltar ao terminal.",
        "email": email,
    })

@router.get("/poll")
def poll(ticket_id: str):
    t = get_ticket(ticket_id)
    if not t:
        raise HTTPException(status_code=404, detail="Invalid ticket.")
    if t["jwt"] is None:
        return {"status": "pending"}
    return {"status": "ready", "token": t["jwt"]}

@router.get("/public-key")
def public_key():
    return {"alg": settings.JWT_ALG, "kid": settings.JWT_KID, "public_key_pem": public_key_pem()}

@router.post("/service-token")
def service_token(x_auth_service_secret: str | None = Header(default=None)):
    if not settings.SERVICE_SECRET:
        raise HTTPException(status_code=500, detail="Service secret not configured.")
    if x_auth_service_secret != settings.SERVICE_SECRET:
        raise HTTPException(status_code=401, detail="Unauthorized.")
    token = sign_service_token(subject="prefect-server", role="admin")
    return {"token": token}
