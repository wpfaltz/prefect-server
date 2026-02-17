from __future__ import annotations
from fastapi import FastAPI
from sqlalchemy import text
from app.routers import auth, vault
from app.db.session import engine

app = FastAPI(title="FastFlow Control Plane")

app.include_router(auth.router, prefix="/auth", tags=["auth"])
app.include_router(vault.router, prefix="/vault", tags=["vault"])

@app.on_event("startup")
def _startup() -> None:
    # Só valida conexão (migrations são responsabilidade do Alembic)
    with engine.connect() as conn:
        conn.execute(text("SELECT 1"))

@app.get("/health")
def health():
    return {"ok": True}

# from __future__ import annotations

# import os
# import time
# import secrets
# from typing import Optional, Dict, Any
# from urllib.parse import urlencode

# import jwt
# import requests
# from fastapi import FastAPI, HTTPException
# from fastapi.responses import RedirectResponse, JSONResponse

# app = FastAPI(title="FastFlow Auth Server")

# # ---- Config ----
# AUTH_JWT_ALG = os.getenv("AUTH_JWT_ALG", "RS256")
# AUTH_JWT_PRIVATE_KEY_PATH = os.getenv("AUTH_JWT_PRIVATE_KEY_PATH", "")
# AUTH_JWT_PUBLIC_KEY_PATH = os.getenv("AUTH_JWT_PUBLIC_KEY_PATH", "")
# AUTH_JWT_EXP_MINUTES = int(os.getenv("AUTH_JWT_EXP_MINUTES", "30"))
# AUTH_JWT_KID = os.getenv("AUTH_JWT_KID", "fastflow-auth-1")
# AUTH_SERVICE_SECRET = os.getenv("AUTH_SERVICE_SECRET", "")

# AUTH_ALLOWED_DOMAIN = os.getenv("AUTH_ALLOWED_DOMAIN", "").strip().lower()
# AUTH_BASE_URL = os.getenv("AUTH_BASE_URL", "http://localhost:8008").rstrip("/")

# GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
# GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
# GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", f"{AUTH_BASE_URL}/auth/callback")

# # ---- In-memory ticket store ----
# # ticket_id -> {"created_at": float, "jwt": Optional[str]}
# TICKETS: Dict[str, Dict[str, Any]] = {}


# def _now() -> float:
#     return time.time()

# def _read_file(path: str) -> str:
#     with open(path, "r", encoding="utf-8") as f:
#         return f.read()


# def _jwt_for_email(email: str) -> str:
#     iat = int(_now())
#     exp = iat + AUTH_JWT_EXP_MINUTES * 60

#     payload = {
#         "email": email,
#         "iat": iat,
#         "exp": exp,
#         "aud": "fastflow",
#         "iss": "fastflow-auth",
#     }

#     headers = {"kid": AUTH_JWT_KID}

#     private_key = _read_file(AUTH_JWT_PRIVATE_KEY_PATH)
#     return jwt.encode(payload, private_key, algorithm=AUTH_JWT_ALG, headers=headers)


# def _jwt_for_service(subject: str, role: str) -> str:
#     iat = int(_now())
#     exp = iat + 3600  # 1h por exemplo
#     payload = {
#         "sub": subject,
#         "role": role,
#         "email": "prefect@system",
#         "iat": iat,
#         "exp": exp,
#         "aud": "fastflow",
#         "iss": "fastflow-auth",
#     }
#     headers = {"kid": AUTH_JWT_KID}
#     private_key = _read_file(AUTH_JWT_PRIVATE_KEY_PATH)
#     return jwt.encode(payload, private_key, algorithm=AUTH_JWT_ALG, headers=headers)


# def _google_auth_url(state: str) -> str:
#     params = {
#         "client_id": GOOGLE_CLIENT_ID,
#         "redirect_uri": GOOGLE_REDIRECT_URI,
#         "response_type": "code",
#         "scope": "openid email",
#         "access_type": "online",
#         "prompt": "select_account",
#         "state": state,
#     }
#     return "https://accounts.google.com/o/oauth2/v2/auth?" + urlencode(params)


# def _exchange_code_for_token(code: str) -> str:
#     token_url = "https://oauth2.googleapis.com/token"
#     data = {
#         "client_id": GOOGLE_CLIENT_ID,
#         "client_secret": GOOGLE_CLIENT_SECRET,
#         "code": code,
#         "grant_type": "authorization_code",
#         "redirect_uri": GOOGLE_REDIRECT_URI,
#     }
#     r = requests.post(token_url, data=data, timeout=15)
#     r.raise_for_status()
#     return r.json()["access_token"]


# def _get_user_email(access_token: str) -> str:
#     r = requests.get(
#         "https://www.googleapis.com/oauth2/v3/userinfo",
#         headers={"Authorization": f"Bearer {access_token}"},
#         timeout=15,
#     )
#     r.raise_for_status()
#     email = r.json().get("email")
#     if not email or "@" not in email:
#         raise RuntimeError("Não foi possível obter email do Google.")
#     return email


# @app.get("/auth/login")
# def login(ticket_id: str):
#     if ticket_id not in TICKETS:
#         raise HTTPException(status_code=404, detail="Ticket inválido.")
#     # state carrega o ticket_id pra voltar no callback
#     return RedirectResponse(_google_auth_url(state=ticket_id))

# @app.get("/auth/public-key")
# def public_key():
#     pub = _read_file(AUTH_JWT_PUBLIC_KEY_PATH)
#     return JSONResponse({"alg": AUTH_JWT_ALG, "kid": AUTH_JWT_KID, "public_key_pem": pub})


# @app.get("/auth/callback")
# def callback(code: str, state: str):
#     ticket_id = state
#     if ticket_id not in TICKETS:
#         raise HTTPException(status_code=404, detail="Ticket inválido (state).")

#     try:
#         access_token = _exchange_code_for_token(code)
#         email = _get_user_email(access_token)
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=f"Falha no login Google: {e}")

#     # domínio permitido (opcional)
#     if AUTH_ALLOWED_DOMAIN:
#         if not email.lower().endswith("@" + AUTH_ALLOWED_DOMAIN):
#             raise HTTPException(status_code=403, detail="Domínio de email não permitido.")

#     # gera JWT e salva no ticket
#     token = _jwt_for_email(email)
#     TICKETS[ticket_id]["jwt"] = token

#     # Uma página simples pro usuário ver "ok"
#     return JSONResponse({
#         "status": "ok",
#         "message": "Login concluído. Você pode fechar esta aba e voltar ao terminal.",
#         "email": email,
#     })


# @app.get("/auth/poll")
# def poll(ticket_id: str):
#     t = TICKETS.get(ticket_id)
#     if not t:
#         raise HTTPException(status_code=404, detail="Ticket inválido.")
#     if t["jwt"] is None:
#         return {"status": "pending"}
#     return {"status": "ready", "token": t["jwt"]}


# @app.post("/auth/ticket")
# def create_ticket():
#     if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
#         raise HTTPException(status_code=500, detail="Google OAuth não configurado no servidor.")
#     ticket_id = secrets.token_urlsafe(24)
#     TICKETS[ticket_id] = {"created_at": _now(), "jwt": None}
#     return {"ticket_id": ticket_id, "login_url": f"{AUTH_BASE_URL}/auth/login?ticket_id={ticket_id}"}


# @app.post("/auth/service-token")
# def service_token(x_auth_service_secret: str | None = Header(default=None)):
#     if not AUTH_SERVICE_SECRET:
#         raise HTTPException(status_code=500, detail="Service secret not configured.")
#     if x_auth_service_secret != AUTH_SERVICE_SECRET:
#         raise HTTPException(status_code=401, detail="Unauthorized.")

#     # token com role admin/service
#     token = _jwt_for_service(subject="prefect-server", role="admin")
#     return {"token": token}