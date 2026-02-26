from __future__ import annotations
import time
import jwt
from app.core.settings import settings

def _read(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()

def sign_user_token(email: str) -> str:
    iat = int(time.time())
    exp = iat + settings.JWT_EXP_MINUTES * 60
    payload = {
        "email": email,
        "iat": iat,
        "exp": exp,
        "aud": settings.JWT_AUD,
        "iss": settings.JWT_ISS,
        "role": "user",
        "sub": email,
    }
    headers = {"kid": settings.JWT_KID}
    private_key = _read(settings.JWT_PRIVATE_KEY_PATH)
    return jwt.encode(payload, private_key, algorithm=settings.JWT_ALG, headers=headers)

def sign_service_token(subject: str = "prefect-server", role: str = "admin") -> str:
    iat = int(time.time())
    exp = iat + 3600  # 1h (ajuste se quiser)
    payload = {
        "email": "prefect@system",
        "iat": iat,
        "exp": exp,
        "aud": settings.JWT_AUD,
        "iss": settings.JWT_ISS,
        "role": role,
        "sub": subject,
    }
    headers = {"kid": settings.JWT_KID}
    private_key = _read(settings.JWT_PRIVATE_KEY_PATH)
    return jwt.encode(payload, private_key, algorithm=settings.JWT_ALG, headers=headers)

def public_key_pem() -> str:
    return _read(settings.JWT_PUBLIC_KEY_PATH)

def verify_token(token: str) -> dict:
    pub = public_key_pem()
    return jwt.decode(
        token,
        pub,
        algorithms=[settings.JWT_ALG],
        audience=settings.JWT_AUD,
        issuer=settings.JWT_ISS,
        options={"require": ["exp", "iat", "email"]},
    )
