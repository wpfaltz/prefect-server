from __future__ import annotations
import os
from dataclasses import dataclass, field

@dataclass(frozen=True)
class Settings:
    # Base URL público do control-plane (importante pro redirect do Google)
    BASE_URL: str = os.getenv("CONTROL_PLANE_BASE_URL", "http://localhost:8008").rstrip("/")

    # JWT (Auth)
    JWT_ALG: str = os.getenv("AUTH_JWT_ALG", "RS256")
    JWT_PRIVATE_KEY_PATH: str = os.getenv("AUTH_JWT_PRIVATE_KEY_PATH", "/run/secrets/jwt_private.pem")
    JWT_PUBLIC_KEY_PATH: str = os.getenv("AUTH_JWT_PUBLIC_KEY_PATH", "/run/secrets/jwt_public.pem")
    JWT_KID: str = os.getenv("AUTH_JWT_KID", "fastflow-auth-1")
    JWT_EXP_MINUTES: int = int(os.getenv("AUTH_JWT_EXP_MINUTES", "30"))
    JWT_AUD: str = os.getenv("AUTH_JWT_AUD", "fastflow")
    JWT_ISS: str = os.getenv("AUTH_JWT_ISS", "fastflow-auth")

    # Google OAuth (Auth)
    GOOGLE_CLIENT_ID: str = os.getenv("GOOGLE_CLIENT_ID", "")
    GOOGLE_CLIENT_SECRET: str = os.getenv("GOOGLE_CLIENT_SECRET", "")
    GOOGLE_REDIRECT_URI: str = os.getenv("GOOGLE_REDIRECT_URI", f"{BASE_URL}/auth/callback")

    # Audience restrictions
    ALLOWED_DOMAIN: str = os.getenv("AUTH_ALLOWED_DOMAIN", "").strip().lower()

    # Service token (Auth)
    SERVICE_SECRET: str = os.getenv("AUTH_SERVICE_SECRET", "")

    # Vault crypto
    VAULT_MASTER_KEY: str = os.getenv("KEYVAULT_MASTER_KEY", "")  # Fernet key
    VAULT_DB_PATH: str = os.getenv("KEYVAULT_DB_PATH", "/data/keyvault.sqlite")

    # Admin emails (vault admin endpoints)
    VAULT_ADMIN_EMAILS: set[str] = field(default_factory=set)

    DB_URL: str = os.getenv("CONTROL_PLANE_DB_URL", "")

settings = Settings(
    VAULT_ADMIN_EMAILS={
        e.strip().lower() 
        for e in os.getenv("KEYVAULT_ADMIN_EMAILS", "").split(",") 
        if e.strip()
    },
)
