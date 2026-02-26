from __future__ import annotations
from cryptography.fernet import Fernet
from app.core.settings import settings

def _fernet() -> Fernet:
    if not settings.VAULT_MASTER_KEY:
        raise RuntimeError("KEYVAULT_MASTER_KEY not configured.")
    return Fernet(settings.VAULT_MASTER_KEY.encode("utf-8"))

def encrypt(value: str) -> str:
    return _fernet().encrypt(value.encode("utf-8")).decode("utf-8")

def decrypt(ciphertext: str) -> str:
    return _fernet().decrypt(ciphertext.encode("utf-8")).decode("utf-8")
