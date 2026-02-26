from __future__ import annotations
from cryptography.fernet import Fernet
from app.core.settings import settings

def _fernet() -> Fernet:
    """Retorna uma instância do Fernet configurada com a chave mestra.

    Utiliza ``settings.VAULT_MASTER_KEY`` como chave de criptografia
    simétrica Fernet. Deve ser chamada apenas internamente pelos
    métodos ``encrypt`` e ``decrypt``.

    Returns:
        Fernet: Instância Fernet pronta para criptografar/descriptografar.

    Raises:
        RuntimeError: Se ``KEYVAULT_MASTER_KEY`` não estiver configurada.
    """
    if not settings.VAULT_MASTER_KEY:
        raise RuntimeError("KEYVAULT_MASTER_KEY not configured.")
    return Fernet(settings.VAULT_MASTER_KEY.encode("utf-8"))

def encrypt(value: str) -> str:
    """Criptografa um valor de texto plano usando Fernet.

    Converte o valor para bytes UTF-8, criptografa com a chave mestra
    Fernet e retorna o ciphertext como string UTF-8 (base64-encoded).

    Args:
        value: Texto plano a ser criptografado (ex: valor de um segredo).

    Returns:
        str: Ciphertext Fernet codificado em base64.
    """
    return _fernet().encrypt(value.encode("utf-8")).decode("utf-8")

def decrypt(ciphertext: str) -> str:
    """Descriptografa um ciphertext Fernet de volta a texto plano.

    Recebe o ciphertext (string base64 Fernet), descriptografa usando a
    chave mestra e retorna o valor original em texto plano.

    Args:
        ciphertext: Texto criptografado em formato Fernet (base64).

    Returns:
        str: Valor original em texto plano.

    Raises:
        cryptography.fernet.InvalidToken: Se o ciphertext for inválido
            ou a chave estiver incorreta.
    """
    return _fernet().decrypt(ciphertext.encode("utf-8")).decode("utf-8")
