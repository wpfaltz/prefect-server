from __future__ import annotations
import time
import jwt
from app.core.settings import settings

def _read(path: str) -> str:
    """Lê o conteúdo completo de um arquivo de texto.

    Utilitário interno para carregar chaves PEM (privada/pública)
    do sistema de arquivos.

    Args:
        path: Caminho absoluto do arquivo a ser lido.

    Returns:
        str: Conteúdo do arquivo como string UTF-8.
    """
    with open(path, "r", encoding="utf-8") as f:
        return f.read()

def sign_user_token(email: str) -> str:
    """Gera e assina um JWT para um usuário autenticado.

    Cria um token JWT contendo o e-mail do usuário, timestamps de
    emissão (``iat``) e expiração (``exp``), audience, issuer e role
    fixa ``user``. O token é assinado com a chave privada RSA
    configurada e inclui o ``kid`` no header.

    Args:
        email: Endereço de e-mail do usuário autenticado.

    Returns:
        str: Token JWT assinado (formato compact serialization).
    """
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
    """Gera e assina um JWT para autenticação machine-to-machine (service token).

    Cria um token JWT com ``sub`` e ``role`` configuráveis, e-mail fixo
    ``prefect@system`` e expiração de 1 hora. Destinado a serviços
    internos (ex: Prefect Server) que precisam se autenticar na API
    sem intervenção humana.

    Args:
        subject: Identificador do serviço (padrão: ``prefect-server``).
        role: Papel atribuído ao service token (padrão: ``admin``).

    Returns:
        str: Token JWT assinado (formato compact serialization).
    """
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
    """Retorna o conteúdo da chave pública JWT em formato PEM.

    Lê o arquivo PEM da chave pública configurada em
    ``settings.JWT_PUBLIC_KEY_PATH`` e retorna seu conteúdo como
    string. Utilizado para expor a chave pública via endpoint
    (``/auth/public-key``) e para verificação local de tokens.

    Returns:
        str: Chave pública RSA em formato PEM.
    """
    return _read(settings.JWT_PUBLIC_KEY_PATH)

def verify_token(token: str) -> dict:
    """Verifica e decodifica um token JWT.

    Valida a assinatura do token usando a chave pública RSA, verifica
    o algoritmo, audience (``settings.JWT_AUD``), issuer
    (``settings.JWT_ISS``) e a presença dos claims obrigatórios
    (``exp``, ``iat``, ``email``).

    Args:
        token: Token JWT em formato compact serialization.

    Returns:
        dict: Payload decodificado do token.

    Raises:
        jwt.ExpiredSignatureError: Se o token estiver expirado.
        jwt.InvalidAudienceError: Se o audience não corresponder.
        jwt.InvalidIssuerError: Se o issuer não corresponder.
        jwt.DecodeError: Se a assinatura for inválida.
        jwt.MissingRequiredClaimError: Se faltar claim obrigatório.
    """
    pub = public_key_pem()
    return jwt.decode(
        token,
        pub,
        algorithms=[settings.JWT_ALG],
        audience=settings.JWT_AUD,
        issuer=settings.JWT_ISS,
        options={"require": ["exp", "iat", "email"]},
    )
