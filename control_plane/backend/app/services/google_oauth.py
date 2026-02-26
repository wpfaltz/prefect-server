from __future__ import annotations
from urllib.parse import urlencode
import requests
from app.core.settings import settings

def google_auth_url(state: str) -> str:
    """Constrói a URL de autorização do Google OAuth 2.0.

    Monta a URL completa para redirecionar o usuário ao consent screen
    do Google, incluindo ``client_id``, ``redirect_uri``, escopos
    (``openid email``) e o parâmetro ``state`` que carrega o ticket ID
    para correlação no callback.

    Args:
        state: Valor opaco (normalmente o ``ticket_id``) que será
            retornado pelo Google no parâmetro ``state`` do callback.

    Returns:
        str: URL completa de autorização do Google.
    """
    params = {
        "client_id": settings.GOOGLE_CLIENT_ID,
        "redirect_uri": settings.GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": "openid email",
        "access_type": "online",
        "prompt": "select_account",
        "state": state,
    }
    return "https://accounts.google.com/o/oauth2/v2/auth?" + urlencode(params)

def exchange_code_for_access_token(code: str) -> str:
    """Troca o authorization code do Google por um access token.

    Envia uma requisição POST ao endpoint de token do Google
    (``https://oauth2.googleapis.com/token``) com o ``code`` recebido
    no callback, juntamente com ``client_id``, ``client_secret`` e
    ``redirect_uri``.

    Args:
        code: Código de autorização retornado pelo Google no callback.

    Returns:
        str: Access token válido para consultar a API do Google.

    Raises:
        requests.HTTPError: Se a resposta do Google indicar erro HTTP.
    """
    r = requests.post(
        "https://oauth2.googleapis.com/token",
        data={
            "client_id": settings.GOOGLE_CLIENT_ID,
            "client_secret": settings.GOOGLE_CLIENT_SECRET,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": settings.GOOGLE_REDIRECT_URI,
        },
        timeout=15,
    )
    r.raise_for_status()
    return r.json()["access_token"]

def fetch_user_email(access_token: str) -> str:
    """Obtém o endereço de e-mail do usuário autenticado via Google.

    Consulta o endpoint ``userinfo`` do Google
    (``https://www.googleapis.com/oauth2/v3/userinfo``) utilizando o
    access token fornecido e extrai o campo ``email`` da resposta.

    Args:
        access_token: Token de acesso válido do Google OAuth.

    Returns:
        str: Endereço de e-mail do usuário.

    Raises:
        RuntimeError: Se o e-mail não puder ser obtido da resposta.
        requests.HTTPError: Se a requisição ao Google falhar.
    """
    r = requests.get(
        "https://www.googleapis.com/oauth2/v3/userinfo",
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=15,
    )
    r.raise_for_status()
    email = r.json().get("email")
    if not email or "@" not in email:
        raise RuntimeError("Could not fetch user email.")
    return email
