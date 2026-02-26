from __future__ import annotations
import time
from fastapi import APIRouter, HTTPException, Header
from fastapi.responses import RedirectResponse, JSONResponse
from app.core.settings import settings
from app.services.ticket_store import create_ticket, get_ticket, set_ticket_jwt
from app.services.google_oauth import google_auth_url, exchange_code_for_access_token, fetch_user_email
from app.services.jwt_service import sign_user_token, sign_service_token, public_key_pem

router = APIRouter()

@router.post("/ticket", summary="Criar ticket de autenticação", description="Cria um novo ticket para iniciar o fluxo de login via Google OAuth 2.0. Retorna o `ticket_id` e a URL de login.")
def ticket():
    """Cria um novo ticket de autenticação para o fluxo de login assíncrono.

    O cliente (CLI/dashboard) chama este endpoint para obter um ``ticket_id``
    e uma ``login_url``. A ``login_url`` deve ser aberta no navegador do
    usuário para iniciar o consent screen do Google. Após o login ser
    concluído, o cliente faz polling em ``/auth/poll`` até o JWT estar
    disponível.

    **Resposta de sucesso (200):**
    ```json
    {
      "ticket_id": "<token_url_safe>",
      "login_url": "https://<base_url>/auth/login?ticket_id=..."
    }
    ```

    **Erros:**
    - **500**: Google OAuth não configurado no servidor.
    """
    if not settings.GOOGLE_CLIENT_ID or not settings.GOOGLE_CLIENT_SECRET:
        raise HTTPException(status_code=500, detail="Google OAuth not configured.")
    tid = create_ticket()
    return {"ticket_id": tid, "login_url": f"{settings.BASE_URL}/auth/login?ticket_id={tid}"}

@router.get("/login", summary="Redirecionar para Google OAuth", description="Redireciona o navegador do usuário para o consent screen do Google, usando o ticket_id como state.")
def login(ticket_id: str):
    """Redireciona o usuário para a tela de login do Google.

    Valida o ``ticket_id`` recebido como query parameter e, se válido,
    retorna um ``RedirectResponse`` (HTTP 307) para a URL de autorização
    do Google OAuth 2.0. O ``ticket_id`` é enviado como parâmetro
    ``state`` para ser recuperado no callback.

    **Parâmetros:**
    - **ticket_id** (query): Identificador do ticket obtido via ``POST /auth/ticket``.

    **Erros:**
    - **404**: Ticket inválido ou inexistente.
    """
    if not get_ticket(ticket_id):
        raise HTTPException(status_code=404, detail="Invalid ticket.")
    return RedirectResponse(google_auth_url(state=ticket_id))

@router.get("/callback", summary="Callback do Google OAuth", description="Endpoint de callback chamado pelo Google após autenticação. Troca o code por access_token, obtém o email e gera o JWT.")
def callback(code: str, state: str):
    """Processa o callback do Google OAuth 2.0.

    Chamado automaticamente pelo Google após o usuário conceder
    autorização. Realiza as seguintes etapas:

    1. Valida o ``state`` (ticket_id) recebido.
    2. Troca o ``code`` de autorização por um access token do Google.
    3. Consulta o endpoint ``userinfo`` para obter o e-mail do usuário.
    4. Verifica se o domínio do e-mail é permitido (se configurado).
    5. Gera um JWT assinado para o usuário.
    6. Armazena o JWT no ticket para ser consumido via polling.

    **Parâmetros:**
    - **code** (query): Código de autorização fornecido pelo Google.
    - **state** (query): ``ticket_id`` enviado na requisição original.

    **Resposta de sucesso (200):**
    ```json
    {
      "status": "ok",
      "message": "Login concluído. Você pode fechar esta aba e voltar ao terminal.",
      "email": "user@example.com"
    }
    ```

    **Erros:**
    - **404**: Ticket inválido.
    - **403**: Domínio de e-mail não permitido.
    - **500**: Falha na comunicação com o Google.
    """
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

@router.get("/poll", summary="Consultar status do ticket", description="Verifica se o login associado ao ticket já foi concluído. Retorna 'pending' ou 'ready' com o token JWT.")
def poll(ticket_id: str):
    """Consulta o status de um ticket de autenticação (polling).

    O cliente utiliza este endpoint repetidamente (a cada poucos segundos)
    para verificar se o fluxo de login OAuth foi concluído. Quando o
    status mudar para ``ready``, o JWT estará disponível no campo
    ``token``.

    **Parâmetros:**
    - **ticket_id** (query): Identificador do ticket a ser consultado.

    **Resposta – login pendente:**
    ```json
    {"status": "pending"}
    ```

    **Resposta – login concluído:**
    ```json
    {"status": "ready", "token": "<jwt>"}
    ```

    **Erros:**
    - **404**: Ticket inválido ou inexistente.
    """
    t = get_ticket(ticket_id)
    if not t:
        raise HTTPException(status_code=404, detail="Invalid ticket.")
    if t["jwt"] is None:
        return {"status": "pending"}
    return {"status": "ready", "token": t["jwt"]}

@router.get("/public-key", summary="Obter chave pública JWT", description="Retorna a chave pública RSA em formato PEM, o algoritmo e o Key ID usados para verificar tokens JWT.")
def public_key():
    """Expor a chave pública utilizada para verificar tokens JWT.

    Retorna o algoritmo de assinatura, o Key ID (``kid``) e o conteúdo
    PEM da chave pública RSA. Qualquer serviço que precise validar
    tokens emitidos pelo control-plane pode consumir este endpoint.

    **Resposta de sucesso (200):**
    ```json
    {
      "alg": "RS256",
      "kid": "fastflow-auth-1",
      "public_key_pem": "-----BEGIN PUBLIC KEY-----\n..."
    }
    ```
    """
    return {"alg": settings.JWT_ALG, "kid": settings.JWT_KID, "public_key_pem": public_key_pem()}

@router.post("/service-token", summary="Gerar service token", description="Emite um JWT de serviço (machine-to-machine) mediante apresentação do secret compartilhado via header.")
def service_token(x_auth_service_secret: str | None = Header(default=None)):
    """Gera um token JWT para autenticação machine-to-machine.

    Destinado a serviços internos (ex: Prefect Server) que precisam
    se autenticar na API sem intervenção humana. O chamador deve
    fornecer o secret compartilhado no header ``X-Auth-Service-Secret``.

    **Headers obrigatórios:**
    - ``X-Auth-Service-Secret``: Segredo compartilhado configurado em
      ``AUTH_SERVICE_SECRET``.

    **Resposta de sucesso (200):**
    ```json
    {"token": "<jwt>"}
    ```

    **Erros:**
    - **500**: Service secret não configurado no servidor.
    - **401**: Secret fornecido não corresponde ao esperado.
    """
    if not settings.SERVICE_SECRET:
        raise HTTPException(status_code=500, detail="Service secret not configured.")
    if x_auth_service_secret != settings.SERVICE_SECRET:
        raise HTTPException(status_code=401, detail="Unauthorized.")
    token = sign_service_token(subject="prefect-server", role="admin")
    return {"token": token}
