from __future__ import annotations
from fastapi import FastAPI
from sqlalchemy import text
from app.routers import auth, vault
from app.db.session import get_engine

app = FastAPI(
    title="FastFlow Control Plane",
    description=(
        "API central do FastFlow Control Plane, responsável por autenticação "
        "via Google OAuth 2.0 com emissão de JWTs e pelo gerenciamento seguro "
        "de segredos (Key Vault), incluindo controle de acesso baseado em papéis (RBAC), "
        "mapeamentos genéricos de segredos e auditoria completa de operações."
    ),
)

app.include_router(auth.router, prefix="/auth", tags=["auth"])
app.include_router(vault.router, prefix="/vault", tags=["vault"])

@app.on_event("startup")
def _startup() -> None:
    """Evento de inicialização da aplicação FastAPI.

    Executado automaticamente quando o servidor sobe. Obtém a engine do
    banco de dados e executa uma query trivial (``SELECT 1``) apenas para
    validar que a conexão está funcional. As migrations de schema ficam sob
    responsabilidade exclusiva do Alembic.

    Raises:
        RuntimeError: Se a variável ``CONTROL_PLANE_DB_URL`` não estiver
            configurada ou se a conexão com o banco falhar.
    """
    engine = get_engine()
    with engine.connect() as conn:
        conn.execute(text("SELECT 1"))

@app.get("/health")
def health():
    """Endpoint de health-check da aplicação.

    Retorna um JSON simples ``{"ok": true}`` indicando que o serviço está
    no ar e respondendo a requisições. Pode ser utilizado por load-balancers,
    orquestradores (Docker/Kubernetes) ou scripts de monitoramento.

    Returns:
        dict: ``{"ok": True}``
    """
    return {"ok": True}