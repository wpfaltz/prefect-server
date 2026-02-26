# Componente: FastAPI (Control Plane)

## Visão Geral

O **FastAPI** é o framework web que hospeda a **API central do FastFlow Control Plane**. Ele serve como contêiner para dois grandes módulos — **Autenticação (Google OAuth)** e **Key Vault** — e expõe todos os endpoints REST da plataforma em uma única aplicação, incluindo documentação interativa auto-gerada (Swagger UI / ReDoc).

Este é o componente que **une** todos os serviços do backend: recebe requisições HTTP, valida tokens JWT, consulta o banco via SQLAlchemy, aplica regras de RBAC e retorna respostas JSON padronizadas.

---

## Como foi Implementado

### Aplicação Principal (`app/main.py`)

A instância do FastAPI é criada com título e descrição detalhada, e dois routers são acoplados:

```python
app = FastAPI(
    title="FastFlow Control Plane",
    description="API central do FastFlow Control Plane..."
)

app.include_router(auth.router, prefix="/auth", tags=["auth"])
app.include_router(vault.router, prefix="/vault", tags=["vault"])
```

### Dockerfile

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY alembic.ini .
COPY alembic ./alembic
COPY app ./app
ENV PYTHONUNBUFFERED=1
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8008"]
```

### Comando de startup (docker-compose)

```yaml
command: >
  sh -c "alembic upgrade head &&
         uvicorn app.main:app --host 0.0.0.0 --port 8008"
```

O Alembic roda primeiro para garantir que o schema do banco está atualizado, e em seguida o Uvicorn inicia o servidor ASGI.

### Dependências Python (`requirements.txt`)

| Pacote | Versão | Propósito |
|---|---|---|
| `fastapi` | 0.115.0 | Framework web (rotas, validação, OpenAPI) |
| `uvicorn[standard]` | 0.30.6 | Servidor ASGI (HTTP) |
| `pyjwt` | 2.9.0 | Geração e verificação de tokens JWT |
| `requests` | 2.32.5 | Comunicação HTTP com API do Google |
| `cryptography` | 46.0.5 | Criptografia Fernet + geração de chaves RSA |
| `pydantic` | 2.8.2 | Validação de dados (schemas de request/response) |
| `SQLAlchemy` | 2.0.46 | ORM para acesso ao PostgreSQL |
| `alembic` | 1.13.2 | Migrations de banco de dados |
| `psycopg[binary]` | 3.3.2 | Driver PostgreSQL síncrono |

---

## Arquivos nos quais se baseia

| Arquivo | Função |
|---|---|
| `app/main.py` | Ponto de entrada: cria a instância FastAPI, registra routers e define startup + health check |
| `app/routers/auth.py` | Router com 6 endpoints de autenticação (`/auth/*`) |
| `app/routers/vault.py` | Router com 10 endpoints do Key Vault (`/vault/*`) |
| `app/core/settings.py` | Classe `Settings` (dataclass) com todas as variáveis de ambiente |
| `app/db/session.py` | Engine e sessionmaker SQLAlchemy (singleton) |
| `app/db/deps.py` | `get_db()` — dependency injection de sessão do banco |
| `app/db/models.py` | 4 modelos ORM (Principal, Secret, SecretMapping, AuditLog) |
| `app/services/*.py` | Lógica de negócio (OAuth, JWT, criptografia, RBAC, repositório) |
| `Dockerfile` | Build da imagem Docker do backend |
| `requirements.txt` | Dependências Python |
| `alembic.ini` + `alembic/` | Configuração e migrations do Alembic |

---

## Estrutura Completa do Backend

```
control_plane/backend/
├── Dockerfile
├── requirements.txt
├── alembic.ini
├── alembic/
│   ├── env.py
│   ├── script.py.mako
│   └── versions/
│       ├── 0001_init_vault.py
│       └── 0002_secrets_assign_level.py
├── app/
│   ├── __init__.py
│   ├── main.py                    ← Ponto de entrada
│   ├── core/
│   │   └── settings.py            ← Configurações centralizadas
│   ├── db/
│   │   ├── deps.py                ← Dependency injection
│   │   ├── models.py              ← Modelos ORM
│   │   └── session.py             ← Engine + sessionmaker
│   ├── routers/
│   │   ├── auth.py                ← Endpoints /auth/*
│   │   └── vault.py               ← Endpoints /vault/*
│   └── services/
│       ├── google_oauth.py        ← Comunicação com Google API
│       ├── jwt_service.py         ← Geração/verificação JWT
│       ├── rbac.py                ← Hierarquia de papéis
│       ├── ticket_store.py        ← Tickets em memória
│       ├── vault_crypto.py        ← Criptografia Fernet
│       └── vault_repo.py          ← CRUD no banco
└── keys/
    └── generate_keys.py           ← Geração de chaves RSA
```

---

## Principais Funções

### `app/main.py`

| Função | Descrição |
|---|---|
| `_startup()` | Evento de startup — valida conexão com o banco via `SELECT 1`. |
| `health()` | `GET /health` — Health check simples (`{"ok": true}`). |

### Endpoints registrados

O FastAPI expõe **17 endpoints** no total:

| Grupo | Endpoints |
|---|---|
| Raiz | `GET /health` |
| Auth (6) | `POST /auth/ticket`, `GET /auth/login`, `GET /auth/callback`, `GET /auth/poll`, `GET /auth/public-key`, `POST /auth/service-token` |
| Vault (10) | `GET /vault/me`, `GET /vault/secrets/{generic}`, `GET /vault/secrets`, `POST /vault/real-secrets`, `GET /vault/real-secrets`, `GET /vault/principals`, `POST /vault/principals`, `GET /vault/mappings`, `POST /vault/mappings/bulk`, `GET /vault/admin/audit` |

### Documentação Swagger

Todos os endpoints possuem `summary`, `description` e docstrings formatadas em Markdown, visíveis na interface Swagger UI disponível em:

```
http://<host>:8008/docs
```

---

## Principais Variáveis de Ambiente

| Variável | Descrição |
|---|---|
| `CONTROL_PLANE_BASE_URL` | URL público do control-plane, usado para redirect URI do Google e construção de links. |
| `CONTROL_PLANE_DB_URL` | URL SQLAlchemy de conexão com o PostgreSQL. |
| `AUTH_JWT_*` | Configurações JWT (algoritmo, chaves, KID, audience, issuer, expiração). |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | Credenciais OAuth do Google. |
| `GOOGLE_REDIRECT_URI` | URI de callback do Google OAuth. |
| `AUTH_ALLOWED_DOMAIN` | Restrição de domínio de email. |
| `AUTH_SERVICE_SECRET` | Segredo para emissão de service tokens. |
| `KEYVAULT_MASTER_KEY` | Chave Fernet para criptografia de segredos. |
| `KEYVAULT_ADMIN_EMAILS` | Emails com privilégio de admin bootstrap. |

---

## Relacionamento com outros componentes

| Componente | Tipo de relação |
|---|---|
| **Google OAuth** | **Módulo interno** — as rotas `/auth/*` são registradas como sub-router. O FastAPI serve como host. |
| **Key Vault** | **Módulo interno** — as rotas `/vault/*` são registradas como sub-router. O FastAPI serve como host. |
| **PostgreSQL** | **Dependência direta** — o FastAPI se conecta ao PostgreSQL via SQLAlchemy para todas as operações de dados. |
| **Alembic** | **Pré-processamento** — o Alembic roda antes do FastAPI no mesmo container, garantindo que o schema está atualizado. |
| **Streamlit** | **Servidor** — o dashboard Streamlit é um cliente HTTP que consume todos os endpoints do FastAPI. |
| **Prefect Server** | **Coexistência** — ambos rodam na mesma stack Docker mas em containers separados. O FastAPI pode emitir service tokens usados por automações que interagem com o Prefect. |
