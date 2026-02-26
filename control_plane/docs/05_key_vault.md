# Componente: Key Vault

## Visão Geral

O **Key Vault** é o sistema de gerenciamento seguro de segredos (credenciais, senhas, API keys, tokens) do FastFlow. Ele permite que **flows automatizados** acessem segredos sem que estes sejam hardcoded no código, utilizando um sistema de **nomes genéricos** que são mapeados para **segredos reais** de forma individual por usuário.

Características principais:
- **Criptografia Fernet** (AES-128-CBC): todos os valores de segredos são armazenados criptografados no banco.
- **RBAC (Role-Based Access Control)**: controle granular de quem pode ler, criar ou atribuir segredos.
- **Mapeamento genérico → real**: permite que diferentes usuários usem o mesmo nome de segredo no código (`db_password`) mas acessem credenciais reais diferentes (`oracle_pwd_prod` vs `oracle_pwd_dev`).
- **Auditoria completa**: toda operação (leitura, escrita, listagem, atribuição) é registrada no audit log.
- **Revogação de tokens**: via campo `token_valid_after` no principal.

---

## Como foi Implementado

O Key Vault é implementado como um conjunto de **rotas FastAPI** (`/vault/*`), **serviços Python** (criptografia, repositório, RBAC) e **modelos ORM** (SQLAlchemy), todos servidos pelo mesmo container `fastflow-control-plane`.

### Arquitetura de Camadas

```
Rotas (/vault/*)          →  RBAC + Validação
    ↓
Serviços (vault_repo,     →  Lógica de negócio
  vault_crypto, rbac)
    ↓
Modelos ORM (models.py)   →  Mapeamento para tabelas
    ↓
PostgreSQL                 →  Persistência
```

---

## Arquivos nos quais se baseia

| Arquivo | Função |
|---|---|
| `app/routers/vault.py` | Rotas FastAPI para todas as operações do Key Vault (11 endpoints) |
| `app/services/vault_repo.py` | Repositório de acesso a dados (CRUD de principals, secrets, mappings, audit) |
| `app/services/vault_crypto.py` | Criptografia/descriptografia Fernet dos valores de segredos |
| `app/services/rbac.py` | Hierarquia de papéis e funções de autorização |
| `app/services/jwt_service.py` | Verificação de tokens JWT (compartilhado com o módulo OAuth) |
| `app/db/models.py` | Modelos ORM: `Principal`, `Secret`, `SecretMapping`, `AuditLog` |
| `app/db/deps.py` | Dependency injection da sessão SQLAlchemy |
| `app/db/session.py` | Engine e sessionmaker do SQLAlchemy |
| `app/core/settings.py` | Configurações (master key, admin emails, etc.) |

---

## Principais Funções

### Rotas (`app/routers/vault.py`)

| Endpoint | Método | Descrição |
|---|---|---|
| `/vault/me` | GET | Retorna identidade (email, role, status) do usuário autenticado. |
| `/vault/secrets/{generic_secret}` | GET | Resolve mapeamento do usuário e retorna valor descriptografado. |
| `/vault/secrets?names=...` | GET | Leitura bulk de múltiplos segredos. |
| `/vault/real-secrets` | POST | Cria/atualiza segredo real (criptografa o valor). |
| `/vault/real-secrets` | GET | Lista segredos reais visíveis ao ator (filtrado por assign_level). |
| `/vault/principals` | GET | Lista todos os principals. |
| `/vault/principals` | POST | Cria/atualiza um principal (email, role, status). |
| `/vault/mappings?target_email=...` | GET | Lista mapeamentos de um usuário específico. |
| `/vault/mappings/bulk` | POST | Salva múltiplos mapeamentos de uma só vez. |
| `/vault/admin/audit` | GET | Lista log de auditoria (somente admin). |

### Serviço de Criptografia (`app/services/vault_crypto.py`)

| Função | Descrição |
|---|---|
| `encrypt(value)` | Criptografa valor com Fernet (AES). Retorna ciphertext base64. |
| `decrypt(ciphertext)` | Descriptografa ciphertext Fernet. Retorna texto plano. |

### Repositório (`app/services/vault_repo.py`)

| Função | Descrição |
|---|---|
| `ensure_principal(db, email, ...)` | Garante que um principal exista (cria se necessário). |
| `get_principal(db, email)` | Busca principal por email. |
| `upsert_real_secret(db, ...)` | Cria ou atualiza um segredo real. |
| `set_mapping(db, ...)` | Cria ou atualiza mapeamento genérico → real. |
| `resolve_real_secret_name(db, email, generic_secret)` | Resolve via VIEW `v_secret_resolution`. |
| `get_secret(db, real_secret_name)` | Busca segredo real por nome. |
| `audit(db, ...)` | Registra entrada no audit log. |
| `list_audit(db, limit)` | Lista entradas mais recentes do audit log. |

### RBAC (`app/services/rbac.py`)

| Função / Constante | Descrição |
|---|---|
| `ROLE_RANK` | Hierarquia: user(0) < reader(1) < writer(2) < admin(3) = service(3). |
| `can_set_mapping(actor_role)` | Verifica se pode alterar mapeamentos (writer/admin/service). |
| `can_assign_secret(actor_role, assign_level)` | Verifica se pode atribuir segredo com dado nível. |
| `can_modify_principal(actor_role, target_role)` | Verifica se pode modificar um principal de dado nível. |

---

## Schema do Banco (Modelos ORM)

### `Principal`
| Coluna | Tipo | Descrição |
|---|---|---|
| `email` (PK) | String(320) | Email do usuário |
| `role` | String(32) | Papel: user, reader, writer, admin, service |
| `status` | String(32) | active ou disabled |
| `created_at` | BigInteger | Timestamp de criação |
| `updated_at` | BigInteger | Timestamp de última atualização |
| `token_valid_after` | BigInteger | Tokens com iat < este valor são revogados |

### `Secret`
| Coluna | Tipo | Descrição |
|---|---|---|
| `real_secret_name` (PK) | String(255) | Nome único do segredo |
| `ciphertext` | Text | Valor criptografado (Fernet) |
| `updated_at` | BigInteger | Timestamp de atualização |
| `enabled` | Boolean | Se está habilitado para leitura |
| `assign_level` | String(16) | Nível mínimo para atribuição (reader/writer/admin) |

### `SecretMapping`
| Coluna | Tipo | Descrição |
|---|---|---|
| `email` (PK, FK) | String(320) | Email do principal |
| `generic_secret` (PK) | String(255) | Nome genérico usado no código |
| `real_secret_name` (FK) | String(255) | Nome real do segredo |
| `updated_at` | BigInteger | Timestamp de atualização |
| `active` | Boolean | Se o mapeamento está ativo |

### `AuditLog`
| Coluna | Tipo | Descrição |
|---|---|---|
| `id` (PK) | BigInteger | Auto-incrementado |
| `ts` | BigInteger | Timestamp do evento |
| `email` | String(320) | Email do ator |
| `action` | String(64) | Tipo da ação |
| `status` | String(32) | Resultado (ok, forbidden, not_found, error) |
| `generic_secret` | String(255) | Nome genérico (opcional) |
| `real_secret_name` | String(255) | Nome real (opcional) |
| `details` | Text | Informações adicionais (opcional) |

---

## Principais Variáveis de Ambiente

| Variável | Descrição |
|---|---|
| `KEYVAULT_MASTER_KEY` | Chave mestra **Fernet** usada para criptografar e descriptografar todos os valores de segredos. Deve ser gerada com `Fernet.generate_key()`. |
| `KEYVAULT_ADMIN_EMAILS` | Lista de emails separados por vírgula que possuem privilégio de administrador bootstrap (garantem role `admin` no banco). |
| `CONTROL_PLANE_DB_URL` | URL de conexão SQLAlchemy com o PostgreSQL. |

---

## Relacionamento com outros componentes

| Componente | Tipo de relação |
|---|---|
| **FastAPI (Control Plane)** | **Hospedeiro** — as rotas `/vault/*` são registradas como sub-router no FastAPI principal. |
| **Google OAuth** | **Dependência** — o Key Vault depende do módulo OAuth para validar tokens JWT e identificar o ator autenticado em cada requisição. |
| **PostgreSQL** | **Persistência** — todas as tabelas (principals, secrets, secret_mapping, audit_log) e a VIEW `v_secret_resolution` residem no PostgreSQL. |
| **Alembic** | **Gerenciamento de schema** — as migrations do Alembic criam e evoluem o schema do banco utilizado pelo Key Vault. |
| **Streamlit** | **CLI/Dashboard** — o dashboard Streamlit consome todos os endpoints `/vault/*` para gerenciar principals, segredos e mapeamentos via interface gráfica. |
| **Prefect Server** | **Consumidor potencial** — flows executados pelo Prefect podem consumir `GET /vault/secrets/{generic_secret}` para obter credenciais em runtime, usando JWTs para autenticação. |
