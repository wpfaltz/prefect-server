# Componente: PostgreSQL

## Visão Geral

O **PostgreSQL** é o banco de dados relacional que serve como camada de persistência compartilhada da stack. Ele armazena tanto os **metadados do Prefect Server** (flows, runs, deployments, work pools, logs) quanto os **dados do control-plane** (principals, segredos criptografados, mapeamentos e audit logs do Key Vault).

Uma única instância PostgreSQL 16 atende ambos os serviços, utilizando bancos separados ou schemas dentro do mesmo banco, dependendo da configuração de cada consumidor.

---

## Como foi Implementado

Utiliza-se a **imagem oficial do Docker Hub** sem customizações:

```
postgres:16
```

A configuração completa é feita via variáveis de ambiente no `docker-compose.yml`, e os dados são persistidos em um **Docker volume nomeado** (`prefect_pgdata`).

### Trecho relevante do `docker-compose.yml`

```yaml
postgres:
  image: postgres:16
  container_name: prefect-postgres
  restart: unless-stopped
  environment:
    POSTGRES_USER: prefect
    POSTGRES_PASSWORD: prefect
    POSTGRES_DB: prefect
  volumes:
    - prefect_pgdata:/var/lib/postgresql/data
  healthcheck:
    test: ["CMD-SHELL", "pg_isready -U prefect -d prefect"]
    interval: 5s
    timeout: 5s
    retries: 20

volumes:
  prefect_pgdata:
```

### Destaques da configuração

| Aspecto | Detalhe |
|---|---|
| **Imagem** | `postgres:16` |
| **Container** | `prefect-postgres` |
| **Volume** | `prefect_pgdata` (dados persistentes entre restarts) |
| **Healthcheck** | `pg_isready` a cada 5s (até 20 tentativas) |
| **Restart policy** | `unless-stopped` |

---

## Arquivos nos quais se baseia

| Arquivo | Função |
|---|---|
| `docker-compose.yml` | Definição do serviço, credenciais, volume e healthcheck |
| `alembic/versions/0001_init_vault.py` | Migration que cria as tabelas do Key Vault neste banco |
| `alembic/versions/0002_secrets_assign_level.py` | Migration que adiciona a coluna `assign_level` na tabela `secrets` |
| `app/db/session.py` | Código Python que cria a engine e sessionmaker SQLAlchemy apontando para este banco |
| `app/db/models.py` | Modelos ORM (Principal, Secret, SecretMapping, AuditLog) mapeados para as tabelas |

---

## Definição do Schema (Tabelas)

### Criadas pelo Alembic (migration `0001_init_vault`)

| Tabela | Descrição |
|---|---|
| `principals` | Usuários do sistema (email, role, status, timestamps, token_valid_after) |
| `secrets` | Segredos reais criptografados (real_secret_name, ciphertext, enabled, assign_level) |
| `secret_mapping` | Mapeamento (email + generic_secret) → real_secret_name |
| `audit_log` | Log de auditoria (ts, email, action, status, details) |
| `v_secret_resolution` | **VIEW** que resolve (email, generic_secret) → real_secret_name para principals e mappings ativos |

### Índices

| Índice | Tabela | Coluna(s) |
|---|---|---|
| `ix_secret_mapping_email` | `secret_mapping` | `email` |
| `ix_secret_mapping_generic` | `secret_mapping` | `generic_secret` |
| `ix_audit_log_ts` | `audit_log` | `ts` |
| `ix_audit_log_email` | `audit_log` | `email` |

---

## Principais Variáveis de Ambiente

### Do serviço PostgreSQL

| Variável | Descrição |
|---|---|
| `POSTGRES_USER` | Usuário do banco (padrão na stack: `prefect`). |
| `POSTGRES_PASSWORD` | Senha do usuário (padrão na stack: `prefect`). |
| `POSTGRES_DB` | Nome do banco criado automaticamente no startup (padrão: `prefect`). |

### Dos serviços consumidores

| Variável | Serviço | Descrição |
|---|---|---|
| `PREFECT_API_DATABASE_CONNECTION_URL` | Prefect Server | URL asyncpg de conexão (`postgresql+asyncpg://prefect:prefect@postgres:5432/prefect`). |
| `CONTROL_PLANE_DB_URL` | FastAPI Control Plane | URL SQLAlchemy síncrona de conexão com o banco para o Key Vault. |

---

## Principais Funcionalidades

- **Persistência de metadados do Prefect**: Flows, flow runs, task runs, deployments, work pools, logs.
- **Persistência do Key Vault**: Principals, segredos criptografados, mapeamentos e audit logs.
- **Healthcheck nativo**: Permite que outros serviços (`depends_on: condition: service_healthy`) esperem até o banco estar pronto antes de iniciarem.
- **Dados persistentes via volume**: O volume `prefect_pgdata` garante que os dados sobrevivem a recreações do container.

---

## Relacionamento com outros componentes

| Componente | Tipo de relação |
|---|---|
| **Prefect Server** | **Consumidor direto** — utiliza o banco para armazenar todos os metadados de orquestração via driver asyncpg. |
| **FastAPI (Control Plane)** | **Consumidor direto** — utiliza o banco para armazenar as tabelas do Key Vault via SQLAlchemy síncrono. |
| **Alembic** | **Gerenciador de schema** — o Alembic roda as migrations para criar/alterar tabelas do Key Vault neste banco. |
| **Streamlit** | **Sem relação direta** — o dashboard não acessa o banco; toda a comunicação passa pela API FastAPI. |
| **Google OAuth** | **Sem relação direta** — o módulo OAuth não persiste dados no banco (tickets ficam em memória). |
