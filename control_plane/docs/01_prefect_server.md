# Componente: Prefect Server

## Visão Geral

O **Prefect Server** é o componente central de orquestração de workflows (flows) da stack. Ele fornece a **API REST** utilizada pelos agentes/workers para registrar, agendar e reportar execuções de flows, além de uma **interface web (UI)** para visualização e gerenciamento de runs, deployments, work pools e logs.

Nesta stack ele é utilizado como a **camada de orquestração pura**: não contém lógica de autenticação própria — essa responsabilidade é delegada ao control-plane FastAPI (autenticação via Google OAuth + JWT).

---

## Como foi Implementado

O Prefect Server **não é compilado localmente**; utiliza-se a imagem oficial do Docker Hub:

```
prefecthq/prefect:3.6.15-python3.12
```

A configuração é feita inteiramente via variáveis de ambiente no `docker-compose.yml`.

### Trecho relevante do `docker-compose.yml`

```yaml
prefect-server:
  image: prefecthq/prefect:3.6.15-python3.12
  container_name: prefect-server
  restart: unless-stopped
  depends_on:
    postgres:
      condition: service_healthy
  command: ["prefect", "server", "start", "--host", "0.0.0.0", "--port", "4200"]
  environment:
    - PREFECT_UI_API_URL=/api
    - PREFECT_API_DATABASE_CONNECTION_URL=postgresql+asyncpg://prefect:prefect@postgres:5432/prefect
  ports:
    - "4200:4200"
```

### Destaques da configuração

| Aspecto | Detalhe |
|---|---|
| **Imagem** | `prefecthq/prefect:3.6.15-python3.12` |
| **Comando** | `prefect server start --host 0.0.0.0 --port 4200` |
| **Porta exposta** | `4200` (API + UI) |
| **Dependência** | Espera o `postgres` estar saudável antes de iniciar |
| **Persistência** | Delegada ao PostgreSQL (via `PREFECT_API_DATABASE_CONNECTION_URL`) |

---

## Arquivos nos quais se baseia

| Arquivo | Função |
|---|---|
| `docker-compose.yml` | Definição do serviço, variáveis de ambiente e dependências |

Não há arquivos de código-fonte locais para este componente — toda a lógica vem da imagem oficial.

---

## Principais Variáveis de Ambiente

| Variável | Descrição |
|---|---|
| `PREFECT_UI_API_URL` | Caminho relativo da API utilizado pela UI web (`/api`). |
| `PREFECT_API_DATABASE_CONNECTION_URL` | URL de conexão assíncrona (asyncpg) com o PostgreSQL onde o Prefect armazena metadados de flows, runs, deployments, etc. |

---

## Principais Funcionalidades

- **Orquestração de Flows**: Agendamento, disparo e monitoramento de execuções.
- **UI Web**: Interface gráfica para visualização de runs, logs, deployments e work pools.
- **API REST**: Endpoints para interação programática com o servidor (registro de flows, consulta de status, etc.).
- **Persistência**: Todos os metadados são armazenados no PostgreSQL compartilhado.

---

## Relacionamento com outros componentes

| Componente | Tipo de relação |
|---|---|
| **PostgreSQL** | **Depende diretamente** — utiliza o banco `prefect` para armazenar todos os metadados de orquestração. |
| **FastAPI (Control Plane)** | **Independente em runtime** — ambos rodam em containers separados; o control-plane emite service tokens (`/auth/service-token`) que podem ser utilizados por automações que interagem com o Prefect Server. |
| **Streamlit** | **Não possui relação direta** — o dashboard Streamlit se comunica apenas com o control-plane FastAPI. |
| **Workers/Agentes** | **Consumidores** — workers remotos se conectam à API do Prefect Server para pegar e reportar execuções. |
