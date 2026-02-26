# Componente: Streamlit (Dashboard)

## Visão Geral

O **Streamlit Dashboard** é a interface gráfica web para gerenciamento do **Key Vault** do FastFlow. Ele permite que administradores e usuários autorizados realizem operações de forma visual — como gerenciar usuários (principals), criar/editar segredos criptografados, configurar mapeamentos genéricos → reais e consultar o log de auditoria — tudo sem necessidade de interagir diretamente com a API REST.

O dashboard se comunica **exclusivamente** com o control-plane FastAPI via HTTP; ele **não tem acesso direto** ao banco de dados.

---

## Como foi Implementado

### Aplicação

O dashboard é uma única página Streamlit (`streamlit_app.py`) que implementa:
- **Autenticação** via Google OAuth (fluxo de tickets com polling)
- **Interface com abas** para cada funcionalidade (Minha Conta, Usuários, Secrets, Mappings, Auditoria)
- **Comunicação HTTP** com o control-plane via `requests`

### Dockerfile

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY streamlit_app.py ./streamlit_app.py
ENV PYTHONUNBUFFERED=1
EXPOSE 8501
CMD ["streamlit", "run", "streamlit_app.py", "--server.address=0.0.0.0", "--server.port=8501"]
```

### Dependências Python (`requirements.txt`)

| Pacote | Versão | Propósito |
|---|---|---|
| `streamlit` | 1.37.1 | Framework de dashboard/UI |
| `requests` | 2.32.5 | Comunicação HTTP com o FastAPI |

### Trecho do `docker-compose.yml`

```yaml
fastflow-dashboard:
  build: ./control_plane/dashboard
  container_name: fastflow-dashboard
  restart: unless-stopped
  depends_on:
    fastflow-control-plane:
      condition: service_started
  environment:
    CONTROL_PLANE_URL: "http://prefect-server.br:8008"
  ports:
    - "8501:8501"
```

---

## Arquivos nos quais se baseia

| Arquivo | Função |
|---|---|
| `control_plane/dashboard/streamlit_app.py` | Código completo do dashboard (única página) |
| `control_plane/dashboard/Dockerfile` | Build da imagem Docker |
| `control_plane/dashboard/requirements.txt` | Dependências Python |
| `docker-compose.yml` | Definição do serviço, variáveis de ambiente e dependências |

---

## Principais Funções

### Helpers HTTP

| Função | Descrição |
|---|---|
| `api_headers()` | Monta o header `Authorization: Bearer <jwt>` a partir do token armazenado na sessão Streamlit. |
| `cp_get(path, **kwargs)` | Wrapper para `requests.get` no control-plane (base URL + path, timeout 20s). |
| `cp_post(path, **kwargs)` | Wrapper para `requests.post` no control-plane (base URL + path, timeout 20s). |

### Autenticação

| Função | Descrição |
|---|---|
| `login_flow()` | Executa o fluxo completo de login: cria ticket, abre browser, faz polling até receber JWT ou timeout. |
| `invalidate_session()` | Limpa JWT e dados do usuário do `st.session_state` (logout local). |
| `load_me()` | Consulta `GET /vault/me` para obter email, role e status do usuário autenticado. |

### UI

| Função | Descrição |
|---|---|
| `show_forbidden_hint()` | Exibe mensagem amigável quando o usuário não tem permissão para acessar um endpoint. |

---

## Interface (Abas)

O dashboard organiza suas funcionalidades em **abas** (tabs), com visibilidade baseada no papel do usuário:

| Aba | Visível para | Funcionalidade |
|---|---|---|
| **Minha Conta** | Todos | Exibe informações do usuário autenticado. |
| **Usuários** | Todos* | Lista principals e formulário para criar/atualizar (role, status). |
| **Secrets** | Todos* | Lista segredos reais e formulário para criar/atualizar (valor criptografado, assign_level). |
| **Acessos (Mappings)** | Todos* | Editor tabular de mapeamentos genérico → real por usuário (bulk save). |
| **Auditoria** | Admin/Service | Tabela com log de auditoria completo. |

> \* A visibilidade no frontend é para todos, mas as operações de escrita são controladas pelo RBAC do backend.

### Fluxo de Mappings (Editor Tabular)

1. Usuário digita o email do principal-alvo.
2. Dashboard carrega mapeamentos existentes via `GET /vault/mappings?target_email=...`.
3. Exibe editor tabular com `st.data_editor` (linhas adicionáveis/removíveis).
4. Ao salvar, envia `POST /vault/mappings/bulk` com todos os itens.

---

## Gerenciamento de Sessão

O Streamlit gerencia o estado de autenticação via `st.session_state`:

| Chave | Tipo | Descrição |
|---|---|---|
| `jwt` | `str \| None` | Token JWT obtido no login |
| `me` | `dict \| None` | Dados do usuário (`email`, `role`, `status`) |

- Se `jwt` é `None`, o dashboard exibe apenas o botão "Login com Google".
- Se `jwt` está presente mas expirado, o `load_me()` detecta HTTP 401 e invalida a sessão.

---

## Principais Variáveis de Ambiente

| Variável | Descrição |
|---|---|
| `CONTROL_PLANE_URL` | URL base do control-plane FastAPI (ex: `http://prefect-server.br:8008`). Todos os endpoints são acessados a partir desta URL. |
| `AUTH_TIMEOUT_MINUTES` | Tempo máximo de espera pelo login via polling (padrão: `2` minutos). |
| `AUTH_POLL_INTERVAL_SECONDS` | Intervalo entre cada requisição de polling (padrão: `2` segundos). |

---

## Relacionamento com outros componentes

| Componente | Tipo de relação |
|---|---|
| **FastAPI (Control Plane)** | **Dependência direta** — o Streamlit é um cliente HTTP puro; toda operação passa pela API FastAPI (autenticação + vault). O container depende do `fastflow-control-plane` estar iniciado. |
| **Google OAuth** | **Consumidor** — o dashboard utiliza `POST /auth/ticket` e `GET /auth/poll` para autenticar o usuário via fluxo OAuth. |
| **Key Vault** | **Interface gráfica** — o dashboard é a principal interface de gerenciamento do Key Vault, permitindo CRUD de principals, secrets e mappings. |
| **PostgreSQL** | **Sem relação direta** — o dashboard não acessa o banco; toda persistência é feita indiretamente via chamadas à API. |
| **Alembic** | **Sem relação direta** — o dashboard não interage com migrations. |
| **Prefect Server** | **Sem relação direta** — não há comunicação entre o dashboard e o Prefect Server. |
