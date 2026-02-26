# Componente: Google OAuth 2.0

## Visão Geral

O componente de **Google OAuth 2.0** é responsável por toda a autenticação de usuários humanos na plataforma. Implementa o fluxo **Authorization Code** do OAuth 2.0 com o Google como Identity Provider, permitindo que apenas usuários com conta Google (opcionalmente restrito a um domínio específico) possam obter um JWT válido para acessar os demais serviços do control-plane.

O diferencial desta implementação é o **fluxo baseado em tickets com polling**, que permite que clientes não-web (como CLIs e terminais) iniciem a autenticação sem precisar de um servidor de callback local.

---

## Como foi Implementado

A autenticação é implementada como um conjunto de **rotas FastAPI** (`/auth/*`) e **serviços Python** que encapsulam a comunicação com a API do Google, a geração/verificação de JWTs e o armazenamento temporário de tickets.

### Fluxo completo

```
1. Cliente → POST /auth/ticket
      ↓ retorna ticket_id + login_url
2. Usuário abre login_url no browser
      ↓
3. GET /auth/login?ticket_id=...  → Redirect para Google
      ↓
4. Usuário faz login no Google
      ↓
5. Google redireciona para GET /auth/callback?code=...&state=ticket_id
      ↓ troca code → access_token → email
      ↓ gera JWT e associa ao ticket
6. Cliente faz polling: GET /auth/poll?ticket_id=...
      ↓ retorna {status: "ready", token: "<jwt>"}
```

---

## Arquivos nos quais se baseia

| Arquivo | Função |
|---|---|
| `app/routers/auth.py` | Rotas FastAPI que expõem os endpoints do fluxo OAuth |
| `app/services/google_oauth.py` | Funções de comunicação com a API do Google (construção de URL de auth, troca de code por token, obtenção de email) |
| `app/services/jwt_service.py` | Geração e verificação de tokens JWT (RSA / RS256) |
| `app/services/ticket_store.py` | Armazenamento em memória dos tickets de autenticação |
| `app/core/settings.py` | Configurações centralizadas (client_id, client_secret, redirect_uri, etc.) |
| `keys/generate_keys.py` | Script para gerar o par de chaves RSA (privada/pública) utilizadas na assinatura dos JWTs |

---

## Principais Funções

### `app/routers/auth.py`

| Função | Descrição |
|---|---|
| `ticket()` | `POST /auth/ticket` — Cria um ticket e retorna `ticket_id` + `login_url`. |
| `login(ticket_id)` | `GET /auth/login` — Redireciona para o consent screen do Google. |
| `callback(code, state)` | `GET /auth/callback` — Processa o retorno do Google: troca code → token → email, gera JWT, armazena no ticket. |
| `poll(ticket_id)` | `GET /auth/poll` — Retorna "pending" ou "ready" + JWT. |
| `public_key()` | `GET /auth/public-key` — Expõe a chave pública RSA para verificação de tokens. |
| `service_token(...)` | `POST /auth/service-token` — Gera JWT machine-to-machine mediante secret compartilhado. |

### `app/services/google_oauth.py`

| Função | Descrição |
|---|---|
| `google_auth_url(state)` | Constrói a URL de autorização do Google com client_id, redirect_uri e scopes. |
| `exchange_code_for_access_token(code)` | Troca o authorization code por um access token via POST ao Google. |
| `fetch_user_email(access_token)` | Consulta o endpoint userinfo do Google para obter o email do usuário. |

### `app/services/jwt_service.py`

| Função | Descrição |
|---|---|
| `sign_user_token(email)` | Gera um JWT RS256 para um usuário autenticado (exp: configurável, padrão 30min). |
| `sign_service_token(subject, role)` | Gera um JWT para autenticação machine-to-machine (exp: 1h). |
| `public_key_pem()` | Retorna a chave pública PEM. |
| `verify_token(token)` | Valida assinatura, audience, issuer e claims obrigatórios do JWT. |

### `app/services/ticket_store.py`

| Função | Descrição |
|---|---|
| `create_ticket()` | Cria um ticket com ID criptograficamente seguro (URL-safe). |
| `set_ticket_jwt(ticket_id, token)` | Associa o JWT ao ticket após login bem-sucedido. |
| `get_ticket(ticket_id)` | Busca um ticket pelo ID. |

---

## Principais Variáveis de Ambiente

| Variável | Descrição |
|---|---|
| `GOOGLE_CLIENT_ID` | Client ID da aplicação registrada no Google Cloud Console. |
| `GOOGLE_CLIENT_SECRET` | Client Secret da aplicação no Google Cloud Console. |
| `GOOGLE_REDIRECT_URI` | URI de redirecionamento pós-autenticação (ex: `http://host:8008/auth/callback`). |
| `AUTH_ALLOWED_DOMAIN` | Domínio de email permitido (ex: `empresa.com`). Se vazio, aceita qualquer domínio. |
| `AUTH_SERVICE_SECRET` | Segredo compartilhado para emissão de service tokens (machine-to-machine). |
| `AUTH_JWT_ALG` | Algoritmo JWT (padrão: `RS256`). |
| `AUTH_JWT_PRIVATE_KEY_PATH` | Caminho do arquivo PEM da chave privada (montado como secret no Docker). |
| `AUTH_JWT_PUBLIC_KEY_PATH` | Caminho do arquivo PEM da chave pública. |
| `AUTH_JWT_KID` | Key ID incluído no header do JWT (padrão: `fastflow-auth-1`). |
| `AUTH_JWT_EXP_MINUTES` | Tempo de expiração do JWT em minutos (padrão: `30`). |
| `AUTH_JWT_AUD` | Audience esperado nos tokens (padrão: `fastflow`). |
| `AUTH_JWT_ISS` | Issuer esperado nos tokens (padrão: `fastflow-auth`). |

---

## Relacionamento com outros componentes

| Componente | Tipo de relação |
|---|---|
| **FastAPI (Control Plane)** | **Hospedeiro** — todas as rotas `/auth/*` são registradas como sub-router do FastAPI principal. |
| **Key Vault** | **Consumidor** — o Key Vault valida JWTs emitidos pelo módulo OAuth para autorizar operações. O `verify_token()` é usado pelo vault para extrair identidade e papel do ator. |
| **Streamlit** | **Cliente** — o dashboard Streamlit consome `POST /auth/ticket` e `GET /auth/poll` para autenticar o usuário. |
| **PostgreSQL** | **Sem dependência direta** — os tickets são armazenados em memória (`TICKETS` dict); o banco é usado apenas indiretamente (ao consultar principals via vault). |
| **Prefect Server** | **Indireto** — service tokens podem ser usados por automações que interagem com o Prefect. |
