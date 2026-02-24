import os
import time
import webbrowser
from typing import Any

import requests
import streamlit as st

CONTROL_PLANE_URL = os.getenv("CONTROL_PLANE_URL", "http://prefect-server.br:8008").rstrip("/")
AUTH_TIMEOUT_MINUTES = int(os.getenv("AUTH_TIMEOUT_MINUTES", "30"))
POLL_INTERVAL_SECONDS = float(os.getenv("AUTH_POLL_INTERVAL_SECONDS", "2"))

st.set_page_config(page_title="FastFlow Dashboard", layout="wide")
st.title("FastFlow Dashboard")


# -------------------------
# HTTP helpers
# -------------------------
def api_headers() -> dict[str, str]:
    token = st.session_state.get("jwt")
    return {"Authorization": f"Bearer {token}"} if token else {}


def cp_get(path: str, **kwargs: Any):
    return requests.get(f"{CONTROL_PLANE_URL}{path}", timeout=20, **kwargs)


def cp_post(path: str, **kwargs: Any):
    return requests.post(f"{CONTROL_PLANE_URL}{path}", timeout=20, **kwargs)


def invalidate_session():
    st.session_state["jwt"] = None
    st.session_state["me"] = None


def load_me():
    r = cp_get("/vault/me", headers=api_headers())
    if r.status_code == 401:
        invalidate_session()
        return None
    if r.status_code != 200:
        return None
    return r.json()


# -------------------------
# Auth flow: ticket + poll
# -------------------------
def login_flow() -> bool:
    r = cp_post("/auth/ticket")
    if r.status_code != 200:
        st.error(f"Falha ao criar ticket: {r.status_code} {r.text}")
        return False

    data = r.json()
    ticket_id = data["ticket_id"]
    login_url = data["login_url"]

    st.info("Abrindo janela de login do Google. Se não abrir, clique no link abaixo.")
    st.markdown(f"[Abrir login]({login_url})")

    try:
        webbrowser.open(login_url)
    except Exception:
        pass

    with st.spinner("Aguardando autenticação..."):
        deadline = time.time() + (AUTH_TIMEOUT_MINUTES*60)
        while time.time() < deadline:
            p = cp_get("/auth/poll", params={"ticket_id": ticket_id})
            if p.status_code != 200:
                st.error(f"Erro no poll: {p.status_code} {p.text}")
                return False
            j = p.json()
            if j.get("status") == "ready":
                st.session_state["jwt"] = j["token"]
                return True
            time.sleep(POLL_INTERVAL_SECONDS)

    st.error("Timeout aguardando autenticação.")
    return False


# -------------------------
# Session init
# -------------------------
if "jwt" not in st.session_state:
    st.session_state["jwt"] = None
if "me" not in st.session_state:
    st.session_state["me"] = None

col1, col2 = st.columns([1, 2])

with col1:
    if st.session_state["jwt"]:
        if st.button("Logout"):
            invalidate_session()
            st.rerun()
    else:
        if st.button("Login com Google"):
            ok = login_flow()
            if ok:
                st.session_state["me"] = load_me()
                st.success("Logado com sucesso.")
                st.rerun()

with col2:
    if st.session_state["jwt"]:
        if st.session_state["me"] is None:
            st.session_state["me"] = load_me()
        me = st.session_state["me"]
        if me:
            st.write(
                f"**Usuário:** {me['email']}  \n"
                f"**Role:** {me['role']}  \n"
            )
        else:
            st.warning("Não consegui carregar /vault/me. Token expirado ou endpoints indisponíveis.")

if not st.session_state["jwt"]:
    st.stop()

me = st.session_state["me"] or {}
role = (me.get("role") or "user").lower()
is_admin = role in ("admin", "service")

# -------------------------
# Tabs
# -------------------------
tabs = ["Minha Conta"]
if is_admin:
    tabs += ["Usuários", "Secrets", "Acessos (Mappings)", "Auditoria"]

chosen = st.tabs(tabs)


# ---- Minha Conta
with chosen[0]:
    st.subheader("Minha Conta")
    st.write("Você está autenticado e pode usar o Key Vault conforme suas permissões.")


# ---- Admin tabs
if is_admin:
    # -------------------------
    # Usuários (Principals)
    # -------------------------
    with chosen[1]:
        st.subheader("Usuários (Principals)")

        r = cp_get("/vault/admin/principals", headers=api_headers())
        if r.status_code != 200:
            st.error(f"Erro ao listar usuários: {r.status_code} {r.text}")
        else:
            principals = r.json().get("principals", [])
            st.dataframe(principals, use_container_width=True)

        st.markdown("### Criar/Atualizar usuário")
        with st.form("upsert_principal"):
            email = st.text_input("Email")
            role_in = st.selectbox("Role", ["user", "reader", "writer", "admin", "service"])
            status_in = st.selectbox("Status", ["active", "disabled"])
            submitted = st.form_submit_button("Salvar")
            if submitted:
                rr = cp_post(
                    "/vault/admin/principals",
                    headers=api_headers(),
                    json={"email": email, "role": role_in, "status": status_in},
                )
                if rr.status_code == 200:
                    st.success("Salvo.")
                    st.rerun()
                else:
                    st.error(f"Falha ao salvar: {rr.status_code} {rr.text}")

    # -------------------------
    # Secrets (reais)
    # -------------------------
    with chosen[2]:
        st.subheader("Secrets Reais")

        r = cp_get("/vault/admin/real-secrets", headers=api_headers())
        if r.status_code != 200:
            st.error(f"Erro ao listar secrets: {r.status_code} {r.text}")
        else:
            st.dataframe(r.json().get("secrets", []), use_container_width=True)

        st.markdown("### Criar/Atualizar secret real")
        with st.form("upsert_real_secret"):
            real_name = st.text_input("real_secret_name (ex: oracle_pwd_writer)")
            value = st.text_input("valor (será criptografado)", type="password")
            enabled = st.checkbox("enabled", value=True)
            assign_level = st.selectbox("assign_level", ["reader", "writer", "admin"])
            submitted = st.form_submit_button("Salvar")
            if submitted:
                rr = cp_post(
                    "/vault/admin/real-secrets",
                    headers=api_headers(),
                    json={
                        "real_secret_name": real_name,
                        "value": value,
                        "enabled": enabled,
                        "assign_level": assign_level,
                    },
                )
                if rr.status_code == 200:
                    st.success("Salvo.")
                    st.rerun()
                else:
                    st.error(f"Falha ao salvar: {rr.status_code} {rr.text}")

    # -------------------------
    # Mappings (Bulk save)
    # -------------------------
    with chosen[3]:
        st.subheader("Acessos (generic_secret → real_secret por usuário)")

        target_email = st.text_input("Email do usuário para editar mappings", "")
        if target_email:
            rr = cp_get(
                "/vault/admin/mappings",
                headers=api_headers(),
                params={"target_email": target_email},
            )
            if rr.status_code != 200:
                st.error(f"Erro ao buscar mappings: {rr.status_code} {rr.text}")
            else:
                mappings = rr.json().get("mappings", [])

                default_row = {
                    "email": target_email.lower().strip(),
                    "generic_secret": "",
                    "real_secret_name": "",
                    "active": True,
                }

                edited = st.data_editor(
                    mappings if mappings else [default_row],
                    use_container_width=True,
                    num_rows="dynamic",
                    key="mappings_editor",
                )

                if st.button("Salvar alterações de mappings"):
                    # bulk endpoint
                    payload = {
                        "items": [
                            {
                                "email": target_email,
                                "generic_secret": (row.get("generic_secret") or "").strip(),
                                "real_secret_name": (row.get("real_secret_name") or "").strip(),
                                "active": bool(row.get("active", True)),
                            }
                            for row in edited
                            if (row.get("generic_secret") or "").strip()
                            and (row.get("real_secret_name") or "").strip()
                        ]
                    }

                    resp = cp_post(
                        "/vault/admin/mappings/bulk",
                        headers=api_headers(),
                        json=payload,
                    )

                    if resp.status_code == 200:
                        saved = resp.json().get("saved", 0)
                        st.success(f"Salvos {saved} mappings.")
                        st.rerun()
                    else:
                        st.error(f"Falha no bulk save: {resp.status_code} {resp.text}")

    # -------------------------
    # Auditoria
    # -------------------------
    with chosen[4]:
        st.subheader("Auditoria")
        r = cp_get("/vault/admin/audit", headers=api_headers(), params={"limit": 200})
        if r.status_code != 200:
            st.error(f"Erro auditoria: {r.status_code} {r.text}")
        else:
            st.dataframe(r.json().get("rows", []), use_container_width=True)