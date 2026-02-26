from __future__ import annotations
import secrets, time
from typing import Any

TICKETS: dict[str, dict[str, Any]] = {}
"""Armazenamento em memória dos tickets de autenticação.

Dicionário que mapeia ``ticket_id`` para um dict contendo
``created_at`` (timestamp de criação) e ``jwt`` (token JWT ou ``None``
enquanto o login não for concluído).
"""

def create_ticket() -> str:
    """Cria um novo ticket de autenticação.

    Gera um identificador único criptograficamente seguro (URL-safe)
    e o armazena no dicionário ``TICKETS`` com timestamp de criação
    e JWT inicialmente nulo. Esse ticket é usado no fluxo de login
    assíncrono (poll-based) com o Google OAuth.

    Returns:
        str: Identificador único do ticket (24 bytes URL-safe base64).
    """
    tid = secrets.token_urlsafe(24)
    TICKETS[tid] = {"created_at": time.time(), "jwt": None}
    return tid

def set_ticket_jwt(ticket_id: str, token: str) -> None:
    """Associa um token JWT a um ticket existente.

    Chamado após o callback do Google OAuth ter sucesso. Armazena
    o JWT no ticket para que a requisição de poll subsequente possa
    entregá-lo ao cliente.

    Args:
        ticket_id: Identificador do ticket previamente criado.
        token: Token JWT assinado a ser armazenado.

    Raises:
        KeyError: Se o ``ticket_id`` não existir no store.
    """
    if ticket_id not in TICKETS:
        raise KeyError("invalid ticket")
    TICKETS[ticket_id]["jwt"] = token

def get_ticket(ticket_id: str) -> dict[str, Any] | None:
    """Busca um ticket pelo seu identificador.

    Retorna o dicionário do ticket contendo ``created_at`` e ``jwt``,
    ou ``None`` se o ticket não existir.

    Args:
        ticket_id: Identificador do ticket a ser buscado.

    Returns:
        dict | None: Dados do ticket ou ``None`` se inexistente.
    """
    return TICKETS.get(ticket_id)