from __future__ import annotations
from sqlalchemy.orm import Session
from sqlalchemy import select, delete, text
from app.db.models import Principal, Secret, SecretMapping, AuditLog

def ensure_principal(db: Session, email: str, *, role: str = "user", status: str = "active", now: int) -> Principal:
    """Garante que um principal exista no banco de dados, criando-o se necessário.

    Se o principal já existir, apenas atualiza o campo ``updated_at``
    (se diferente). Caso contrário, cria um novo registro com os
    valores fornecidos e faz ``commit``.

    Args:
        db: Sessão SQLAlchemy ativa.
        email: Endereço de e-mail do principal (será normalizado para minúsculas).
        role: Papel inicial do principal (padrão: ``user``).
        status: Status inicial (padrão: ``active``).
        now: Timestamp Unix atual para ``created_at`` / ``updated_at``.

    Returns:
        Principal: Instância do modelo ``Principal`` (existente ou recém-criada).
    """
    email = email.lower()
    p = db.get(Principal, email)
    if p:
        if p.updated_at != now:
            p.updated_at = now
        return p
    p = Principal(email=email, role=role, status=status, created_at=now, updated_at=now, token_valid_after=0)
    db.add(p)
    db.commit()
    return p


def get_principal(db: Session, email: str) -> Principal | None:
    """Busca um principal pelo endereço de e-mail.

    Args:
        db: Sessão SQLAlchemy ativa.
        email: Endereço de e-mail a ser buscado (normalizado para minúsculas).

    Returns:
        Principal | None: Instância encontrada ou ``None`` se inexistente.
    """
    return db.get(Principal, email.lower())


def upsert_real_secret(
    db: Session,
    *,
    real_secret_name: str,
    ciphertext: str,
    updated_at: int,
    enabled: bool = True,
    assign_level: str = "reader",
) -> None:
    """Cria ou atualiza um segredo real no Key Vault.

    Se o segredo já existir (mesmo ``real_secret_name``), atualiza o
    ciphertext, timestamp, flag ``enabled`` e ``assign_level``. Caso
    contrário, insere um novo registro. Faz ``commit`` ao final.

    Args:
        db: Sessão SQLAlchemy ativa.
        real_secret_name: Nome único do segredo.
        ciphertext: Valor já criptografado (Fernet) do segredo.
        updated_at: Timestamp Unix da operação.
        enabled: Se o segredo deve ficar habilitado (padrão: ``True``).
        assign_level: Nível mínimo de papel para atribuição
            (``reader``, ``writer`` ou ``admin``).
    """
    s = db.get(Secret, real_secret_name)
    if s:
        s.ciphertext = ciphertext
        s.updated_at = updated_at
        s.enabled = enabled
        # novo
        if hasattr(s, "assign_level"):
            s.assign_level = assign_level
    else:
        kwargs = dict(
            real_secret_name=real_secret_name,
            ciphertext=ciphertext,
            updated_at=updated_at,
            enabled=enabled,
        )
        # novo (se o model tiver)
        if "assign_level" in Secret.__table__.columns:
            kwargs["assign_level"] = assign_level

        db.add(Secret(**kwargs))
    db.commit()


def set_mapping(db: Session, *, email: str, generic_secret: str, real_secret_name: str, updated_at: int, active: bool = True) -> None:
    """Cria ou atualiza o mapeamento entre um nome genérico e um segredo real
    para um determinado usuário.

    Se o mapeamento (``email`` + ``generic_secret``) já existir, atualiza
    os campos ``real_secret_name``, ``updated_at`` e ``active``. Caso
    contrário, insere um novo registro. Faz ``commit`` ao final.

    Args:
        db: Sessão SQLAlchemy ativa.
        email: E-mail do principal (normalizado para minúsculas).
        generic_secret: Nome genérico do segredo usado pelo flow.
        real_secret_name: Nome real do segredo no vault.
        updated_at: Timestamp Unix da operação.
        active: Se o mapeamento deve ficar ativo (padrão: ``True``).
    """
    email = email.lower()
    m = db.get(SecretMapping, {"email": email, "generic_secret": generic_secret})
    if m:
        m.real_secret_name = real_secret_name
        m.updated_at = updated_at
        m.active = active
    else:
        db.add(
            SecretMapping(
                email=email,
                generic_secret=generic_secret,
                real_secret_name=real_secret_name,
                updated_at=updated_at,
                active=active,
            )
        )
    db.commit()


def resolve_real_secret_name(db: Session, *, email: str, generic_secret: str) -> str | None:
    """Resolve o nome real de um segredo a partir do nome genérico e do e-mail.

    Consulta a VIEW ``v_secret_resolution`` no banco de dados para
    encontrar qual segredo real está mapeado para a combinação de
    usuário + nome genérico fornecida.

    Args:
        db: Sessão SQLAlchemy ativa.
        email: E-mail do principal (normalizado para minúsculas).
        generic_secret: Nome genérico do segredo solicitado.

    Returns:
        str | None: Nome real do segredo ou ``None`` se nenhum mapeamento
            ativo for encontrado.
    """
    # Usa a VIEW (v_secret_resolution)
    row = db.execute(
        text("SELECT real_secret_name FROM v_secret_resolution WHERE email=:email AND generic_secret=:gs LIMIT 1"),
        {"email": email.lower(), "gs": generic_secret},
    ).fetchone()
    return row[0] if row else None


def get_secret(db: Session, real_secret_name: str) -> Secret | None:
    """Busca um segredo real pelo seu nome.

    Args:
        db: Sessão SQLAlchemy ativa.
        real_secret_name: Nome único do segredo a ser buscado.

    Returns:
        Secret | None: Instância do modelo ``Secret`` ou ``None``
            se inexistente.
    """
    return db.get(Secret, real_secret_name)


def audit(db: Session, *, ts: int, email: str, action: str, status: str,
          generic_secret: str | None = None, real_secret_name: str | None = None, details: str | None = None) -> None:
    """Registra uma entrada no log de auditoria do Key Vault.

    Cria um novo registro na tabela ``audit_log`` com os dados da
    operação realizada e faz ``commit`` imediatamente.

    Args:
        db: Sessão SQLAlchemy ativa.
        ts: Timestamp Unix do evento.
        email: E-mail do ator que realizou a ação.
        action: Tipo da ação (ex: ``read_secret``, ``upsert_real_secret``).
        status: Resultado da ação (ex: ``ok``, ``forbidden``, ``not_found``).
        generic_secret: Nome genérico do segredo envolvido (opcional).
        real_secret_name: Nome real do segredo envolvido (opcional).
        details: Informações adicionais em texto livre (opcional).
    """
    db.add(
        AuditLog(
            ts=ts,
            email=email.lower(),
            action=action,
            status=status,
            generic_secret=generic_secret,
            real_secret_name=real_secret_name,
            details=details,
        )
    )
    db.commit()


def list_audit(db: Session, limit: int = 200) -> list[AuditLog]:
    """Lista as entradas mais recentes do log de auditoria.

    Retorna os registros ordenados do mais recente para o mais antigo,
    limitados pela quantidade especificada.

    Args:
        db: Sessão SQLAlchemy ativa.
        limit: Número máximo de registros a retornar (padrão: 200).

    Returns:
        list[AuditLog]: Lista de instâncias ``AuditLog`` ordenadas
            por ``ts`` descendente.
    """
    stmt = select(AuditLog).order_by(AuditLog.ts.desc()).limit(limit)
    return list(db.execute(stmt).scalars().all())