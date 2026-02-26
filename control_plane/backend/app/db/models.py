from __future__ import annotations
from sqlalchemy import (
    Boolean, BigInteger, ForeignKey, Index, String, Text
)
from sqlalchemy.orm import Mapped, mapped_column
from app.db.session import Base

class Principal(Base):
    """Modelo ORM que representa um usuário (principal) do sistema.

    Cada registro armazena o e-mail do usuário, seu papel (role) dentro
    do RBAC e seu status de ativação. O campo ``token_valid_after``
    permite revogar antecipadamente todos os tokens emitidos antes de
    determinado timestamp.

    Attributes:
        email: Endereço de e-mail do principal (chave primária, máx. 320 chars).
        role: Papel do usuário no RBAC (``user``, ``reader``, ``writer``,
            ``admin`` ou ``service``).
        status: Estado da conta (``active`` ou ``disabled``).
        created_at: Timestamp Unix de criação do registro.
        updated_at: Timestamp Unix da última atualização.
        token_valid_after: Timestamp Unix mínimo do ``iat`` de tokens
            aceitos; tokens com ``iat`` inferior são considerados revogados.
    """
    __tablename__ = "principals"

    email: Mapped[str] = mapped_column(String(320), primary_key=True)  # RFC max email len
    role: Mapped[str] = mapped_column(String(32), nullable=False, default="user")      # user/admin/service
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")  # active/disabled

    created_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
    updated_at: Mapped[int] = mapped_column(BigInteger, nullable=False)

    # opcional p/ revogação antecipada (recomendado)
    token_valid_after: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)

class Secret(Base):
    """Modelo ORM que representa um segredo real armazenado no Key Vault.

    O valor do segredo é persistido já criptografado (campo ``ciphertext``)
    utilizando criptografia simétrica Fernet. O campo ``assign_level``
    define o nível mínimo de papel necessário para que um ator possa
    atribuir este segredo a um usuário via mapeamento.

    Attributes:
        real_secret_name: Nome único do segredo (chave primária, máx. 255 chars).
        ciphertext: Valor criptografado do segredo (Fernet).
        updated_at: Timestamp Unix da última atualização.
        enabled: Indica se o segredo está habilitado para leitura.
        assign_level: Nível mínimo de papel para atribuição
            (``reader``, ``writer`` ou ``admin``).
    """
    __tablename__ = "secrets"

    real_secret_name: Mapped[str] = mapped_column(String(255), primary_key=True)
    ciphertext: Mapped[str] = mapped_column(Text, nullable=False)
    updated_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    assign_level: Mapped[str] = mapped_column(String(16), nullable=False, default="reader")


class SecretMapping(Base):
    """Modelo ORM que mapeia um nome genérico de segredo a um segredo real para
    um determinado usuário.

    Permite que diferentes usuários utilizem o mesmo nome genérico
    (``generic_secret``) enquanto acessam segredos reais distintos,
    viabilizando isolamento de credenciais entre ambientes ou equipes.

    Attributes:
        email: E-mail do principal associado (FK para ``principals.email``).
        generic_secret: Nome genérico utilizado pelo flow/código.
        real_secret_name: Nome real do segredo no vault
            (FK para ``secrets.real_secret_name``).
        updated_at: Timestamp Unix da última atualização.
        active: Indica se o mapeamento está ativo.
    """
    __tablename__ = "secret_mapping"

    email: Mapped[str] = mapped_column(
        String(320),
        ForeignKey("principals.email", ondelete="CASCADE"),
        primary_key=True,
    )
    generic_secret: Mapped[str] = mapped_column(String(255), primary_key=True)

    real_secret_name: Mapped[str] = mapped_column(
        String(255),
        ForeignKey("secrets.real_secret_name", ondelete="RESTRICT"),
        nullable=False,
    )

    updated_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

Index("ix_secret_mapping_email", SecretMapping.email)
Index("ix_secret_mapping_generic", SecretMapping.generic_secret)

class AuditLog(Base):
    """Modelo ORM para registro de auditoria de operações no Key Vault.

    Cada entrada registra quem executou qual ação, em que momento,
    qual o resultado (sucesso, proibido, não encontrado, erro) e
    opcionalmente detalhes adicionais. Serve como trilha de auditoria
    completa para fins de compliance e investigação de incidentes.

    Attributes:
        id: Identificador auto-incrementado (chave primária).
        ts: Timestamp Unix do evento.
        email: E-mail do ator que realizou a ação.
        action: Tipo da ação (ex: ``read_secret``, ``upsert_real_secret``,
            ``set_mappings_bulk``, etc.).
        status: Resultado da ação (``ok``, ``forbidden``, ``not_found``, ``error``).
        generic_secret: Nome genérico do segredo envolvido (quando aplicável).
        real_secret_name: Nome real do segredo envolvido (quando aplicável).
        details: Informações adicionais em texto livre.
    """
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    ts: Mapped[int] = mapped_column(BigInteger, nullable=False)

    email: Mapped[str] = mapped_column(String(320), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)   # read_secret, list_secrets, upsert_secret, set_mapping...
    status: Mapped[str] = mapped_column(String(32), nullable=False)   # ok/forbidden/not_found/error

    generic_secret: Mapped[str | None] = mapped_column(String(255), nullable=True)
    real_secret_name: Mapped[str | None] = mapped_column(String(255), nullable=True)

    details: Mapped[str | None] = mapped_column(Text, nullable=True)


Index("ix_audit_log_ts", AuditLog.ts)
Index("ix_audit_log_email", AuditLog.email)
