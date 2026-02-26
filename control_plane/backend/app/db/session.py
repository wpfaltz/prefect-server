from __future__ import annotations
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from app.core.settings import settings

class Base(DeclarativeBase):
    """Classe base declarativa do SQLAlchemy para todos os modelos ORM.

    Todos os modelos do control-plane devem herdar desta classe para que
    suas tabelas sejam automaticamente registradas no ``MetaData`` e
    reconhecidas pelo Alembic durante o autogenerate de migrations.
    """
    pass

_engine = None
_SessionLocal = None

def get_engine():
    """Retorna a engine SQLAlchemy singleton do control-plane.

    Na primeira chamada, cria a engine a partir da URL definida em
    ``settings.DB_URL`` (variável de ambiente ``CONTROL_PLANE_DB_URL``).
    Chamadas subsequentes reutilizam a mesma instância. A opção
    ``pool_pre_ping=True`` é ativada para detectar conexões quebradas
    antes de usá-las.

    Returns:
        Engine: Instância de ``sqlalchemy.engine.Engine``.

    Raises:
        RuntimeError: Se ``CONTROL_PLANE_DB_URL`` não estiver configurada.
    """
    global _engine
    if _engine is None:
        if not settings.DB_URL:
            raise RuntimeError("CONTROL_PLANE_DB_URL not configured.")
        _engine = create_engine(settings.DB_URL, pool_pre_ping=True)
    return _engine

def get_sessionmaker():
    """Retorna o ``sessionmaker`` singleton vinculado à engine do control-plane.

    Na primeira chamada, cria o factory ``sessionmaker`` com ``autoflush=False``
    e ``autocommit=False``, vinculado à engine obtida via ``get_engine()``.
    Chamadas subsequentes retornam a mesma instância.

    Returns:
        sessionmaker: Factory de sessões SQLAlchemy.
    """
    global _SessionLocal
    if _SessionLocal is None:
        _SessionLocal = sessionmaker(bind=get_engine(), autoflush=False, autocommit=False)
    return _SessionLocal