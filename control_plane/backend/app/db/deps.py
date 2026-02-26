from __future__ import annotations
from typing import Generator
from app.db.session import get_sessionmaker
from sqlalchemy.orm import Session

def get_db() -> Generator[Session, None, None]:
    """Gera uma sessão do SQLAlchemy para injeção de dependência no FastAPI.

    Utiliza o padrão *generator dependency* do FastAPI: cria uma sessão
    via ``get_sessionmaker()``, fornece-a ao endpoint através de ``yield``
    e garante que ela será fechada ao final da requisição, mesmo em caso
    de exceção.

    Yields:
        Session: Instância de ``sqlalchemy.orm.Session`` pronta para uso.
    """
    SessionLocal = get_sessionmaker()
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
