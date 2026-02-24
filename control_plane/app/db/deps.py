from __future__ import annotations
from typing import Generator
from app.db.session import get_sessionmaker
from sqlalchemy.orm import Session

def get_db() -> Generator[Session, None, None]:
    SessionLocal = get_sessionmaker()
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
