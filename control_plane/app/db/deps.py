from __future__ import annotations
from typing import Generator
from app.db.session import SessionLocal
from sqlalchemy.orm import Session

def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
