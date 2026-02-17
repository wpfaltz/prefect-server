from __future__ import annotations
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from app.core.settings import settings

class Base(DeclarativeBase):
    pass

def get_engine():
    if not settings.DB_URL:
        raise RuntimeError("CONTROL_PLANE_DB_URL not configured.")
    return create_engine(settings.DB_URL, pool_pre_ping=True)

engine = get_engine()
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)