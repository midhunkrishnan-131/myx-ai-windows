"""
SQLAlchemy 2.0 Database Engine and Session Factory (PostgreSQL / Neon / Supabase + SQLite test mode).
"""
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.core.config import settings

# Ensure SQLite runtime directory exists if using relative SQLite
if settings.DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}
    db_file_path = settings.DATABASE_URL.replace("sqlite:///", "")
    if not db_file_path.startswith(":memory:"):
        os.makedirs(os.path.dirname(os.path.abspath(db_file_path)), exist_ok=True)
else:
    connect_args = {}

engine = create_engine(settings.DATABASE_URL, pool_pre_ping=True, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
