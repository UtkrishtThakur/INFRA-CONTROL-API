from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

from config import settings

# =========================
# SQLAlchemy Engine
# =========================

engine = create_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True,
    future=True,
)

# =========================
# Session factory
# =========================

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    future=True,
)

# =========================
# Base class for models
# =========================

Base = declarative_base()

# =========================
# Dependency
# =========================

def get_db():
    """
    FastAPI dependency that provides a database session
    and ensures it is closed after the request.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
