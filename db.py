from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.exc import OperationalError
from config import settings
import logging

logger = logging.getLogger("securex.db")

# =========================
# SQLAlchemy Engine
# =========================

engine = create_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True,              # Detect dead/stale connections
    pool_size=5,                     # Safe baseline
    max_overflow=10,                 # Burst tolerance
    pool_timeout=30,
    connect_args={
        "sslmode": "require",        # Supabase requires SSL
    },
    future=True,
)

# =========================
# Session Factory
# =========================

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
    future=True,
)

# =========================
# Base Model
# =========================

Base = declarative_base()

# =========================
# Dependency
# =========================

def get_db():
    """
    FastAPI dependency that provides a database session
    and guarantees cleanup.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# =========================
# Safe DB Init (OPTIONAL)
# =========================

def init_db() -> None:
    """
    Initializes database tables.

    IMPORTANT:
    - This MUST NOT crash the app if DB is temporarily unreachable
    - Control Plane must stay up even if DB is flaky
    """
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Database schema ensured")
    except OperationalError as e:
        logger.error(f"Database not reachable during startup: {e}")
    except Exception as e:
        logger.exception(f"Unexpected DB init error: {e}")
