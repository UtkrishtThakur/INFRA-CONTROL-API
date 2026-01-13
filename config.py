from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    # =========================
    # Core Infrastructure
    # =========================
    DATABASE_URL: str
    REDIS_URL: Optional[str] = None

    # =========================
    # Auth
    # =========================
    JWT_SECRET_KEY: str
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # =========================
    # Internal Security
    # =========================
    CONTROL_WORKER_SHARED_SECRET: str

    # =========================
    # Service Metadata
    # =========================
    SERVICE_NAME: str = "control-api"
    ENV: str = "development"

    class Config:
        env_file = ".env"
        case_sensitive = True
        extra = "ignore"


settings = Settings()
