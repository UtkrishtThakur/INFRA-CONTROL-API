from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    DATABASE_URL: str
    REDIS_URL: str | None = None

    UPSTREAM_BASE_URL: str

    JWT_SECRET_KEY: str
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    CONTROL_WORKER_SHARED_SECRET: str | None = None

    SERVICE_NAME: str = "control-api"
    ENV: str = "development"
    WORKER_SECRET_KEY: str = "dev-secret"

    class Config:
        env_file = ".env"
        case_sensitive = True
        extra = "ignore"

settings = Settings()
