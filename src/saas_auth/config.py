"""Application settings loaded from environment variables (and an optional .env file)."""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "multi-tenant-saas-auth"
    environment: str = "development"
    log_level: str = "INFO"

    database_url: str = "sqlite:///./saas_auth.db"
    redis_url: str | None = None

    jwt_secret: str = "change-me-in-production"
    jwt_algorithm: str = "HS256"
    access_token_ttl_seconds: int = 900
    refresh_token_ttl_seconds: int = 60 * 60 * 24 * 30
    email_token_ttl_seconds: int = 60 * 60 * 24
    invitation_ttl_seconds: int = 60 * 60 * 24 * 7

    bcrypt_rounds: int = 12
    login_max_attempts: int = 5
    login_lockout_seconds: int = 900

    rate_limit_auth_requests: int = 20
    rate_limit_auth_window_seconds: int = 60

    email_backend: str = "console"
    email_from: str = "no-reply@example.com"
    frontend_base_url: str = "http://localhost:3000"

    @property
    def is_production(self) -> bool:
        return self.environment.lower() in {"production", "prod"}


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
