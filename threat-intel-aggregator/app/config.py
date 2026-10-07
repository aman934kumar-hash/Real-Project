"""
Application configuration — loaded from environment variables via Pydantic Settings.
"""
from functools import lru_cache
from typing import List, Optional

from pydantic import AnyUrl, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # ------------------------------------------------------------------ App
    app_name: str = "Threat Intelligence Aggregator"
    app_version: str = "1.0.0"
    debug: bool = False
    api_prefix: str = "/api/v1"
    allowed_hosts: List[str] = ["*"]

    # ------------------------------------------------------------------ Database
    database_url: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/threat_intel"
    db_pool_size: int = 10
    db_max_overflow: int = 20
    db_echo: bool = False

    # ------------------------------------------------------------------ Security
    secret_key: str = "change-me-in-production-use-32-char-min"
    api_key_header: str = "X-API-Key"
    internal_api_keys: List[str] = []   # comma-separated in .env

    # ------------------------------------------------------------------ Rate limiting
    rate_limit_per_minute: int = 60
    enrichment_cache_ttl_seconds: int = 3600   # 1 hour default

    # ------------------------------------------------------------------ Threat Feed API keys
    otx_api_key: Optional[str] = None
    virustotal_api_key: Optional[str] = None
    abuseipdb_api_key: Optional[str] = None

    # ------------------------------------------------------------------ Scheduler
    scheduler_enabled: bool = True
    scheduler_timezone: str = "UTC"

    # ------------------------------------------------------------------ HTTP client
    http_timeout_seconds: int = 30
    http_max_retries: int = 3
    http_retry_backoff_factor: float = 1.5

    @field_validator("internal_api_keys", mode="before")
    @classmethod
    def split_api_keys(cls, v):
        if isinstance(v, str):
            return [k.strip() for k in v.split(",") if k.strip()]
        return v


@lru_cache
def get_settings() -> Settings:
    return Settings()
