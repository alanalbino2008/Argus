"""Centralised runtime configuration (12-factor style).

Every setting can be overridden with an ``ARGUS_``-prefixed environment
variable or a local ``.env`` file, e.g.::

    ARGUS_DATABASE_URL=postgresql+asyncpg://argus:secret@db/argus
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ARGUS_", env_file=".env", extra="ignore")

    database_url: str = Field(
        default="sqlite+aiosqlite:///./argus.db",
        description="SQLAlchemy async URL. SQLite for single-node, PostgreSQL (asyncpg) for production.",
    )
    db_echo: bool = Field(default=False, description="Log every SQL statement (debugging only)")
    persist_flush_interval: float = Field(default=1.0, gt=0, description="Seconds between write-behind flushes")
    ws_queue_size: int = Field(default=2000, ge=10, description="Max buffered messages per WebSocket client")


@lru_cache
def get_settings() -> Settings:
    return Settings()
