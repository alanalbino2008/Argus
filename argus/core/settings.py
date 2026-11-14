"""Centralised runtime configuration (12-factor style).

Every setting can be overridden with an ``ARGUS_``-prefixed environment
variable or a local ``.env`` file, e.g.::

    ARGUS_DATABASE_URL=postgresql+asyncpg://argus:secret@db/argus
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field, SecretStr
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

    # --- Security (Phase 3) ---------------------------------------------------------
    auth_enabled: bool = Field(
        default=True, description="Require API keys. Disable ONLY for isolated local development."
    )
    bootstrap_admin_key: SecretStr | None = Field(
        default=None, description="Admin key to install on first start (otherwise one is generated and logged once)"
    )
    cors_origins: list[str] = Field(
        default_factory=list, description='Extra browser origins allowed to call the API, e.g. ["https://soc.example"]'
    )
    allow_private_targets: bool = Field(
        default=False, description="Permit scanning private/internal networks (authorised internal tests only)"
    )
    max_concurrent_scans: int = Field(default=5, ge=1, description="Scans allowed to run at once (whole server)")
    scans_per_minute: int = Field(default=10, ge=1, description="Scan launches allowed per API key per minute")
    # --- Optional intelligence sources (modules stay disabled until a key is set) ---------
    virustotal_api_key: SecretStr | None = Field(default=None, description="VirusTotal v3 API key")
    hibp_api_key: SecretStr | None = Field(default=None, description="Have I Been Pwned v3 API key")
    shodan_api_key: SecretStr | None = Field(default=None, description="Shodan API key (full host API)")
    github_token: SecretStr | None = Field(
        default=None, description="GitHub token: enables public code-leak search (GitHub requires auth for code search)"
    )
    extra_platforms_file: str | None = Field(
        default=None, description="JSON file of extra username platforms (same format as argus/data/platforms.json)"
    )
    plugins: list[str] = Field(
        default_factory=list,
        description='Entry-point names of third-party plugin modules to load, e.g. ["crtsh_plus"]. Empty = none.',
    )
    monitors_enabled: bool = Field(default=True, description="Run the scheduler that re-scans monitored targets")
    monitor_poll_seconds: float = Field(
        default=60.0, ge=1, description="How often the scheduler checks for due monitors"
    )
    ws_ticket_ttl_seconds: int = Field(default=30, ge=5, description="Lifetime of one-time WebSocket tickets")


@lru_cache
def get_settings() -> Settings:
    return Settings()
