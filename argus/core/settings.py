"""Centralised runtime configuration (12-factor style).

Every setting can be overridden with an ``ARGUS_``-prefixed environment
variable or a local ``.env`` file, e.g.::

    ARGUS_DATABASE_URL=postgresql+asyncpg://argus:secret@db/argus
"""

from __future__ import annotations

import os
import socket
from functools import lru_cache
from typing import Any, Literal

from pydantic import Field, SecretStr, field_validator
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
    # --- Single sign-on (OpenID Connect) ---------------------------------------------------
    public_url: str | None = Field(
        default=None,
        description="External URL users open, e.g. https://argus.example.com (builds the OIDC redirect URI)",
    )
    oidc_issuer: str | None = Field(
        default=None,
        description="OIDC issuer, e.g. https://accounts.google.com or https://login.microsoftonline.com/<tenant>/v2.0",
    )
    oidc_client_id: str | None = Field(default=None, description="Client (application) id registered at the provider")
    oidc_client_secret: SecretStr | None = Field(default=None, description="Client secret (confidential client)")
    oidc_display_name: str = Field(default="Single sign-on", description="Button label, e.g. 'Microsoft' or 'Okta'")
    oidc_scopes: str = Field(default="openid email profile", description="Requested scopes")
    oidc_allowed_domains: list[str] = Field(
        default_factory=list, description='Only these email domains may sign in, e.g. ["acme.com"] (empty = any)'
    )
    oidc_require_verified_email: bool = Field(
        default=True, description="Reject identities whose provider does not assert email_verified=true"
    )
    oidc_role_claim: str = Field(default="groups", description="ID-token claim holding group/role names")
    oidc_admin_groups: list[str] = Field(default_factory=list, description="Claim values that grant admin")
    oidc_analyst_groups: list[str] = Field(default_factory=list, description="Claim values that grant analyst")
    oidc_viewer_groups: list[str] = Field(default_factory=list, description="Claim values that grant viewer")
    oidc_default_role: Literal["viewer", "analyst", "none"] = Field(
        default="viewer",
        description="Role for users matching no group ('none' = refuse them). Ignored for existing users "
        "unless group mapping is configured.",
    )
    oidc_admin_emails: list[str] = Field(
        default_factory=list, description="Emails always granted admin (bootstrap the first administrators)"
    )
    oidc_default_workspace: str = Field(
        default="default",
        description="Workspace (slug) every SSO user joins with their resolved role; empty = none",
    )
    oidc_workspace_groups: dict[str, str] = Field(
        default_factory=dict,
        description='IdP group -> workspace slug, e.g. {"red-team": "red-team"}. Memberships of mapped '
        "workspaces follow the provider at every sign-in.",
    )
    session_ttl_hours: float = Field(default=8.0, gt=0, le=24 * 30, description="Lifetime of a browser session")

    # --- Outbound notifications ------------------------------------------------------------
    encryption_key: SecretStr | None = Field(
        default=None,
        description="Encrypts webhook URLs and signing secrets at rest (random string, >= 32 characters)",
    )
    encryption_key_file: str | None = Field(
        default=None,
        description="File holding the encryption key, created on first start if missing (single-node installs)",
    )
    encryption_previous_keys: list[SecretStr] = Field(
        default_factory=list, description="Former encryption keys, still accepted for decryption during rotation"
    )
    notifications_enabled: bool = Field(default=True, description="Run the notification dispatcher")
    report_schedules_enabled: bool = Field(default=True, description="Run the scheduled-report loop")
    report_poll_seconds: float = Field(default=60.0, gt=0, description="How often due report schedules are checked")
    notify_poll_seconds: float = Field(default=2.0, gt=0, description="How often pending notifications are checked")
    notify_max_attempts: int = Field(
        default=8, ge=1, le=20, description="Delivery attempts before a notification is marked failed (~7 h)"
    )
    notify_timeout_seconds: float = Field(default=10.0, gt=0, le=60, description="Timeout for one delivery attempt")
    smtp_host: str | None = Field(default=None, description="SMTP server for email notifications (unset = no email)")
    smtp_port: int = Field(default=587, ge=1, le=65535, description="SMTP port (587 STARTTLS, 465 TLS)")
    smtp_security: Literal["starttls", "tls", "none"] = Field(
        default="starttls", description="'starttls' (587), 'tls' (465) or 'none' (trusted local relay only)"
    )
    smtp_username: str | None = Field(default=None, description="SMTP user (unset = no authentication)")
    smtp_password: SecretStr | None = Field(default=None, description="SMTP password")
    smtp_from: str = Field(default="argus@localhost", description="Sender address of notification emails")

    @field_validator("encryption_key", mode="before")
    @classmethod
    def _empty_key_is_none(cls, value: Any) -> Any:
        return None if value in ("", None) else value

    @field_validator("encryption_key")
    @classmethod
    def _long_enough(cls, value: SecretStr | None) -> SecretStr | None:
        if value is not None and len(value.get_secret_value()) < 32:
            raise ValueError("ARGUS_ENCRYPTION_KEY must be at least 32 characters")
        return value

    # --- Observability ---------------------------------------------------------------------
    log_format: Literal["text", "json"] = Field(
        default="text", description="'json' for one JSON object per line (log platforms); 'text' for humans"
    )
    log_level: str = Field(default="INFO", description="Level for Argus's own loggers")
    metrics_enabled: bool = Field(default=True, description="Expose Prometheus metrics at /metrics")
    metrics_token: SecretStr | None = Field(
        default=None,
        description="If set, /metrics requires 'Authorization: Bearer <token>' (otherwise restrict it by network)",
    )
    # --- Clustering (several replicas sharing one PostgreSQL database) ---------------------
    instance_id: str = Field(
        default_factory=lambda: os.environ.get("HOSTNAME") or socket.gethostname(),
        description="Name of this replica (Kubernetes: the pod name). Recorded as the owner of the scans it runs.",
    )
    auto_migrate: bool = Field(
        default=True,
        description="Apply database migrations at startup. Kubernetes runs them once in a Job instead (false).",
    )
    scan_stale_seconds: float = Field(
        default=120.0,
        ge=10,
        description="A running scan whose owner sent no heartbeat for this long is treated as crashed",
    )
    ws_ticket_ttl_seconds: int = Field(default=30, ge=5, description="Lifetime of one-time WebSocket tickets")


@lru_cache
def get_settings() -> Settings:
    return Settings()
