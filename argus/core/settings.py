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
from urllib.parse import urlsplit

from pydantic import BaseModel, Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class EgressRoute(BaseModel):
    """A way out to the internet that hides where an investigator is (Tor, a VPN or proxy).

    ``url`` is an HTTP CONNECT proxy, e.g. Tor's ``HTTPTunnelPort`` (``http://127.0.0.1:9080``) or
    ``http://user:password@vpn-gateway:3128``. Only the name, kind and description are ever shown
    to users; the address and credentials stay with the operator.
    """

    name: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,31}$")
    url: str
    kind: Literal["tor", "proxy"] = "proxy"
    anonymous: bool | None = None  # default: True for Tor, False for proxies (which may know who you are)
    description: str = ""

    @field_validator("url")
    @classmethod
    def _connect_proxy(cls, url: str) -> str:
        parts = urlsplit(url)
        if parts.scheme != "http" or not parts.hostname or not parts.port:
            raise ValueError("an egress route is an HTTP CONNECT proxy: http://host:port")
        return url

    @property
    def is_anonymous(self) -> bool:
        return self.kind == "tor" if self.anonymous is None else self.anonymous


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
    api_requests_per_minute: int = Field(
        default=600, ge=0, description="API requests allowed per API key per minute (0 = unlimited)"
    )
    # --- Optional intelligence sources (modules stay disabled until a key is set) ---------
    virustotal_api_key: SecretStr | None = Field(default=None, description="VirusTotal v3 API key")
    hibp_api_key: SecretStr | None = Field(default=None, description="Have I Been Pwned v3 API key")
    ransomware_feed_url: str | None = Field(
        default="https://api.ransomware.live/v2",
        description="Ransomware leak-site research feed (ransomware.live API); empty turns it off",
    )
    exposure_monitoring_enabled: bool = Field(default=True, description="Run the breach and dark-web exposure loop")
    exposure_poll_seconds: float = Field(
        default=300.0, gt=0, description="How often due exposure checks are looked for"
    )
    egress_routes: list[EgressRoute] = Field(
        default_factory=list,
        description='Routes that hide where investigations come from, e.g. [{"name": "tor", '
        '"url": "http://127.0.0.1:9080", "kind": "tor"}]',
    )
    egress_check_url: str = Field(
        default="https://check.torproject.org/api/ip",
        description="Returns the caller's address (and whether it is Tor) to test a route",
    )
    capture_browser: str = Field(
        default="auto",
        description="Headless Chromium/Chrome for evidence screenshots: 'auto' (find one), 'off', or a path",
    )
    capture_browser_sandbox: bool = Field(
        default=True,
        description="Chrome's own sandbox for the capture browser; turn off only where the kernel cannot provide "
        "it (some containers, Ubuntu 24.04 without user namespaces), at a security cost",
    )
    evidence_timestamp_url: str | None = Field(
        default=None,
        description="RFC 3161 timestamp authority for evidence (e.g. https://freetsa.org/tsr); only digests are sent",
    )
    evidence_max_upload_mb: int = Field(default=25, ge=1, le=200, description="Largest evidence file accepted")
    remediation_poll_seconds: float = Field(
        default=300.0, gt=0, description="How often overdue remediation tasks and expired acceptances are checked"
    )
    exposure_retention_days: int = Field(
        default=365, ge=30, description="Resolved exposure findings are deleted after this many days"
    )
    companies_house_api_key: SecretStr | None = Field(
        default=None,
        description="UK Companies House API key: your own (lookups stay private, no credits), or the account "
        "service's key that it uses for Argus Connect",
    )
    web_search_api_key: SecretStr | None = Field(
        default=None,
        description="Brave Search API key for web mentions of phone numbers and emails: your own (searches stay "
        "private, no credits), or the account service's key that it uses for Argus Connect",
    )
    companies_house_officer_limit: int = Field(
        default=8, ge=0, le=35, description="Directors whose other companies are looked up per company (1 credit each)"
    )
    sec_user_agent: str = Field(
        default="", description="SEC EDGAR asks for 'Organisation contact@email' in every request; '' = EDGAR off"
    )
    offshore_leaks_url: str = Field(
        default="https://offshoreleaks.icij.org", description="ICIJ Offshore Leaks Database; '' = off"
    )
    crawl_max_pages: int = Field(
        default=40, ge=1, le=500, description="Most pages the website crawler reads on one site"
    )
    crawl_delay_seconds: float = Field(
        default=0.5, ge=0.0, le=30.0, description="Pause between the website crawler's pages, to spare the site"
    )
    gleif_url: str = Field(default="https://api.gleif.org/api/v1", description="Global LEI register (GLEIF); '' = off")
    france_registry_url: str = Field(default="https://recherche-entreprises.api.gouv.fr",
                                     description="France's company search (SIRENE / RNE); '' = off")  # fmt: skip
    norway_registry_url: str = Field(default="https://data.brreg.no/enhetsregisteret/api",
                                     description="Norway's company register (Brønnøysund); '' = off")  # fmt: skip
    finland_registry_url: str = Field(default="https://avoindata.prh.fi/opendata-ytj-api/v3",
                                      description="Finland's company register (PRH); '' = off")  # fmt: skip
    vault_idle_minutes: int = Field(
        default=15, ge=0, le=1440, description="Case vault: lock after this many minutes without activity; 0 = never"
    )
    # ---------------------------------------------------------------- AI analyst
    anthropic_api_key: SecretStr | None = Field(
        default=None,
        description="Claude API key for the AI analyst: your own (case material goes straight to Anthropic and "
        "costs no credits), or the account service's key that it uses for Argus Connect",
    )
    analyst_model: str = Field(
        default="", max_length=100, description="Claude model for the AI analyst; '' = the newest Opus model available"
    )
    analyst_effort: Literal["low", "medium", "high", "xhigh", "max"] = Field(
        default="high", description="How hard the AI analyst thinks: higher is more thorough, slower and dearer"
    )
    analyst_max_chars: int = Field(
        default=400_000, ge=10_000, le=2_000_000, description="Most case material (characters) sent in one request"
    )
    shodan_api_key: SecretStr | None = Field(default=None, description="Shodan API key (full host API)")
    github_token: SecretStr | None = Field(
        default=None, description="GitHub token: enables public code-leak search (GitHub requires auth for code search)"
    )
    extra_platforms_file: str | None = Field(
        default=None, description="JSON file of extra username platforms (same format as argus/data/platforms.json)"
    )
    username_catalog_url: str = Field(
        default="https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json",
        description="Community username catalog (WhatsMyName format) searched alongside the built-in sites; '' = off",
    )
    username_catalog_file: str | None = Field(
        default=None, description="A local copy of the community catalog (offline installs); used instead of the URL"
    )
    username_catalog_extra_url: str = Field(
        default="https://raw.githubusercontent.com/soxoj/maigret/main/maigret/resources/data.json",
        description="A second community username catalog (Maigret format), with more sites; '' = off",
    )
    username_catalog_extra_limit: int = Field(
        default=3000, ge=0, le=20000, description="Most sites taken from the second catalog (the most visited first)"
    )
    username_catalog_extra_file: str | None = Field(
        default=None, description="A local copy of the second catalog (offline installs); used instead of the URL"
    )
    # ---------------------------------------------------------------- editions and accounts
    edition: Literal["server", "personal"] = Field(
        default="server",
        description="'personal': one person's Argus on their own computer, unlocked by their Argus account",
    )
    account_service_enabled: bool = Field(
        default=False, description="Run the Argus account service here (subscription accounts and licences)"
    )
    licence_signing_key: SecretStr | None = Field(
        default=None,
        description="Account service: Ed25519 private key that signs licences (argus --generate-licence-keys)",
    )
    account_signup_enabled: bool = Field(
        default=False, description="Account service: anyone may create a trial account"
    )
    trial_days: int = Field(default=14, ge=1, le=90, description="Account service: length of a new account's trial")
    licence_offline_days: int = Field(
        default=14, ge=1, le=90, description="Account service: how long a licence works without reaching the service"
    )
    account_server_url: str = Field(
        default="", description="Personal edition: the Argus account service it signs in to (https://...)"
    )
    licence_public_key: str = Field(
        default="", description="Personal edition: the account service's public key, to check licences offline"
    )
    opencorporates_api_key: SecretStr | None = Field(
        default=None, description="OpenCorporates API token: company registers of about 140 countries"
    )
    courtlistener_api_key: SecretStr | None = Field(
        default=None, description="CourtListener API token: US federal court dockets and opinions (free account)"
    )
    tineye_api_key: SecretStr | None = Field(
        default=None, description="TinEye API key: reverse image search (where else a picture appears)"
    )
    wayback_url: str = Field(
        default="https://web.archive.org", description="The Internet Archive (page history); '' = off"
    )
    gazette_url: str = Field(
        default="https://www.thegazette.co.uk", description="The UK Gazette (insolvency notices); '' = off"
    )
    stripe_secret_key: SecretStr | None = Field(
        default=None, description="Account service: Stripe secret key (sk_live_... or sk_test_...) for payments"
    )
    stripe_webhook_secret: SecretStr | None = Field(
        default=None, description="Account service: the signing secret of the Stripe webhook (whsec_...)"
    )
    stripe_api_url: str = Field(default="https://api.stripe.com", description="Stripe's API (changed only in tests)")
    stripe_price_personal: str = Field(default="", description="Account service: Stripe price id of the Personal plan")
    stripe_price_professional: str = Field(
        default="", description="Account service: Stripe price id of the Professional plan"
    )
    stripe_price_byok: str = Field(
        default="", description="Account service: Stripe price id of the Bring-your-own-keys plan"
    )
    stripe_price_business: str = Field(
        default="", description="Account service: Stripe price id of the Business plan (priced per seat)"
    )
    stripe_price_business_setup: str = Field(
        default="", description="Account service: optional one-off Stripe price charged when a Business plan starts"
    )
    stripe_credit_packs: str = Field(
        default="", description="Account service: credit packs for sale, as credits=price id (500=price_1,2000=price_2)"
    )
    owner_email: str = Field(
        default="", description="The email of this server's owner: the only person who can open the owner console"
    )
    admin_keys_allowed: bool = Field(
        default=True, description="API keys and other administrators may administer the platform (off: owner only)"
    )
    owner_session_hours: float = Field(default=8, ge=0.25, le=24, description="Owner console: longest session")
    owner_idle_minutes: float = Field(default=30, ge=5, le=240, description="Owner console: ends after this idle time")
    account_emails_enabled: bool = Field(
        default=True, description="Account service: email account holders (needs ARGUS_SMTP_HOST)"
    )
    account_email_from: str = Field(
        default="", description="Account service: sender of account emails (default: ARGUS_SMTP_FROM)"
    )
    support_email: str = Field(default="", description="Account service: support address shown in emails and replies")
    owner_alerts_enabled: bool = Field(
        default=True, description="Owner console: email the owner when something needs attention"
    )
    owner_alert_email: str = Field(
        default="", description="Owner alerts: where to send them (default: the owner's email)"
    )
    owner_alert_payments: bool = Field(default=True, description="Owner alerts: disputes and failed payments")
    owner_alert_new_customers: bool = Field(default=True, description="Owner alerts: each new paying customer")
    owner_daily_summary: bool = Field(default=False, description="Owner alerts: a short daily summary email")
    owner_summary_hour: int = Field(default=8, ge=0, le=23, description="Owner alerts: hour (UTC) of the daily summary")
    owner_alert_check_seconds: float = Field(
        default=300, ge=10, le=3600, description="Owner alerts: how often to check"
    )
    backup_dir: str = Field(
        default="", description="Automatic encrypted backups (SQLite databases): the folder they go to"
    )
    backup_password: SecretStr | None = Field(
        default=None, description="Password the automatic backups are encrypted with (needed to restore them)"
    )
    backup_every_hours: int = Field(default=24, ge=1, le=168, description="Automatic backups: how often")
    backup_keep: int = Field(default=14, ge=1, le=365, description="Automatic backups: how many to keep")
    desktop_latest_version: str = Field(
        default="", description="Account service: the newest Argus Personal desktop version (e.g. 1.55.0)"
    )
    desktop_download_url: str = Field(
        default="", description="Account service: the page where investigators download the desktop installer"
    )
    billing_return_url: str = Field(
        default="",
        description="Account service: page customers return to after paying, when not paying from Argus Personal",
    )
    licence_refresh_seconds: float = Field(default=6 * 3600, ge=60, description="Personal edition: renewal attempts")
    # ---------------------------------------------------------------- cryptocurrency
    bitcoin_api_url: str = Field(
        default="https://mempool.space/api", description="Esplora-compatible Bitcoin API (mempool.space, Blockstream)"
    )
    evm_chains: dict[str, str] = Field(
        default_factory=lambda: {"ethereum": "https://eth.blockscout.com"},
        description='Blockscout instances to trace Ethereum-style addresses on, e.g. {"ethereum": ..., "base": ...}',
    )
    crypto_counterparties: int = Field(default=12, ge=1, le=50, description="Counterparty wallets kept per wallet")
    sanctions_sdn_url: str = Field(
        default="https://www.treasury.gov/ofac/downloads/sdn.csv", description="OFAC SDN list (CSV); '' = off"
    )
    sanctions_comments_url: str = Field(
        default="https://www.treasury.gov/ofac/downloads/sdn_comments.csv",
        description="OFAC SDN remarks continued (CSV), where long entries list more addresses",
    )
    sanctions_alt_url: str = Field(
        default="https://www.treasury.gov/ofac/downloads/alt.csv", description="OFAC SDN aliases (CSV)"
    )
    uk_sanctions_url: str = Field(
        default="https://sanctionslist.fcdo.gov.uk/docs/UK-Sanctions-List.csv",
        description="UK Sanctions List (CSV); '' = off",
    )
    un_sanctions_url: str = Field(
        default="https://scsanctions.un.org/resources/xml/en/consolidated.xml",
        description="UN Security Council Consolidated List (XML); '' = off",
    )
    sanctions_file: str | None = Field(
        default=None,
        description="A folder of saved sanctions files for offline use: sdn.csv, sdn_comments.csv, alt.csv, "
        "UK-Sanctions-List.csv, consolidated.xml",
    )
    map_tile_url: str = Field(
        default="https://tile.openstreetmap.org/{z}/{x}/{y}.png",
        description="Map images (fetched by the server, never the browser); '' = maps without a background",
    )
    map_attribution: str = Field(default="© OpenStreetMap contributors", description="Credit shown on maps")
    geocoder_url: str = Field(
        default="https://nominatim.openstreetmap.org/search",
        description="Nominatim-compatible address look-up, used only when asked; '' = off",
    )
    account_watch_enabled: bool = Field(default=True, description="Re-read watched accounts and record changes")
    account_watch_poll_seconds: float = Field(default=60.0, ge=5.0, description="How often due watches are looked for")
    username_catalog_ttl_hours: int = Field(default=168, ge=1, le=2160, description="How long the catalog is cached")
    plugins: list[str] = Field(
        default_factory=list,
        description='Entry-point names of third-party plugin modules to load, e.g. ["crtsh_plus"]. Empty = none.',
    )
    hackertarget_api_key: SecretStr | None = Field(
        default=None, description="HackerTarget API key: raises the free daily limit of reverse-IP/DNS pivots"
    )
    lookalike_max_candidates: int = Field(
        default=1500, ge=0, le=20000, description="Lookalike domains checked per scan (0 disables the check)"
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
    integration_allowed_hosts: list[str] = Field(
        default_factory=list,
        description=(
            "Exact host names of self-hosted integrations (Splunk, Jira Data Center, ServiceNow, webhooks) that may"
            ' be on a private network, e.g. ["splunk.corp.internal"]. Link-local and metadata addresses stay blocked.'
        ),
    )

    @field_validator("integration_allowed_hosts")
    @classmethod
    def _exact_hosts(cls, hosts: list[str]) -> list[str]:
        cleaned = []
        for host in hosts:
            h = host.strip().lower().rstrip(".")
            if not h or any(c in h for c in "*/:@ ") or h.startswith("."):
                raise ValueError(f"integration_allowed_hosts takes exact host names, not patterns or URLs: {host!r}")
            cleaned.append(h)
        return sorted(set(cleaned))

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
