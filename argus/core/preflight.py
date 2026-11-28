"""Production preflight: refuse to start a production server with an unsafe configuration.

A misconfiguration that is merely inconvenient in development is a breach in production: authentication
switched off, a load balancer told to trust everyone's ``X-Forwarded-For``, replicas that cannot read
each other's encrypted secrets, sign-in cookies sent over plain HTTP. With ``ARGUS_ENVIRONMENT=production``
the server checks its configuration on start and **refuses to start** on any *error*, naming what to fix.
*Warnings* are logged and do not stop it.

Run the same checks without starting anything: ``argus --preflight`` (exit code 1 on errors).
"""

from __future__ import annotations

import ipaddress
import logging
import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlsplit

from argus.core.settings import Settings

logger = logging.getLogger("argus.preflight")

Level = Literal["error", "warning"]


@dataclass(frozen=True)
class Finding:
    level: Level
    code: str
    message: str
    fix: str


class PreflightFailed(RuntimeError):
    def __init__(self, findings: list[Finding]):
        self.findings = findings
        errors = [f for f in findings if f.level == "error"]
        super().__init__("; ".join(f"{f.code}: {f.message}" for f in errors))


def _local_host(host: str | None) -> bool:
    if not host:
        return False
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def check(settings: Settings, env: Mapping[str, str] | None = None) -> list[Finding]:
    """Every problem found in ``settings`` for a production deployment, errors first."""
    env = os.environ if env is None else env
    found: list[Finding] = []

    def error(code: str, message: str, fix: str) -> None:
        found.append(Finding("error", code, message, fix))

    def warning(code: str, message: str, fix: str) -> None:
        found.append(Finding("warning", code, message, fix))

    clustered = settings.database_url.startswith("postgresql")

    if not settings.auth_enabled:
        error("auth_disabled", "authentication is switched off: every caller is an administrator",
              "remove ARGUS_AUTH_ENABLED=false")  # fmt: skip

    trusted = {p.strip() for p in env.get("FORWARDED_ALLOW_IPS", "").split(",")}
    if "*" in trusted:
        error("trust_all_proxies", 'FORWARDED_ALLOW_IPS="*" lets any client forge its IP address (past network '
              "allow-lists, rate limits and sign-in lockouts)",
              "set FORWARDED_ALLOW_IPS to your load balancer's address or subnet")  # fmt: skip

    if settings.encryption_key is None and not settings.encryption_key_file:
        if clustered:
            error("no_encryption_key", "no shared encryption key: integration secrets cannot be stored, and "
                  "replicas could not read each other's", "set ARGUS_ENCRYPTION_KEY (the same on every replica)")  # fmt: skip
        else:
            warning("no_encryption_key", "no encryption key: Slack, Teams, webhook and other integration secrets "
                    "cannot be stored", "set ARGUS_ENCRYPTION_KEY or ARGUS_ENCRYPTION_KEY_FILE")  # fmt: skip
    elif settings.encryption_key is None and clustered:
        error("encryption_key_file_in_cluster", "a key file is per machine: replicas would each make their own "
              "and fail to read each other's secrets", "set ARGUS_ENCRYPTION_KEY (the same on every replica)")  # fmt: skip

    if settings.public_url:
        url = urlsplit(settings.public_url)
        if url.scheme != "https" and not _local_host(url.hostname):
            error("public_url_not_https", f"ARGUS_PUBLIC_URL is {url.scheme}://: sign-in cookies and API keys "
                  "would cross the network unencrypted", "serve Argus over HTTPS and set ARGUS_PUBLIC_URL=https://...")  # fmt: skip
    else:
        warning("no_public_url", "ARGUS_PUBLIC_URL is not set: links in emails and single sign-on need it, and "
                "cookies are marked Secure only when the request arrived over HTTPS",
                "set ARGUS_PUBLIC_URL=https://argus.example.com")  # fmt: skip

    if any(o.strip() == "*" for o in settings.cors_origins):
        error("cors_wildcard", "ARGUS_CORS_ORIGINS contains *: any website could call the API from a visitor's browser",
              "list the exact origins of your own front-ends")  # fmt: skip

    if settings.allow_private_targets:
        warning("private_targets", "scans may reach private and internal networks (ARGUS_ALLOW_PRIVATE_TARGETS)",
                "leave it off unless this server is for authorised internal tests")  # fmt: skip

    if not clustered:
        warning("sqlite", "SQLite: a single server only, with no failover",
                "use PostgreSQL (ARGUS_DATABASE_URL=postgresql+asyncpg://...) for high availability")  # fmt: skip

    if settings.log_format != "json":
        warning("text_logs", "logs are plain text", "set ARGUS_LOG_FORMAT=json for your log platform")
    if settings.metrics_enabled and settings.metrics_token is None:
        warning("metrics_without_token", "/metrics has no token (it answers only loopback, private networks and "
                "signed-in admins)", "set ARGUS_METRICS_TOKEN and give it to Prometheus")  # fmt: skip
    if not settings.smtp_host:
        warning("no_email", "no SMTP server: no password resets, invitations or email alerts",
                "set ARGUS_SMTP_HOST (and credentials)")  # fmt: skip

    found.sort(key=lambda f: f.level != "error")
    return found


def enforce(settings: Settings, env: Mapping[str, str] | None = None) -> list[Finding]:
    """Log every finding; in production raise :class:`PreflightFailed` if any is an error."""
    findings = check(settings, env)
    production = settings.environment == "production"
    for f in findings:
        if not production and f.level == "warning":
            continue  # a development machine need not hear about SMTP and JSON logs on every start
        level = logging.ERROR if f.level == "error" and production else logging.WARNING
        logger.log(level, "Preflight %s: %s - fix: %s", f.code, f.message, f.fix)
    if production and any(f.level == "error" for f in findings):
        raise PreflightFailed(findings)
    return findings
