"""Channel types and validation of their destinations.

A notification channel makes the *server* send requests to a URL a user typed, which is
exactly the shape of a Server-Side Request Forgery (SSRF) attack. So:

* Slack and Teams channels only accept those services' own webhook hosts; they cannot be
  used to reach anything else;
* generic webhooks must be HTTPS, carry no credentials in the URL, and point to a public
  host; at send time the guarded resolver re-checks the *resolved* address (DNS rebinding),
  and redirects are not followed;
* the URL is a secret (a Slack webhook URL alone lets anyone post) so it is encrypted at rest
  and only a masked hint is ever shown again.

Integrations (Jira, ServiceNow, Splunk, Microsoft Sentinel) carry credentials, so:

* everything needed to send - URL included - is sealed together, so a changed database row
  cannot redirect stored credentials to another host;
* changing an integration's destination (scheme, host or port) requires re-entering its credentials (otherwise an admin who
  never saw a token could send it to a server they control);
* self-hosted instances on private networks are reachable only if the *operator* lists their
  exact host name in ``ARGUS_INTEGRATION_ALLOWED_HOSTS``; link-local and metadata addresses
  stay blocked even then.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

from argus.security.network import BlockedDestinationError, assert_allowed_host

TYPES = ("slack", "teams", "webhook", "email", "jira", "servicenow", "splunk", "sentinel")
INTEGRATIONS = ("jira", "servicenow", "splunk", "sentinel")
TICKETING = ("jira", "servicenow")  # create tickets for alerts; scheduled reports are not tickets
SEVERITIES = ("low", "medium", "high", "critical")
SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
MAX_RECIPIENTS = 20
SLACK_HOSTS = {"hooks.slack.com"}
# Teams "Workflows" (Power Automate) webhooks, and the older Office 365 connector URLs.
TEAMS_HOST_SUFFIXES = (".logic.azure.com", ".api.powerplatform.com", ".webhook.office.com")
_JIRA_PROJECT = re.compile(r"^[A-Z][A-Z0-9_]{1,9}$")
_SPLUNK_INDEX = re.compile(r"^[a-z0-9_][a-z0-9_-]{0,79}$")
_SOURCETYPE = re.compile(r"^[A-Za-z0-9_:.\-]{1,100}$")
_GUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_TENANT_DOMAIN = re.compile(r"^[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})+$")
_DCR_ID = re.compile(r"^dcr-[0-9a-f]{32}$")
_STREAM = re.compile(r"^(Custom|Microsoft)-[A-Za-z0-9_]{1,100}$")
_TOKEN = re.compile(r"^[^\s]{8,1024}$")
SENTINEL_CLOUDS = {  # DCE host suffix -> (token authority, scope)
    ".ingest.monitor.azure.com": ("login.microsoftonline.com", "https://monitor.azure.com//.default"),
    ".ingest.monitor.azure.us": ("login.microsoftonline.us", "https://monitor.azure.us//.default"),
    ".ingest.monitor.azure.cn": ("login.chinacloudapi.cn", "https://monitor.azure.cn//.default"),
}
SPLUNK_PATH = "/services/collector/event"
_EMAIL = re.compile(r"^[^@\s<>,;\"']{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}$")


class ChannelConfigError(ValueError):
    """The destination is invalid; the message is safe to show to the user."""


def _check_url(url: str, *, allow_private: bool) -> tuple[str, str]:
    url = url.strip()
    if len(url) > 2048:
        raise ChannelConfigError("The URL is too long")
    parts = urlsplit(url)
    if parts.scheme != "https" and not (allow_private and parts.scheme == "http"):
        raise ChannelConfigError("The URL must start with https://")
    if not parts.hostname:
        raise ChannelConfigError("The URL has no host")
    if parts.username or parts.password:
        raise ChannelConfigError("Put credentials in the signing secret, not in the URL")
    if any(c in url for c in "\r\n\t "):
        raise ChannelConfigError("The URL contains whitespace")
    return url, parts.hostname.lower()


def mask(url: str) -> str:
    """'https://hooks.slack.com/…/AbCd': enough to recognise, useless to an attacker."""
    parts = urlsplit(url)
    return (
        f"{parts.scheme}://{parts.hostname}/…{url[-4:]}"
        if len(parts.path) > 4
        else f"{parts.scheme}://{parts.hostname}/"
    )


def _text(config: dict[str, Any], key: str, limit: int = 256) -> str:
    value = str(config.get(key) or "").strip()
    if len(value) > limit:
        raise ChannelConfigError(f"{key.replace('_', ' ').capitalize()} is too long")
    if any(c in value for c in "\r\n\t"):
        raise ChannelConfigError(f"{key.replace('_', ' ').capitalize()} cannot contain line breaks")
    return value


def _reachable(host: str, *, allow_private: bool, private_ok: tuple[str, ...], what: str) -> None:
    if allow_private:
        return
    try:
        assert_allowed_host(host, private_ok)
    except BlockedDestinationError as exc:
        raise ChannelConfigError(
            f"{what} must be on the public internet. A self-hosted instance on a private network has to be "
            "allowed by the server operator (ARGUS_INTEGRATION_ALLOWED_HOSTS)"
        ) from exc


def _origin(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{(parts.netloc or '').lower()}"


def _secret(
    config: dict[str, Any], key: str, label: str, url: str, current: dict[str, Any] | None, *, required: bool = True
) -> str:
    """A credential: new if given; otherwise kept, but only while the destination (scheme, host, port) is unchanged."""
    value = str(config.get(key) or "").strip()
    if value:
        if not _TOKEN.match(value):
            raise ChannelConfigError(f"The {label} doesn't look right (no spaces, at least 8 characters)")
        return value
    if current and current.get(key) and _origin(str(current.get("url", ""))) == _origin(url):
        return str(current[key])
    if not required:
        return ""
    if current and current.get(key):
        raise ChannelConfigError(f"Re-enter the {label}: the destination changed, so the saved one is not reused")
    raise ChannelConfigError(f"Enter the {label}")


def _base_url(config: dict[str, Any], *, allow_private: bool) -> tuple[str, str]:
    url, host = _check_url(str(config.get("url") or ""), allow_private=allow_private)
    parts = urlsplit(url)
    if parts.query or parts.fragment:
        raise ChannelConfigError("Enter the site address only, without ?query or #fragment")
    return f"{parts.scheme}://{parts.netloc}{parts.path.rstrip('/')}", host


def _integration(
    channel_type: str,
    config: dict[str, Any],
    *,
    allow_private: bool,
    private_ok: tuple[str, ...],
    current: dict[str, Any] | None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if channel_type == "sentinel":
        dce, host = _base_url({"url": config.get("dce_url") or config.get("url")}, allow_private=allow_private)
        cloud = next((v for k, v in SENTINEL_CLOUDS.items() if host.endswith(k)), None)
        if cloud is None or urlsplit(dce).path:
            raise ChannelConfigError(
                "Use the data collection endpoint's Logs Ingestion URL (https://<name>.<region>.ingest.monitor.azure.com)"
            )
        tenant, client = _text(config, "tenant_id", 253), _text(config, "client_id", 64)
        if not (_GUID.match(tenant) or _TENANT_DOMAIN.match(tenant)):
            raise ChannelConfigError("The tenant ID should be a GUID (or the tenant's domain)")
        if not _GUID.match(client):
            raise ChannelConfigError("The application (client) ID should be a GUID")
        dcr, stream = _text(config, "dcr_id", 64), _text(config, "stream", 120) or "Custom-ArgusEvents_CL"
        if not _DCR_ID.match(dcr):
            raise ChannelConfigError("The DCR immutable ID looks like dcr-0123456789abcdef0123456789abcdef")
        if not _STREAM.match(stream):
            raise ChannelConfigError("The stream name looks like Custom-ArgusEvents_CL")
        secret = _secret(config, "client_secret", "client secret", dce, current)
        public: dict[str, Any] = {"destination": dce, "host": host, "tenant_id": tenant, "client_id": client, "dcr_id": dcr,
                  "stream": stream}  # fmt: skip
        return public, {**public, "url": dce, "authority": cloud[0], "scope": cloud[1], "client_secret": secret}

    url, host = _base_url(config, allow_private=allow_private)
    if channel_type == "jira":
        _reachable(host, allow_private=allow_private, private_ok=private_ok, what="Jira")
        project = _text(config, "project_key", 16).upper()
        if not _JIRA_PROJECT.match(project):
            raise ChannelConfigError("Enter the Jira project key, e.g. SEC")
        issue_type = _text(config, "issue_type", 64) or "Task"
        email = _text(config, "email", 254).lower()
        if email and not _EMAIL.match(email):
            raise ChannelConfigError("Enter the email address of the Jira account the API token belongs to")
        token = _secret(config, "api_token", "API token", url, current)
        public = {"destination": url, "host": host, "project_key": project, "issue_type": issue_type,
                  "auth": f"API token of {email}" if email else "Personal access token",
                  "cloud": host.endswith(".atlassian.net")}  # fmt: skip
        return public, {**public, "url": url, "email": email, "api_token": token}
    if channel_type == "servicenow":
        _reachable(host, allow_private=allow_private, private_ok=private_ok, what="ServiceNow")
        username = _text(config, "username", 128)
        if not username:
            raise ChannelConfigError("Enter the ServiceNow integration user's name")
        group = _text(config, "assignment_group", 100)
        password = _secret(config, "password", "password", url, current)
        public = {"destination": url, "host": host, "username": username, "assignment_group": group}
        return public, {**public, "url": url, "password": password}
    if channel_type == "splunk":
        _reachable(host, allow_private=allow_private, private_ok=private_ok, what="Splunk")
        url = url.removesuffix(SPLUNK_PATH).removesuffix("/services/collector")
        index, sourcetype = _text(config, "index", 80), _text(config, "sourcetype", 100) or "argus:event"
        if index and not _SPLUNK_INDEX.match(index):
            raise ChannelConfigError("Splunk index names use lowercase letters, digits, - and _")
        if not _SOURCETYPE.match(sourcetype):
            raise ChannelConfigError("The sourcetype may contain letters, digits and : . _ -")
        token = _secret(config, "token", "HEC token", url, current)
        public = {"destination": url, "host": host, "index": index, "sourcetype": sourcetype}
        return public, {**public, "url": url, "token": token}
    raise ChannelConfigError(f"Unknown channel type {channel_type!r}")


def validate(
    channel_type: str,
    config: dict[str, Any],
    *,
    allow_private: bool,
    private_ok: tuple[str, ...] | list[str] = (),
    current: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return (public settings to store in clear, secrets to encrypt).

    ``current`` holds the channel's present secrets when it is being edited, so credentials can
    be kept without being re-typed (as long as the destination host stays the same).
    """
    private_ok = tuple(private_ok)
    if channel_type in INTEGRATIONS:
        return _integration(channel_type, config, allow_private=allow_private, private_ok=private_ok, current=current)
    if channel_type == "email":
        raw = config.get("recipients") or []
        if isinstance(raw, str):
            raw = re.split(r"[,;\s]+", raw)
        recipients = sorted({str(r).strip().lower() for r in raw if str(r).strip()})
        if not recipients:
            raise ChannelConfigError("Add at least one recipient")
        if len(recipients) > MAX_RECIPIENTS:
            raise ChannelConfigError(f"At most {MAX_RECIPIENTS} recipients per channel")
        bad = [r for r in recipients if not _EMAIL.match(r)]
        if bad:
            raise ChannelConfigError(f"Not a valid email address: {bad[0]}")
        return {"recipients": recipients}, {}

    url, host = _check_url(str(config.get("url") or ""), allow_private=allow_private)
    if channel_type == "slack":
        if host not in SLACK_HOSTS or not urlsplit(url).path.startswith(("/services/", "/triggers/")):
            raise ChannelConfigError("Use a Slack incoming-webhook URL (https://hooks.slack.com/services/…)")
    elif channel_type == "teams":
        if not host.endswith(TEAMS_HOST_SUFFIXES):
            raise ChannelConfigError(
                "Use a Microsoft Teams Workflows webhook URL (…logic.azure.com or …powerplatform.com)"
            )
    elif channel_type == "webhook":
        if not allow_private:
            try:
                assert_allowed_host(host, private_ok)
            except BlockedDestinationError as exc:
                raise ChannelConfigError("Webhooks can only be sent to public internet addresses") from exc
    else:
        raise ChannelConfigError(f"Unknown channel type {channel_type!r}")
    return {"destination": mask(url), "host": host}, {"url": url}
