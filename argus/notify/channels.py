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
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

from argus.security.network import BlockedDestinationError, assert_public_host

TYPES = ("slack", "teams", "webhook", "email")
SEVERITIES = ("low", "medium", "high", "critical")
SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
MAX_RECIPIENTS = 20
SLACK_HOSTS = {"hooks.slack.com"}
# Teams "Workflows" (Power Automate) webhooks, and the older Office 365 connector URLs.
TEAMS_HOST_SUFFIXES = (".logic.azure.com", ".api.powerplatform.com", ".webhook.office.com")
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


def validate(
    channel_type: str, config: dict[str, Any], *, allow_private: bool
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return (public settings to store in clear, secrets to encrypt)."""
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
                assert_public_host(host)
            except BlockedDestinationError as exc:
                raise ChannelConfigError("Webhooks can only be sent to public internet addresses") from exc
    else:
        raise ChannelConfigError(f"Unknown channel type {channel_type!r}")
    return {"destination": mask(url), "host": host}, {"url": url}
