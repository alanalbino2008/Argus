"""Sending: HTTPS webhooks (SSRF-guarded) and SMTP email.

Every attempt ends in a :class:`Result` that says whether trying again could help:

* 2xx -> delivered;
* timeouts, connection errors, 408, 425, 429 and 5xx -> retry later (honouring ``Retry-After``);
* any other 4xx, redirects, blocked destinations -> give up: the URL is wrong or revoked,
  and hammering it would not change that.

Response bodies are never stored or shown: a webhook must not become a way to read pages
from servers Argus can reach. Error messages name only the host, never the URL, whose path
is the secret for Slack and Teams.
"""

from __future__ import annotations

import asyncio
import smtplib
import ssl
from dataclasses import dataclass
from email.message import EmailMessage
from urllib.parse import urlsplit

import aiohttp

from argus.core.settings import Settings
from argus.security.network import BlockedDestinationError, GuardedResolver, assert_public_host, configured_proxy_hosts

USER_AGENT = "Argus-Notifications/1 (+https://github.com/alanalbino2008/Argus)"
RETRYABLE_STATUS = {408, 425, 429, 500, 502, 503, 504}
MAX_RETRY_AFTER = 3600.0


@dataclass(frozen=True)
class Result:
    ok: bool
    retryable: bool = False
    status_code: int | None = None
    error: str | None = None
    retry_after: float | None = None


def _retry_after(value: str | None) -> float | None:
    try:
        return min(MAX_RETRY_AFTER, max(0.0, float(value))) if value else None
    except ValueError:
        return None  # HTTP-date form: fall back to our own backoff


def _blocked(exc: BaseException) -> bool:
    return isinstance(exc, BlockedDestinationError) or isinstance(
        getattr(exc, "os_error", None), BlockedDestinationError
    )


class Transport:
    def __init__(self, settings: Settings):
        self.settings = settings
        self._session: aiohttp.ClientSession | None = None

    def _http(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            resolver = (
                None if self.settings.allow_private_targets else GuardedResolver(trusted_hosts=configured_proxy_hosts())
            )
            self._session = aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(limit=20, ttl_dns_cache=60, resolver=resolver),
                timeout=aiohttp.ClientTimeout(total=self.settings.notify_timeout_seconds),
                trust_env=True,
                headers={"User-Agent": USER_AGENT},
            )
        return self._session

    async def close(self) -> None:
        if self._session is not None:
            await self._session.close()

    async def post(self, url: str, body: bytes, headers: dict[str, str]) -> Result:
        host = urlsplit(url).hostname or "?"
        try:
            if not self.settings.allow_private_targets:
                assert_public_host(host)
            async with self._http().post(
                url, data=body, headers={"Content-Type": "application/json", **headers}, allow_redirects=False
            ) as resp:
                status = resp.status
                retry_after = _retry_after(resp.headers.get("Retry-After"))
        except asyncio.TimeoutError:
            return Result(
                False, True, error=f"Timed out after {self.settings.notify_timeout_seconds:g}s waiting for {host}"
            )
        except Exception as exc:
            if _blocked(exc):
                return Result(False, False, error=f"Blocked: {host} is not a public internet address")
            if isinstance(exc, aiohttp.ClientError | OSError):
                return Result(False, True, error=f"Could not connect to {host} ({type(exc).__name__})")
            raise
        if 200 <= status < 300:
            return Result(True, status_code=status)
        if 300 <= status < 400:
            return Result(
                False, False, status, f"{host} answered with a redirect (HTTP {status}); redirects are not followed"
            )
        if status in RETRYABLE_STATUS:
            return Result(False, True, status, f"{host} answered HTTP {status}", retry_after)
        hint = " (the webhook was probably deleted or revoked)" if status in (403, 404, 410) else ""
        return Result(False, False, status, f"{host} refused the notification: HTTP {status}{hint}")

    # ------------------------------------------------------------------ email
    @property
    def email_available(self) -> bool:
        return bool(self.settings.smtp_host)

    def _send_mail(self, message: EmailMessage) -> None:
        s = self.settings
        if not s.smtp_host:
            raise smtplib.SMTPException("email is not configured")
        context = ssl.create_default_context()
        timeout = s.notify_timeout_seconds + 5
        server: smtplib.SMTP
        if s.smtp_security == "tls":
            server = smtplib.SMTP_SSL(s.smtp_host, s.smtp_port, timeout=timeout, context=context)
        else:
            server = smtplib.SMTP(s.smtp_host, s.smtp_port, timeout=timeout)
        with server:
            if s.smtp_security == "starttls":
                server.starttls(context=context)
            if s.smtp_username:
                server.login(s.smtp_username, s.smtp_password.get_secret_value() if s.smtp_password else "")
            server.send_message(message)

    async def send_email(self, message: EmailMessage) -> Result:
        try:
            await asyncio.to_thread(self._send_mail, message)
        except smtplib.SMTPRecipientsRefused:
            return Result(False, False, error="The mail server refused every recipient")
        except smtplib.SMTPAuthenticationError:
            return Result(False, True, error="The mail server rejected Argus's SMTP credentials")
        except smtplib.SMTPResponseException as exc:
            return Result(False, exc.smtp_code < 500, exc.smtp_code, f"Mail server answered {exc.smtp_code}")
        except (smtplib.SMTPException, OSError) as exc:
            return Result(False, True, error=f"Could not reach the mail server ({type(exc).__name__})")
        return Result(True)
