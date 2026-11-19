"""Sending account emails (account service): queue, send once, retry, and the trial reminders.

Emails go into an outbox first, keyed so the same email is never queued twice (Stripe re-sending
an event, two servers sweeping at once...). A background loop sends what is due through the SMTP
server already configured for Argus notifications, retrying for about half a day if the mail
server is down, and once an hour queues the trial reminders that have fallen due.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from typing import Any
from urllib.parse import urlencode, urlsplit

from argus.accounts import emails
from argus.core.settings import Settings
from argus.notify.transport import Transport

logger = logging.getLogger(__name__)
SWEEP_EVERY = timedelta(hours=1)


class AccountMailer:
    def __init__(self, mail: Any, subscribers: Any, settings: Settings, transport: Transport | None = None):
        self.mail, self.subscribers, self.settings = mail, subscribers, settings
        self.transport = transport or Transport(settings)
        self._wake = asyncio.Event()
        self._last_sweep: datetime | None = None

    @property
    def enabled(self) -> bool:
        s = self.settings
        return bool(s.account_service_enabled and s.account_emails_enabled and s.smtp_host)

    def _secret(self) -> str:
        key = self.settings.licence_signing_key
        return key.get_secret_value() if key else ""

    def base_url(self) -> str:
        return (self.settings.public_url or "").rstrip("/")

    def unsubscribe_url(self, account_id: str) -> str:
        query = urlencode({"a": account_id, "t": emails.unsubscribe_token(self._secret(), account_id)})
        return f"{self.base_url()}/api/accounts/emails/unsubscribe?{query}"

    async def notify(self, account: dict[str, Any], kind: str, key: str, **ctx: Any) -> bool:
        """Queue one email for an account; False if emails are off, unwanted, or it was already queued."""
        if not self.enabled or not account.get("email"):
            return False
        reminder = kind in emails.REMINDERS
        if reminder and not await self.mail.wants_reminders(account["id"]):
            return False
        subject, text, html = emails.render(kind, account, support=self.settings.support_email,
                                            unsubscribe=self.unsubscribe_url(account["id"]) if reminder else "",
                                            **ctx)  # fmt: skip
        queued = await self.mail.enqueue(account_id=account["id"], kind=kind, key=f"{kind}:{account['id']}:{key}",
                                         to=account["email"], subject=subject, text=text, html=html)  # fmt: skip
        if queued:
            self._wake.set()
        return bool(queued)

    # ------------------------------------------------------------------ sending
    def _message(self, email: dict[str, Any]) -> EmailMessage:
        sender = self.settings.account_email_from or self.settings.smtp_from
        msg = EmailMessage()
        msg["From"], msg["To"], msg["Subject"] = sender, email["to"], email["subject"]
        msg["Date"] = formatdate(localtime=False)
        msg["Message-ID"] = make_msgid(domain=urlsplit(self.base_url()).hostname or "argus.local")
        msg["Auto-Submitted"] = "auto-generated"
        if self.settings.support_email:
            msg["Reply-To"] = self.settings.support_email
        if email["kind"] in emails.REMINDERS:
            msg["List-Unsubscribe"] = f"<{self.unsubscribe_url(email['account_id'])}>"
        msg.set_content(email["text"])
        if email["html"]:
            msg.add_alternative(email["html"], subtype="html")
        return msg

    async def send_due(self) -> int:
        """Send what is due; the number delivered."""
        delivered = 0
        for email in await self.mail.due():
            if not await self.mail.claim(email["id"], email["attempts"]):
                continue  # another server took it
            result = await self.transport.send_email(self._message(email))
            if result.ok:
                await self.mail.sent(email["id"])
                delivered += 1
            else:
                logger.warning("Account email %s (%s) not sent: %s", email["id"], email["kind"], result.error)
                await self.mail.failed(email["id"], result.error or "not sent", result.retryable)
        return delivered

    # ------------------------------------------------------------------ reminders
    async def sweep(self, now: datetime | None = None) -> int:
        """Queue trial reminders that have fallen due; the number queued."""
        now = now or datetime.now(timezone.utc)
        queued = 0
        for account in await self.subscribers.overview():
            until = account.get("until")
            if account["plan"] != "trial" or account["status"] != "trialing" or until is None:
                continue
            day = until.date().isoformat()
            if now < until <= now + timedelta(days=3):
                queued += await self.notify(account, "trial_ending", day)
            elif now - timedelta(days=7) <= until <= now:
                queued += await self.notify(account, "trial_ended", day)
        return queued

    async def tick(self, now: datetime | None = None) -> None:
        now = now or datetime.now(timezone.utc)
        if self._last_sweep is None or now - self._last_sweep >= SWEEP_EVERY:
            self._last_sweep = now
            await self.sweep(now)
        await self.send_due()

    async def run_forever(self, interval: float = 30.0) -> None:
        while True:
            try:
                await self.tick()
            except asyncio.CancelledError:
                raise
            except Exception:  # never let one bad email stop the others
                logger.exception("Account email loop failed; trying again shortly")
            self._wake.clear()
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(self._wake.wait(), timeout=interval)
