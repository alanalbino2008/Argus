"""The owner of an Argus server: the one person who can open the owner console.

* **Exactly one owner, ever.** The owner's email is fixed by the deployment
  (``ARGUS_OWNER_EMAIL``). Setting up the owner also needs an administrator API key of this
  server (the bootstrap key), which proves the person setting up controls the server. Once the
  owner exists, set-up is closed for good.
* **Two factors.** A password (12+ characters, not a common one) and a 6-digit code from an
  authenticator app. Ten one-time recovery codes cover a lost phone.
* **Hard to attack.** Five wrong passwords or codes lock the console for 15 minutes and email the
  owner. Every sign-in emails the owner. No code works twice. Sessions end after 8 hours, or 30
  minutes without use, and changing anything sensitive asks for a fresh code.
* **Separate from everything else.** API keys, workspace users and single sign-on can't open the
  console: only the owner's own session can.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import secrets
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from typing import Any
from urllib.parse import urlsplit

from argus.core.settings import Settings
from argus.security.crypto import SecretBox, _key_from_file

logger = logging.getLogger(__name__)
TOTP_CONTEXT = "owner-totp"
RECOVERY_CODES = 10


def box(settings: Settings) -> SecretBox:
    """Encryption for owner secrets: the server's encryption key, else one derived from its licence key."""
    current = settings.encryption_key.get_secret_value() if settings.encryption_key else None
    if not current and settings.encryption_key_file:
        current = _key_from_file(settings.encryption_key_file)
    signing = settings.licence_signing_key.get_secret_value() if settings.licence_signing_key else ""
    derived = f"argus-owner:{signing}" if signing else ""
    if current:
        return SecretBox(current, [derived] if derived else [])
    return SecretBox(derived or None)


def new_recovery_codes() -> list[str]:
    alphabet = "abcdefghjkmnpqrstuvwxyz23456789"  # no look-alikes (0/o, 1/l/i)
    return [
        "-".join("".join(secrets.choice(alphabet) for _ in range(5)) for _ in range(2)) for _ in range(RECOVERY_CODES)
    ]


def recovery_hash(code: str) -> str:
    return hashlib.sha256(("argus-recovery:" + code.strip().lower().replace(" ", "")).encode()).hexdigest()


async def alert(app: Any, owner_email: str, subject: str, lines: list[str]) -> None:
    """Email the owner straight away (sign-ins, lock-outs, changes). Best effort: never blocks a sign-in."""
    settings = app.state.settings
    if not settings.smtp_host or not owner_email:
        return
    msg = EmailMessage()
    msg["From"] = settings.account_email_from or settings.smtp_from
    msg["To"], msg["Subject"] = owner_email, f"[Argus owner] {subject}"
    msg["Date"] = formatdate(localtime=False)
    msg["Message-ID"] = make_msgid(
        domain=urlsplit(settings.public_url or "http://argus.local").hostname or "argus.local"
    )
    msg["Auto-Submitted"] = "auto-generated"
    msg.set_content("\n\n".join([*lines, "If this wasn't you, sign in to the owner console straight away, change "
                                 "your password and sign out every other session."]))  # fmt: skip

    async def send() -> None:
        try:
            result = await app.state.mailer.transport.send_email(msg)
            if not result.ok:
                logger.warning("Owner alert not sent: %s", result.error)
        except Exception:
            logger.exception("Owner alert failed")

    asyncio.get_running_loop().create_task(send())
