"""Authenticator-app codes (TOTP, RFC 6238): the second factor of the owner console.

The owner scans a QR code with an authenticator app (Google Authenticator, Microsoft
Authenticator, 1Password, Authy...). The app and Argus share a random secret and both turn the
current 30-second window into a 6-digit code. A code is accepted for its own window and the one
either side (clocks drift), and never twice (a code seen once can't be replayed).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote, urlencode

STEP = 30
DIGITS = 6


def new_secret() -> str:
    """A random 160-bit secret, in the base32 form authenticator apps expect."""
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _key(secret: str) -> bytes:
    clean = secret.strip().replace(" ", "").upper()
    return base64.b32decode(clean + "=" * (-len(clean) % 8))


def code_at(secret: str, counter: int) -> str:
    digest = hmac.new(_key(secret), struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10**DIGITS).zfill(DIGITS)


def now_counter(now: float | None = None) -> int:
    return int((time.time() if now is None else now) // STEP)


def verify(secret: str, code: str, *, last_counter: int = -1, now: float | None = None) -> int | None:
    """The time-step a code belongs to, if it is valid now and newer than ``last_counter``."""
    code = "".join(ch for ch in str(code) if ch.isdigit())
    if len(code) != DIGITS:
        return None
    current = now_counter(now)
    for counter in (current - 1, current, current + 1):
        if counter > last_counter and hmac.compare_digest(code_at(secret, counter), code):
            return counter
    return None


def provisioning_uri(secret: str, account: str, issuer: str = "Argus") -> str:
    label = quote(f"{issuer}:{account}")
    return f"otpauth://totp/{label}?" + urlencode({"secret": secret, "issuer": issuer, "digits": DIGITS,
                                                   "period": STEP, "algorithm": "SHA1"})  # fmt: skip


def qr_svg(text: str) -> str:
    """A QR code as a small SVG image (encoded with reportlab, which Argus already uses for PDFs)."""
    from reportlab.graphics.barcode.qr import QrCodeWidget

    qr = QrCodeWidget(text, barLevel="M").qr  # the widget picks the right QR size for the text
    qr.make()
    n, quiet = qr.getModuleCount(), 4
    cells = "".join(f"M{c + quiet},{r + quiet}h1v1h-1z" for r in range(n) for c in range(n) if qr.isDark(r, c))
    size = n + 2 * quiet
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {size} {size}" shape-rendering="crispEdges" '
        f'role="img" aria-label="QR code for your authenticator app"><rect width="{size}" height="{size}" '
        f'fill="#fff"/><path d="{cells}" fill="#000"/></svg>'
    )
