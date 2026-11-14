"""Webhook signatures, compatible with the Standard Webhooks specification.

Every webhook Argus sends carries three headers:

* ``webhook-id``: the delivery id, unchanged across retries, so receivers can drop duplicates;
* ``webhook-timestamp``: Unix seconds, so receivers can refuse old (replayed) requests;
* ``webhook-signature``: ``v1,<base64 HMAC-SHA256(secret, "<id>.<timestamp>.<body>")>``.

While a secret is being rotated, the header holds two space-separated signatures (new and
previous), so receivers can switch at their own pace. Because the format is a published
standard, receivers can verify with the official ``standardwebhooks`` libraries or with the
few lines of :func:`verify`.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time
from collections.abc import Iterable

SECRET_PREFIX = "whsec_"  # noqa: S105 - a format prefix, not a secret
DEFAULT_TOLERANCE_SECONDS = 300


class SignatureError(Exception):
    pass


def new_secret() -> str:
    return SECRET_PREFIX + base64.b64encode(secrets.token_bytes(32)).decode()


def _key(secret: str) -> bytes:
    return base64.b64decode(secret.removeprefix(SECRET_PREFIX))


def _sign(secret: str, msg_id: str, timestamp: int, body: bytes) -> str:
    mac = hmac.new(_key(secret), f"{msg_id}.{timestamp}.".encode() + body, hashlib.sha256).digest()
    return "v1," + base64.b64encode(mac).decode()


def sign_headers(
    secrets_in_use: Iterable[str], msg_id: str, body: bytes, timestamp: int | None = None
) -> dict[str, str]:
    ts = int(time.time()) if timestamp is None else timestamp
    signatures = " ".join(_sign(s, msg_id, ts, body) for s in secrets_in_use if s)
    return {"webhook-id": msg_id, "webhook-timestamp": str(ts), "webhook-signature": signatures}


def verify(
    secret: str,
    headers: dict[str, str],
    body: bytes,
    tolerance: int = DEFAULT_TOLERANCE_SECONDS,
    now: int | None = None,
) -> None:
    """What a receiver does. Raises SignatureError unless the request is authentic and fresh."""
    lowered = {k.lower(): v for k, v in headers.items()}
    try:
        msg_id, ts = lowered["webhook-id"], int(lowered["webhook-timestamp"])
        offered = lowered["webhook-signature"].split()
    except (KeyError, ValueError) as exc:
        raise SignatureError("missing or malformed signature headers") from exc
    current = int(time.time()) if now is None else now
    if abs(current - ts) > tolerance:
        raise SignatureError("timestamp outside the tolerance window (replayed or clock skew)")
    expected = _sign(secret, msg_id, ts, body)
    if not any(hmac.compare_digest(expected, sig) for sig in offered):
        raise SignatureError("no valid signature")
