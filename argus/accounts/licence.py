"""Signed licences: how the personal edition knows its user has a current Argus subscription.

The Argus account service (run centrally by the operator) signs each licence with an **Ed25519**
private key. The personal edition holds only the matching *public* key, so it can check a
licence offline, but nobody can forge or edit one: changing a single character (a later expiry
date, a bigger plan) breaks the signature.

A licence says who it is for, which plan, the subscription's status, and three dates:

* ``valid_until``: the end of the paid (or trial) period. After it the app is read-only until the
  subscription is renewed;
* ``refresh_after``: when the app should ask the account service for a fresh licence (it renews
  quietly in the background);
* ``offline_until``: how long the app keeps working without reaching the account service
  (travel, poor connections). After it the app is read-only until it reconnects.

**Read-only, never locked out.** When a licence lapses, existing cases stay readable and
exportable: an investigator's evidence is never held hostage. Only new work (scans, captures,
watches, uploads) is blocked until the subscription is renewed.

Format: ``argus1.<base64url payload JSON>.<base64url signature>``, the signature covering the
first two parts.
"""

from __future__ import annotations

import base64
import binascii
import json
from datetime import datetime, timedelta, timezone
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

PREFIX = "argus1"
REFRESH_EVERY = timedelta(days=1)
FULL_STATUSES = {"trialing", "active", "past_due"}  # past_due: the payment is being retried; keep working

PRO_FEATURES = ["monitoring", "branded_reports", "playbooks"]
PLANS: dict[str, dict[str, Any]] = {
    # the trial shows everything an individual can buy, so people know what Professional offers
    "trial": {"label": "Free trial", "max_devices": 1, "monthly_credits": 50, "features": PRO_FEATURES},
    # every investigation tool, using the investigator's own API keys (or credit packs); the lowest price
    "byok": {"label": "Bring your own keys", "max_devices": 1, "monthly_credits": 0, "features": []},
    "personal": {"label": "Personal", "max_devices": 2, "monthly_credits": 500, "features": []},
    "professional": {"label": "Professional", "max_devices": 3, "monthly_credits": 2000, "features": PRO_FEATURES},
    # one owner pays per seat (and a one-off set-up fee); members have their own accounts; credits are shared
    "business": {
        "label": "Business",
        "max_devices": 2,
        "monthly_credits": 1000,
        "per_seat": True,
        "features": [*PRO_FEATURES, "team"],
    },
}
STATUSES = ("trialing", "active", "past_due", "cancelled", "suspended")


class LicenceError(Exception):
    """The licence is not genuine, is malformed, or belongs to another account service."""


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def generate_keypair() -> tuple[str, str]:
    """A new signing key pair as (private, public), each base64 of the raw 32 bytes."""
    private = Ed25519PrivateKey.generate()
    raw_private = private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    raw_public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(raw_private).decode(), base64.b64encode(raw_public).decode()


def load_private_key(text: str) -> Ed25519PrivateKey:
    try:
        return Ed25519PrivateKey.from_private_bytes(base64.b64decode(text.strip(), validate=True))
    except (ValueError, binascii.Error) as exc:
        raise LicenceError(
            "the licence signing key must be base64 of 32 bytes (argus --generate-licence-keys)"
        ) from exc


def load_public_key(text: str) -> Ed25519PublicKey:
    try:
        return Ed25519PublicKey.from_public_bytes(base64.b64decode(text.strip(), validate=True))
    except (ValueError, binascii.Error) as exc:
        raise LicenceError("the licence public key must be base64 of 32 bytes") from exc


def public_key_of(private: Ed25519PrivateKey) -> str:
    return base64.b64encode(private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()


def sign(payload: dict[str, Any], private: Ed25519PrivateKey) -> str:
    body = _b64(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
    signed = f"{PREFIX}.{body}"
    return f"{signed}.{_b64(private.sign(signed.encode()))}"


def verify(token: str, public: Ed25519PublicKey, *, issuer: str | None = None) -> dict[str, Any]:
    """The licence's contents, if (and only if) the signature is genuine."""
    try:
        prefix, body, signature = token.strip().split(".")
    except ValueError as exc:
        raise LicenceError("not an Argus licence") from exc
    if prefix != PREFIX:
        raise LicenceError("not an Argus licence (or a newer format)")
    try:
        public.verify(_unb64(signature), f"{prefix}.{body}".encode())
        payload = json.loads(_unb64(body))
    except (InvalidSignature, ValueError, binascii.Error) as exc:
        raise LicenceError("the licence's signature is not valid: it was altered or not issued by Argus") from exc
    if not isinstance(payload, dict) or payload.get("v") != 1:
        raise LicenceError("unsupported licence version")
    if issuer is not None and payload.get("iss") != issuer:
        raise LicenceError("the licence was issued by a different account service")
    return payload


def issue(account: dict[str, Any], *, device_id: str, issuer: str, private: Ed25519PrivateKey, offline_days: int,
          now: datetime | None = None) -> str:  # fmt: skip
    """A licence for ``account`` on one device."""
    now = now or datetime.now(timezone.utc)
    plan = PLANS.get(account["plan"], {"label": account["plan"]})
    payload = {
        "v": 1, "iss": issuer, "sub": account["id"], "email": account["email"], "name": account.get("name") or "",
        "plan": account["plan"], "plan_label": plan["label"], "status": account["status"],
        "features": list(plan.get("features", [])),
        "valid_until": account["valid_until"], "issued_at": now.isoformat(),
        "refresh_after": (now + REFRESH_EVERY).isoformat(),
        "offline_until": (now + timedelta(days=offline_days)).isoformat(), "device": device_id,
    }  # fmt: skip
    return sign(payload, private)


def _when(value: Any) -> datetime | None:
    try:
        moment = datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def access(payload: dict[str, Any] | None, now: datetime | None = None) -> tuple[str, str]:
    """What the licence allows now: ("full" | "read_only" | "none", the reason in plain words)."""
    if not payload:
        return "none", "Sign in with your Argus account to start."
    now = now or datetime.now(timezone.utc)
    valid_until, offline_until = _when(payload.get("valid_until")), _when(payload.get("offline_until"))
    if payload.get("status") not in FULL_STATUSES:
        return "read_only", (f"Your subscription is {payload.get('status')}. Your cases stay readable and exportable; "
                             "renew to add new work.")  # fmt: skip
    if valid_until is None or now >= valid_until:
        what = "free trial" if payload.get("plan") == "trial" else "subscription"
        return "read_only", (f"Your {what} ended on {valid_until:%d %B %Y}. " if valid_until else "") + (
            "Your cases stay readable and exportable; renew to add new work.")  # fmt: skip
    if offline_until is None or now >= offline_until:
        return "read_only", ("Argus has not been able to reach your account for too long. Connect to the internet "
                             "so it can renew your licence; until then your cases are read-only.")  # fmt: skip
    return "full", ""
