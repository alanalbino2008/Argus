"""Password storage for Argus accounts: scrypt, a memory-hard hash that is slow to brute-force.

Each password gets its own random salt, so equal passwords look different and precomputed tables
are useless. Verification compares in constant time. Parameters are stored with each hash, so
they can be raised later without breaking existing accounts.
"""

from __future__ import annotations

import base64
import hmac
import secrets

from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

N, R, P = 2**15, 8, 1  # about 32 MB and a few tens of milliseconds per hash
MIN_LENGTH = 10


def _kdf(salt: bytes, n: int, r: int, p: int) -> Scrypt:
    return Scrypt(salt=salt, length=32, n=n, r=r, p=p)


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = _kdf(salt, N, R, P).derive(password.encode())
    return f"scrypt${N}${R}${P}${base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt, digest = stored.split("$")
        if scheme != "scrypt":
            return False
        _kdf(base64.b64decode(salt), int(n), int(r), int(p)).verify(password.encode(), base64.b64decode(digest))
    except (ValueError, InvalidKey):
        return False
    return True


# A precomputed hash to check against when the email is unknown, so the response takes as long
# whether or not an account exists (no account enumeration by timing).
DUMMY_HASH = hash_password(secrets.token_urlsafe(16))


def weakness(password: str, email: str) -> str | None:
    """Why a new password is unacceptable, or None."""
    if len(password) < MIN_LENGTH:
        return f"Use at least {MIN_LENGTH} characters."
    if password.lower() in {email.lower(), email.split("@")[0].lower()}:
        return "Don't use your email address as your password."
    if len(set(password)) < 4:
        return "That password is too easy to guess."
    if password.lower() in {"password123", "1234567890", "qwertyuiop", "argusargus", "letmein123", "iloveyou12"}:
        return "That password is one of the most common ones: choose another."
    return None


def same(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())
