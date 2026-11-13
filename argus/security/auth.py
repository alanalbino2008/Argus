"""API-key authentication and role-based access control (RBAC).

Keys look like ``argus_<43 random url-safe chars>`` (256 bits of entropy).

Why SHA-256 and not bcrypt/argon2? Slow hashes exist to resist brute-forcing
*low-entropy* human passwords. A 256-bit random key cannot be brute-forced, so a
fast hash is the industry norm (GitHub and Stripe tokens work the same way) and
lets us look a key up by its hash with a single indexed query.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import secrets

KEY_PREFIX = "argus_"


class Role(str, Enum):
    VIEWER = "viewer"      # read investigations, graphs, exports
    ANALYST = "analyst"    # + launch and cancel scans
    ADMIN = "admin"        # + delete data, manage keys, read the audit log

    @property
    def rank(self) -> int:
        return {"viewer": 1, "analyst": 2, "admin": 3}[self.value]


@dataclass(frozen=True)
class Principal:
    """The authenticated caller of a request."""

    key_id: str
    name: str
    role: Role

    def has(self, required: Role) -> bool:
        return self.role.rank >= required.rank


ANONYMOUS_ADMIN = Principal(key_id="anonymous", name="anonymous (auth disabled)", role=Role.ADMIN)
SYSTEM = Principal(key_id="system", name="system", role=Role.ADMIN)


def generate_api_key() -> str:
    return KEY_PREFIX + secrets.token_urlsafe(32)


def hash_api_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def key_display_prefix(key: str) -> str:
    """Safe-to-show identifier, e.g. ``argus_Ab3d…`` (never enough to authenticate)."""
    return key[: len(KEY_PREFIX) + 4]
