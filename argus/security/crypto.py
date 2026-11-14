"""Encryption at rest for secrets Argus must be able to read back.

Passwords and API keys are *hashed* (Argus only ever compares them). Some secrets have to
be used again, though: a Slack or Teams webhook URL is itself a credential (anyone holding
it can post to the channel), and a webhook signing secret is needed to sign every
delivery. Those are encrypted before they reach the database:

* **AES-256-GCM** (authenticated encryption): tampering with a stored value makes
  decryption fail instead of yielding attacker-chosen plaintext.
* The AES key is **derived with HKDF-SHA256** from the operator's ``ARGUS_ENCRYPTION_KEY``,
  so any long random string works and the raw setting is never used as a key directly.
* **Associated data binds each value to its row** (e.g. ``notification-channel:<workspace>:<id>``):
  copying an encrypted blob into another row or another workspace makes it undecryptable.
* **Key rotation**: every value records the id of the key that sealed it. Put the old key in
  ``ARGUS_ENCRYPTION_PREVIOUS_KEYS`` and set a new ``ARGUS_ENCRYPTION_KEY``; old values still
  open, and anything rewritten is sealed with the new key.

A database dump or backup therefore reveals no usable webhook URL or signing secret
without the key, which lives in a Kubernetes Secret (or a separate file), not the database.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import secrets
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from argus.core.settings import Settings

logger = logging.getLogger("argus.crypto")

FORMAT_VERSION = "v1"
MIN_KEY_LENGTH = 32
_HKDF_INFO = b"argus/secret-box/v1"


class SecretBoxError(Exception):
    """A value could not be sealed or opened (no key configured, wrong key, or tampered data)."""


def _derive(material: str) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_HKDF_INFO).derive(material.encode())


def _key_id(key: bytes) -> str:
    return hashlib.sha256(b"argus-key-id" + key).hexdigest()[:12]


class SecretBox:
    def __init__(self, current: str | None, previous: list[str] | tuple[str, ...] = ()):
        self._keys: dict[str, bytes] = {}
        self._current: str | None = None
        for material in previous:
            if material:
                key = _derive(material)
                self._keys[_key_id(key)] = key
        if current:
            key = _derive(current)
            self._current = _key_id(key)
            self._keys[self._current] = key

    @property
    def available(self) -> bool:
        return self._current is not None

    @property
    def key_id(self) -> str | None:
        return self._current

    def seal(self, value: dict[str, Any], context: str) -> str:
        if self._current is None:
            raise SecretBoxError("no encryption key is configured (set ARGUS_ENCRYPTION_KEY)")
        nonce = os.urandom(12)  # 96-bit random nonce, the GCM recommendation
        ciphertext = AESGCM(self._keys[self._current]).encrypt(
            nonce, json.dumps(value, separators=(",", ":")).encode(), context.encode()
        )
        blob = base64.urlsafe_b64encode(nonce + ciphertext).decode().rstrip("=")
        return f"{FORMAT_VERSION}:{self._current}:{blob}"

    def open(self, sealed: str, context: str) -> dict[str, Any]:
        try:
            version, kid, blob = sealed.split(":", 2)
        except ValueError as exc:
            raise SecretBoxError("not a sealed value") from exc
        if version != FORMAT_VERSION:
            raise SecretBoxError(f"unsupported format {version}")
        key = self._keys.get(kid)
        if key is None:
            raise SecretBoxError("sealed with a key that is not configured (rotated away?)")
        raw = base64.urlsafe_b64decode(blob + "=" * (-len(blob) % 4))
        try:
            plaintext = AESGCM(key).decrypt(raw[:12], raw[12:], context.encode())
        except InvalidTag as exc:
            raise SecretBoxError("integrity check failed (tampered, moved to another row, or wrong key)") from exc
        value: dict[str, Any] = json.loads(plaintext)
        return value

    def needs_rotation(self, sealed: str) -> bool:
        return self._current is not None and sealed.split(":", 2)[1:2] != [self._current]


def _key_from_file(path: str) -> str | None:
    """Read the key file, creating it (owner-only) on first start. For single-node installs."""
    file = Path(path)
    try:
        if not file.exists():
            file.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as fh:
                fh.write(secrets.token_urlsafe(48))
            logger.warning("Generated a new encryption key in %s - back it up with the database", file)
        value = file.read_text().strip()
    except OSError as exc:
        logger.error("Cannot use encryption key file %s: %s", file, exc)
        return None
    return value if len(value) >= MIN_KEY_LENGTH else None


def secret_box_from_settings(settings: Settings) -> SecretBox:
    current = settings.encryption_key.get_secret_value() if settings.encryption_key else None
    if not current and settings.encryption_key_file:
        current = _key_from_file(settings.encryption_key_file)
    previous = [k.get_secret_value() for k in settings.encryption_previous_keys]
    box = SecretBox(current, previous)
    if not box.available:
        logger.warning(
            "No encryption key configured: Slack, Teams and webhook notifications are unavailable "
            "(set ARGUS_ENCRYPTION_KEY to a random string of at least %d characters)",
            MIN_KEY_LENGTH,
        )
    return box
