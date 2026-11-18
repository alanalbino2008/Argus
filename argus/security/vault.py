"""The case vault: an investigator's cases, evidence and scan results, encrypted with their passphrase.

A laptop can be lost, stolen or seized. Without the vault, anyone who copies Argus's database file
can read every case: the subjects, the notes, the sources, the captured pages. With the vault
turned on, the sensitive parts of the database are encrypted, and the key exists only in memory,
only while the vault is unlocked.

**How the keys work**

* A random 256-bit **data key** encrypts the data, with AES-256-GCM: each value gets its own
  random nonce, and is bound to the column it belongs to, so values cannot be swapped between
  columns.
* The data key is stored only **wrapped**: encrypted with a key derived from the investigator's
  **passphrase** (scrypt, deliberately slow and memory-hungry, so guessing passphrases is costly).
* It is wrapped a second time with a random **recovery code**, shown once when the vault is set
  up. If both the passphrase and the recovery code are lost, the data cannot be recovered by
  anyone, including Argus's makers. That is the point.
* Changing the passphrase re-wraps the data key; the data itself does not need re-encrypting.

**What is encrypted** (when the vault is on): case titles, purposes and summaries; notes,
entities, links and events; evidence (addresses, titles, notes, manifests, files, custody
details); watched accounts' profiles and history; playbook runs; scan targets and everything
scans found; the details of audit events; alerts; reports and their files; queued notifications.
Identifiers, dates, statuses, counts and kinds stay readable, so Argus can find and order things.

Encryption works field by field inside the database (the ``Encrypted*`` column types below), so
values written before the vault was turned on are read as they are and encrypted in one pass.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import time
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from sqlalchemy import JSON, LargeBinary, String, Text
from sqlalchemy.types import TypeDecorator

TEXT_PREFIX = "av1:"
BYTES_PREFIX = b"AV1\x00"
RECORD_KEY = "vault"
SCRYPT_N = 2**17  # 128 MiB of memory per attempt: slow for an attacker, under a second for the owner
SCRYPT_R, SCRYPT_P = 8, 1
MIN_PASSPHRASE = 12
WRAP_AAD = b"argus-vault-data-key-v1"


class VaultLocked(RuntimeError):
    """Encrypted data was needed while the vault is locked."""


class VaultError(ValueError):
    """A wrong passphrase or recovery code, or a vault that is not set up."""


@dataclass
class _State:
    enabled: bool = False  # a vault is set up on this installation
    key: bytes | None = None  # the data key, only while unlocked
    plain_writes: bool = False  # while turning the vault off: values are written back unencrypted
    record: dict[str, Any] = field(default_factory=dict)
    last_activity: float = field(default_factory=time.monotonic)
    failed_attempts: int = 0


STATE = _State()


def ready() -> bool:
    """Whether encrypted data can be read and written now (no vault, or an unlocked one)."""
    return not STATE.enabled or STATE.key is not None


def locked() -> bool:
    return STATE.enabled and STATE.key is None


def touch() -> None:
    STATE.last_activity = time.monotonic()


# ---------------------------------------------------------------------------- values
def _aesgcm() -> AESGCM:
    if STATE.key is None:
        raise VaultLocked("The case vault is locked")
    return AESGCM(STATE.key)


def seal(data: bytes, label: str) -> bytes:
    nonce = os.urandom(12)
    return nonce + _aesgcm().encrypt(nonce, data, label.encode())


def unseal(blob: bytes, label: str) -> bytes:
    try:
        return _aesgcm().decrypt(blob[:12], blob[12:], label.encode())
    except InvalidTag as exc:
        raise VaultError(f"Encrypted value in {label} could not be decrypted (damaged, or another vault's)") from exc


def _writing_encrypted() -> bool:
    if STATE.plain_writes or not STATE.enabled:
        return False
    if STATE.key is None:
        raise VaultLocked("The case vault is locked: nothing can be saved until it is unlocked")
    return True


def encrypt_text(value: str, label: str) -> str:
    return TEXT_PREFIX + base64.urlsafe_b64encode(seal(value.encode(), label)).decode()


def decrypt_text(value: str, label: str) -> str:
    return unseal(base64.urlsafe_b64decode(value[len(TEXT_PREFIX) :]), label).decode()


class EncryptedText(TypeDecorator[str]):
    """Text that is encrypted while the vault is on (plain text written earlier is read as it is)."""

    impl = String
    cache_ok = True

    def __init__(self, length: int | None = None, *, label: str):
        super().__init__(length)
        self.label = label

    def process_bind_param(self, value: Any, dialect: Any) -> Any:
        if value is None or not _writing_encrypted():
            return value
        return encrypt_text(str(value), self.label)

    def process_result_value(self, value: Any, dialect: Any) -> Any:
        if isinstance(value, str) and value.startswith(TEXT_PREFIX):
            return decrypt_text(value, self.label)
        return value


class EncryptedLongText(EncryptedText):
    impl = Text
    cache_ok = True


class EncryptedJSON(TypeDecorator[Any]):
    """A JSON value, stored as one encrypted JSON string while the vault is on."""

    impl = JSON
    cache_ok = True

    def __init__(self, *, label: str):
        super().__init__()
        self.label = label

    def process_bind_param(self, value: Any, dialect: Any) -> Any:
        if value is None or not _writing_encrypted():
            return value
        return encrypt_text(json.dumps(value, separators=(",", ":"), default=str), self.label)

    def process_result_value(self, value: Any, dialect: Any) -> Any:
        if isinstance(value, str) and value.startswith(TEXT_PREFIX):
            return json.loads(decrypt_text(value, self.label))
        return value


class EncryptedBytes(TypeDecorator[bytes]):
    impl = LargeBinary
    cache_ok = True

    def __init__(self, *, label: str):
        super().__init__()
        self.label = label

    def process_bind_param(self, value: Any, dialect: Any) -> Any:
        if value is None or not _writing_encrypted():
            return value
        return BYTES_PREFIX + seal(bytes(value), self.label)

    def process_result_value(self, value: Any, dialect: Any) -> Any:
        if isinstance(value, (bytes, bytearray, memoryview)) and bytes(value[:4]) == BYTES_PREFIX:
            return unseal(bytes(value)[4:], self.label)
        return value


ENCRYPTED_TYPES = (EncryptedText, EncryptedJSON, EncryptedBytes)


# ---------------------------------------------------------------------------- keys
def normalise(passphrase: str) -> bytes:
    return unicodedata.normalize("NFKC", passphrase).encode()


def check_passphrase(passphrase: str) -> None:
    if len(unicodedata.normalize("NFKC", passphrase).strip()) < MIN_PASSPHRASE:
        raise VaultError(f"Use a passphrase of at least {MIN_PASSPHRASE} characters: a short sentence works well")


def _kek(secret: bytes, salt: bytes, n: int) -> bytes:
    return Scrypt(salt=salt, length=32, n=n, r=SCRYPT_R, p=SCRYPT_P).derive(secret)


def _wrap(secret: bytes, data_key: bytes) -> dict[str, Any]:
    salt, nonce = os.urandom(16), os.urandom(12)
    wrapped = AESGCM(_kek(secret, salt, SCRYPT_N)).encrypt(nonce, data_key, WRAP_AAD)
    return {"salt": base64.b64encode(salt).decode(), "nonce": base64.b64encode(nonce).decode(),
            "wrapped": base64.b64encode(wrapped).decode(), "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P}  # fmt: skip


def _unwrap(secret: bytes, box: dict[str, Any]) -> bytes:
    kek = Scrypt(salt=base64.b64decode(box["salt"]), length=32, n=int(box["n"]), r=int(box["r"]),
                 p=int(box["p"])).derive(secret)  # fmt: skip
    try:
        return AESGCM(kek).decrypt(base64.b64decode(box["nonce"]), base64.b64decode(box["wrapped"]), WRAP_AAD)
    except InvalidTag as exc:
        raise VaultError("Wrong passphrase or recovery code") from exc


def new_recovery_code() -> str:
    """25 random characters in five groups (about 125 bits), easy to write down."""
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no 0/O or 1/I
    raw = "".join(secrets.choice(alphabet) for _ in range(25))
    return "-".join(raw[i : i + 5] for i in range(0, 25, 5))


def _recovery_secret(code: str) -> bytes:
    return "".join(c for c in code.upper() if c.isalnum()).encode()


def create(passphrase: str) -> tuple[dict[str, Any], str, bytes]:
    """A new vault: (the record to store, the recovery code to show once, the data key)."""
    check_passphrase(passphrase)
    data_key = os.urandom(32)
    code = new_recovery_code()
    record = {"version": 1, "passphrase": _wrap(normalise(passphrase), data_key),
              "recovery": _wrap(_recovery_secret(code), data_key), "state": "encrypting",
              "created_at": datetime.now(timezone.utc).isoformat()}  # fmt: skip
    return record, code, data_key


def open_with(record: dict[str, Any], *, passphrase: str | None = None, recovery_code: str | None = None) -> bytes:
    if passphrase:
        return _unwrap(normalise(passphrase), record["passphrase"])
    if recovery_code:
        return _unwrap(_recovery_secret(recovery_code), record["recovery"])
    raise VaultError("Give the passphrase or the recovery code")


def rewrap_passphrase(record: dict[str, Any], data_key: bytes, new_passphrase: str) -> dict[str, Any]:
    check_passphrase(new_passphrase)
    return {**record, "passphrase": _wrap(normalise(new_passphrase), data_key)}


def rewrap_recovery(record: dict[str, Any], data_key: bytes) -> tuple[dict[str, Any], str]:
    code = new_recovery_code()
    return {**record, "recovery": _wrap(_recovery_secret(code), data_key)}, code


def unlock_with(key: bytes) -> None:
    STATE.key = key
    STATE.failed_attempts = 0
    touch()


def lock() -> None:
    STATE.key = None  # Python cannot reliably wipe memory; the reference is dropped at once


def reset() -> None:
    """Forget everything (tests, and turning the vault off)."""
    STATE.enabled, STATE.key, STATE.plain_writes, STATE.record = False, None, False, {}
    STATE.failed_attempts = 0
