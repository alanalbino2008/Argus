"""Signed case reports: anyone can check that a report is genuine and unaltered, without Argus.

Each installation has a **report-signing key** (Ed25519). It is created on first use and kept in the
database, sealed with the server's encryption key, or given explicitly with
``ARGUS_REPORT_SIGNING_KEY`` (so that several replicas, or a rebuilt server, sign with the same key).

**What is signed.** The report stays one HTML file. It carries two ``<meta>`` tags:

* ``argus-signing-key``: the public key (base64), part of the signed content;
* ``argus-signature``: ``ed25519:<key id>:<signature>``.

The signature covers ``argus-case-report/v1\\n`` followed by the SHA-256 of the whole document
*with the signature tag's content empty*. To verify, blank that one attribute, hash, and check the
signature with the public key. A changed character anywhere (a name, a date, a hash) fails.

**Whose key.** The embedded public key proves the file was not altered after signing. That *your*
organisation signed it is shown by the key id matching the one the organisation publishes
(``GET /api/report-signing-key``, the Settings page, or a key passed to the verifier).
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import logging
import re
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

logger = logging.getLogger("argus.report_signing")
STATE_KEY = "report_signing_key"
CONTEXT = "report-signing-key"
PREFIX = b"argus-case-report/v1\n"
SIGNATURE_TAG = '<meta name="argus-signature" content="{}">'
KEY_TAG = '<meta name="argus-signing-key" content="{}">'
SIGNATURE_RE = re.compile(r'<meta name="argus-signature" content="([^"]*)">')
KEY_RE = re.compile(r'<meta name="argus-signing-key" content="([A-Za-z0-9+/=]*)">')


class SigningError(ValueError):
    pass


def _raw(public: Ed25519PublicKey) -> bytes:
    return public.public_bytes(Encoding.Raw, PublicFormat.Raw)


def key_id(public_b64: str) -> str:
    """A short, readable fingerprint of a public key: 16 hex digits in groups of four."""
    digest = hashlib.sha256(base64.b64decode(public_b64)).hexdigest()[:16]
    return "-".join(digest[i : i + 4] for i in range(0, 16, 4))


def _public(public_b64: str) -> Ed25519PublicKey:
    try:
        raw = base64.b64decode(public_b64.strip(), validate=True)
        return Ed25519PublicKey.from_public_bytes(raw)
    except (binascii.Error, ValueError) as exc:
        raise SigningError("Not an Ed25519 public key") from exc


def _private(private_b64: str) -> Ed25519PrivateKey:
    try:
        return Ed25519PrivateKey.from_private_bytes(base64.b64decode(private_b64.strip(), validate=True))
    except (binascii.Error, ValueError) as exc:
        raise SigningError("ARGUS_REPORT_SIGNING_KEY is not a base64 Ed25519 private key (32 bytes)") from exc


def _message(unsigned: bytes) -> bytes:
    return PREFIX + hashlib.sha256(unsigned).digest()


@dataclass(frozen=True)
class ReportSigner:
    private: Ed25519PrivateKey
    public_key: str  # base64
    key_id: str
    source: str  # "settings" or "generated"

    def info(self) -> dict[str, Any]:
        return {"algorithm": "Ed25519", "public_key": self.public_key, "key_id": self.key_id, "source": self.source}

    def tags(self) -> str:
        """The two tags a report must carry (unsigned): put them in its ``<head>`` before signing."""
        return KEY_TAG.format(self.public_key) + SIGNATURE_TAG.format("")

    def sign(self, html: str) -> str:
        if html.count(SIGNATURE_TAG.format("")) != 1 or KEY_TAG.format(self.public_key) not in html:
            raise SigningError("The report does not carry the signing tags exactly once")
        signature = self.private.sign(_message(html.encode()))
        value = f"ed25519:{self.key_id}:{base64.b64encode(signature).decode()}"
        return html.replace(SIGNATURE_TAG.format(""), SIGNATURE_TAG.format(value), 1)


def from_private(private_b64: str, source: str) -> ReportSigner:
    private = _private(private_b64)
    public_b64 = base64.b64encode(_raw(private.public_key())).decode()
    return ReportSigner(private, public_b64, key_id(public_b64), source)


def new_private_key() -> str:
    from cryptography.hazmat.primitives.serialization import NoEncryption, PrivateFormat

    raw = Ed25519PrivateKey.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    return base64.b64encode(raw).decode()


_lock = asyncio.Lock()


async def signer_for(app_state: Any, box: Any, settings: Any) -> ReportSigner:
    """This installation's signer: from settings, from the database, or created now (once)."""
    configured = getattr(settings, "report_signing_key", None)
    if configured is not None and configured.get_secret_value().strip():
        return from_private(configured.get_secret_value(), "settings")
    async with _lock:
        stored = await app_state.get(STATE_KEY)
        if not stored:
            private = new_private_key()
            sealed = box.seal({"private": private}, CONTEXT) if box.available else None
            await app_state.set(STATE_KEY, {"sealed": sealed} if sealed else {"private": private})
            if not box.available:
                logger.warning("The report-signing key is stored unsealed: set ARGUS_ENCRYPTION_KEY to seal it")
            stored = await app_state.get(STATE_KEY)  # another replica may have written first: use what is stored
        if stored and stored.get("sealed"):
            private = box.open(stored["sealed"], CONTEXT)["private"]
        elif stored and stored.get("private"):
            private = stored["private"]
        else:
            raise SigningError("The report-signing key could not be read")
        return from_private(private, "generated")


def verify(data: bytes, trusted_key: str | None = None) -> dict[str, Any]:
    """Check a signed report. ``valid``: unaltered since it was signed by the key it carries;
    ``trusted``: that key is ``trusted_key`` (None when no key was given to compare with)."""
    sha256 = hashlib.sha256(data).hexdigest()
    try:
        html = data.decode("utf-8")
    except UnicodeDecodeError:
        return {"valid": False, "trusted": None, "sha256": sha256, "problem": "Not a text (HTML) file"}
    signatures, keys = SIGNATURE_RE.findall(html), KEY_RE.findall(html)
    if len(signatures) != 1 or len(keys) != 1 or not signatures[0]:
        return {"valid": False, "trusted": None, "sha256": sha256,
                "problem": "Not a signed Argus report (no single signature and key)"}  # fmt: skip
    parts = signatures[0].split(":")
    if len(parts) != 3 or parts[0] != "ed25519":
        return {"valid": False, "trusted": None, "sha256": sha256, "problem": "Unknown signature format"}
    try:
        public = _public(keys[0])
        signature = base64.b64decode(parts[2], validate=True)
    except (SigningError, binascii.Error) as exc:
        return {"valid": False, "trusted": None, "sha256": sha256, "problem": str(exc)}
    embedded_id = key_id(keys[0])
    unsigned = html.replace(SIGNATURE_TAG.format(signatures[0]), SIGNATURE_TAG.format(""), 1).encode()
    result: dict[str, Any] = {"sha256": sha256, "key_id": embedded_id, "public_key": keys[0]}
    if parts[1] != embedded_id:
        return {**result, "valid": False, "trusted": None, "problem": "The signature names a different key"}
    try:
        public.verify(signature, _message(unsigned))
    except InvalidSignature:
        return {**result, "valid": False, "trusted": None,
                "problem": "The report was changed after it was signed (or the signature is not its own)"}  # fmt: skip
    trusted = None
    if trusted_key:
        try:
            trusted = _raw(_public(trusted_key)) == _raw(public)
        except SigningError:
            trusted = key_id(keys[0]).replace("-", "") == trusted_key.strip().replace("-", "").lower()
    return {**result, "valid": True, "trusted": trusted, "problem": None}
