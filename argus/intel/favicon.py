"""Favicon fingerprints: the hashes internet-scan engines index favicons by.

A site's favicon is a surprisingly durable fingerprint. The same icon on two hosts usually means
the same operator, the same product (a VPN appliance's login page, a CI server) or the same
phishing kit, and the scan engines let anyone search by it:

* **Shodan** ``http.favicon.hash:<mmh3>``; **FOFA** ``icon_hash="<mmh3>"``;
  **ZoomEye** ``iconhash:"<mmh3>"``. All three use the *Shodan hash*: MurmurHash3 (x86, 32-bit,
  seed 0, signed) of the icon's **base64 text with a newline every 76 characters**
  (Python's ``base64.encodebytes``).
* **Censys** ``services.http.response.favicons.md5_hash:<md5>``.

MurmurHash3 is implemented here in pure Python (checked against the reference vectors in the
tests), so no compiled dependency is needed.
"""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass
from typing import Any

MAX_ICON_BYTES = 256 * 1024

_C1 = 0xCC9E2D51
_C2 = 0x1B873593
_MASK = 0xFFFFFFFF


def _rotl(x: int, r: int) -> int:
    return ((x << r) | (x >> (32 - r))) & _MASK


def murmur3_32(data: bytes, seed: int = 0) -> int:
    """MurmurHash3 x86 32-bit, as a *signed* integer (what ``mmh3.hash`` returns)."""
    length = len(data)
    h = seed & _MASK
    blocks = length // 4
    for i in range(blocks):
        k = int.from_bytes(data[i * 4 : i * 4 + 4], "little")
        k = (k * _C1) & _MASK
        k = _rotl(k, 15)
        k = (k * _C2) & _MASK
        h ^= k
        h = _rotl(h, 13)
        h = (h * 5 + 0xE6546B64) & _MASK
    tail = data[blocks * 4 :]
    k = 0
    if len(tail) >= 3:
        k ^= tail[2] << 16
    if len(tail) >= 2:
        k ^= tail[1] << 8
    if tail:
        k ^= tail[0]
        k = (k * _C1) & _MASK
        k = _rotl(k, 15)
        k = (k * _C2) & _MASK
        h ^= k
    h ^= length
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & _MASK
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & _MASK
    h ^= h >> 16
    return h - (1 << 32) if h & 0x80000000 else h


def shodan_hash(icon: bytes) -> int:
    """The favicon hash Shodan, FOFA and ZoomEye index (base64 with MIME line breaks, then mmh3)."""
    return murmur3_32(base64.encodebytes(icon))


_SIGNATURES = (
    (b"\x00\x00\x01\x00", "image/x-icon"),
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"BM", "image/bmp"),
)


def sniff_image(data: bytes) -> str | None:
    """The image type from the bytes themselves, or None (e.g. an HTML "soft 404" page)."""
    for magic, kind in _SIGNATURES:
        if data.startswith(magic):
            return kind
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    head = data[:512].lstrip().lower()
    if head.startswith(b"<svg") or (head.startswith(b"<?xml") and b"<svg" in data[:2048].lower()):
        return "image/svg+xml"
    return None


_LINK_RE = re.compile(r"<link\b[^>]*>", re.IGNORECASE)
_ATTR_RE = re.compile(r"""([a-z-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))""", re.IGNORECASE)


def icon_links(html: str) -> list[str]:
    """``href`` of every ``<link rel="icon">`` (also "shortcut icon", "apple-touch-icon"), in page order."""
    found: list[str] = []
    for tag in _LINK_RE.findall(html[:200_000]):
        attrs = {m.group(1).lower(): next(g for g in m.groups()[1:] if g is not None) for m in _ATTR_RE.finditer(tag)}
        rel = attrs.get("rel", "").lower().split()
        href = attrs.get("href", "").strip()
        if (
            href
            and ("icon" in rel or "apple-touch-icon" in rel)
            and not href.lower().startswith(("data:", "javascript:"))
        ):
            found.append(href)
    return found


@dataclass(frozen=True)
class Fingerprint:
    mmh3: int
    md5: str
    sha256: str
    size: int
    content_type: str

    def queries(self) -> dict[str, str]:
        """Ready-to-paste searches for hosts serving the same icon."""
        return {
            "shodan": f"http.favicon.hash:{self.mmh3}",
            "fofa": f'icon_hash="{self.mmh3}"',
            "zoomeye": f'iconhash:"{self.mmh3}"',
            "censys": f"services.http.response.favicons.md5_hash:{self.md5}",
        }

    def as_metadata(self) -> dict[str, Any]:
        return {
            "category": "favicon",
            "mmh3": self.mmh3,
            "md5": self.md5,
            "sha256": self.sha256,
            "size": self.size,
            "content_type": self.content_type,
            "search_queries": self.queries(),
        }


def fingerprint(icon: bytes) -> Fingerprint | None:
    """Hashes for an icon, or None when the bytes are not an image."""
    kind = sniff_image(icon)
    if kind is None or not icon or len(icon) > MAX_ICON_BYTES:
        return None
    return Fingerprint(
        mmh3=shodan_hash(icon),
        md5=hashlib.md5(icon, usedforsecurity=False).hexdigest(),
        sha256=hashlib.sha256(icon).hexdigest(),
        size=len(icon),
        content_type=kind,
    )
