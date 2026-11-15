"""Profile-picture fingerprints: the same photo on two sites is strong evidence of one person.

People reuse their profile picture across platforms far more consistently than their handle. Argus
fetches each account's picture **on the server** (through the case's route, never in the
investigator's browser) and computes a *perceptual hash* (dHash): a 64-bit fingerprint that
survives resizing and recompression, so the same photo served at different sizes by GitHub and
Reddit still matches, while different photos do not.

Pictures that carry no identity are ignored, so they never link strangers:

* blank and single-colour images (most sites' default avatar);
* images too small, too large or not images at all.

Different sites' default avatars differ from one another, and matches are only ever made between
accounts on *different* platforms, so two users who both kept one site's default picture are not
linked. A match is graded **strong**, not verified: someone can copy another person's photo.
"""

from __future__ import annotations

import asyncio
import io
from typing import Any

from PIL import Image, UnidentifiedImageError

MAX_AVATAR = 2 * 1024 * 1024
MAX_PIXELS = 16_000_000
MATCH_DISTANCE = 6  # of 64 bits; re-encoded copies of one photo are typically 0-4 apart


def fingerprint(data: bytes) -> str | None:
    """dHash of an image as 16 hex digits, or None if it says nothing about identity."""
    try:
        with Image.open(io.BytesIO(data)) as img:
            width, height = img.size
            if width < 16 or height < 16 or width * height > MAX_PIXELS:
                return None
            img.seek(0)  # first frame of an animated avatar
            grey = img.convert("L").resize((9, 8), Image.Resampling.LANCZOS)
            pixels = [int(grey.getpixel((x, y)) or 0) for y in range(8) for x in range(9)]  # type: ignore[arg-type]
    except (UnidentifiedImageError, OSError, ValueError, Image.DecompressionBombError, EOFError):
        return None
    if max(pixels) - min(pixels) < 12:  # blank or a flat colour: a default avatar
        return None
    bits = 0
    for row in range(8):
        for col in range(8):
            bits = (bits << 1) | (pixels[row * 9 + col] > pixels[row * 9 + col + 1])
    ones = bin(bits).count("1")
    if ones <= 3 or ones >= 61:  # a plain gradient: too little detail to tell people apart
        return None
    return f"{bits:016x}"


def distance(a: str, b: str) -> int:
    return bin(int(a, 16) ^ int(b, 16)).count("1")


def same_picture(a: str | None, b: str | None) -> bool:
    return bool(a and b) and distance(a, b) <= MATCH_DISTANCE  # type: ignore[arg-type]


async def fetch_fingerprint(session: Any, url: str | None) -> str | None:
    """Download a profile picture (HTTPS only, up to 2 MB) and fingerprint it. Never raises."""
    if not url or not url.startswith("https://"):
        return None
    try:
        async with session.get(url, headers={"Accept": "image/*"}) as resp:
            if resp.status != 200:
                return None
            content = getattr(resp, "content", None)
            data = await content.read(MAX_AVATAR + 1) if content is not None else await resp.read()
    except asyncio.CancelledError:
        raise
    except Exception:  # noqa: BLE001 - a missing picture is never worth failing a profile for
        return None
    if len(data) > MAX_AVATAR:
        return None
    return await asyncio.to_thread(fingerprint, data)
