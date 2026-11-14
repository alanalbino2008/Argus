"""Validate report branding supplied by users.

A logo is an untrusted file that ends up inside documents sent to clients, so it is:

* size-limited before decoding (1 MB) and dimension-limited after (decompression bombs: a
  tiny PNG can claim to be 50,000 x 50,000 pixels);
* accepted only as PNG or JPEG, decided by decoding it, not by its name or claimed type;
* **re-encoded** to a fresh PNG, so EXIF/GPS metadata, embedded payloads and polyglot
  tricks in the original bytes never reach a report.
"""

from __future__ import annotations

import base64
import binascii
import io
import re

from PIL import Image, UnidentifiedImageError

MAX_LOGO_BYTES = 1_000_000
MAX_LOGO_PIXELS = 4_000_000
MAX_LOGO_SIDE = 4000
OUTPUT_MAX_SIDE = 800
HEX_COLOUR = re.compile(r"^#[0-9a-fA-F]{6}$")


class BrandingError(ValueError):
    """Invalid branding; the message is safe to show."""


def decode_data_url(value: str) -> bytes:
    """Accept 'data:image/png;base64,....' or bare base64."""
    payload = value.split(",", 1)[1] if value.startswith("data:") else value
    if len(payload) > MAX_LOGO_BYTES * 4 // 3 + 8:
        raise BrandingError("The logo must be smaller than 1 MB")
    try:
        return base64.b64decode(payload, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise BrandingError("The logo is not valid base64 image data") from exc


def sanitise_logo(raw: bytes) -> bytes:
    if len(raw) > MAX_LOGO_BYTES:
        raise BrandingError("The logo must be smaller than 1 MB")
    try:
        with Image.open(io.BytesIO(raw)) as probe:
            if probe.format not in ("PNG", "JPEG"):
                raise BrandingError("Use a PNG or JPEG logo")
            width, height = probe.size
            if width * height > MAX_LOGO_PIXELS or max(width, height) > MAX_LOGO_SIDE:
                raise BrandingError("The logo is too large (at most 4000 pixels per side)")
            probe.load()
            image = probe.convert("RGBA")
    except BrandingError:
        raise
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError) as exc:
        raise BrandingError("The logo could not be read as an image") from exc
    image.thumbnail((OUTPUT_MAX_SIDE, OUTPUT_MAX_SIDE))
    out = io.BytesIO()
    image.save(out, format="PNG", optimize=True)
    return out.getvalue()


def check_accent(value: str) -> str:
    if not HEX_COLOUR.match(value):
        raise BrandingError("Use a colour like #4f46e5")
    return value.lower()
