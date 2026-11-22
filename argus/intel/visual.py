"""Visual similarity: does a lookalike's page *look* like the brand's own?

Phishing kits copy a login page's look and often change everything a machine checks first: the
favicon, the title, the markup. A person still sees the bank's page. So Argus compares what a person
sees: the first screen of each page, rendered by the headless browser.

Each screenshot becomes a **perceptual fingerprint** of its first screen (1366 x 900):

* a 64-bit **difference hash** (dHash) of a 9 x 8 grey thumbnail: the direction of brightness changes,
  robust to compression, small shifts and colour tweaks;
* a 16 x 16 **grey layout**: where the page is light and dark.

Two pages are similar when both agree (few differing hash bits *and* a close layout). Blank or
near-uniform pages (an empty white page, a solid "loading" screen) carry no information and are never
said to match anything.
"""

from __future__ import annotations

import io
from dataclasses import dataclass
from typing import Any

from PIL import Image, ImageStat

FIRST_SCREEN = (1366, 900)
MATCH = 0.86  # similarity at or above which a page counts as a visual copy
MIN_CONTRAST = 6.0  # grey standard deviation below which a page is "blank"


@dataclass(frozen=True)
class Fingerprint:
    dhash: int
    layout: tuple[int, ...]  # 256 grey levels
    contrast: float

    def as_dict(self) -> dict[str, Any]:
        return {"dhash": f"{self.dhash:016x}", "layout": bytes(self.layout).hex(), "contrast": round(self.contrast, 1)}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Fingerprint:
        return cls(int(data["dhash"], 16), tuple(bytes.fromhex(data["layout"])), float(data.get("contrast", 0)))

    @property
    def blank(self) -> bool:
        return self.contrast < MIN_CONTRAST


def fingerprint(png: bytes) -> Fingerprint | None:
    """The fingerprint of a screenshot's first screen, or None when it is not an image."""
    try:
        image = Image.open(io.BytesIO(png))
        image.load()
    except (OSError, ValueError, Image.DecompressionBombError):
        return None
    width, height = image.size
    first = image.crop((0, 0, min(width, FIRST_SCREEN[0]), min(height, FIRST_SCREEN[1]))).convert("L")
    contrast = float(ImageStat.Stat(first).stddev[0])
    small = first.resize((9, 8), Image.Resampling.LANCZOS)
    pixels = list(small.tobytes())  # mode L: one byte per pixel
    bits = 0
    for row in range(8):
        for col in range(8):
            bits = (bits << 1) | (1 if pixels[row * 9 + col] > pixels[row * 9 + col + 1] else 0)
    layout = tuple(first.resize((16, 16), Image.Resampling.BOX).tobytes())
    return Fingerprint(bits, layout, contrast)


def similarity(a: Fingerprint, b: Fingerprint) -> float:
    """0 (unrelated) to 1 (the same first screen). Blank pages are similar to nothing."""
    if a.blank or b.blank:
        return 0.0
    hash_score = 1 - bin(a.dhash ^ b.dhash).count("1") / 64
    layout_score = 1 - sum(abs(x - y) for x, y in zip(a.layout, b.layout, strict=True)) / (255 * len(a.layout))
    return round(min(hash_score, layout_score), 3)


def best_match(page: Fingerprint, references: list[dict[str, Any]]) -> dict[str, Any] | None:
    """The closest reference ({url, similarity}), or None without usable references."""
    best = None
    for ref in references:
        try:
            score = similarity(page, Fingerprint.from_dict(ref["fingerprint"]))
        except (KeyError, ValueError, TypeError):
            continue
        if best is None or score > best["similarity"]:
            best = {"url": ref["url"], "similarity": score}
    return best
