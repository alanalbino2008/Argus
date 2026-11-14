"""Username platform signatures: loading, validation and detection.

Signatures live in ``argus/data/platforms.json`` (the same idea as Sherlock's
``data.json``) so new sites are added as data, not code. Operators can add their
own with ``ARGUS_EXTRA_PLATFORMS_FILE`` pointing at a JSON file of the same shape.

Detection strategies
--------------------
``status``        the account exists when the probe returns the expected status (200)
``absent``        ... and the page does NOT contain a "not found" marker (soft-404 sites)
``present``       ... and the page DOES contain a marker only real profiles have
``json_key``      ... and the JSON response has a truthy ``key``
``json_nonempty`` ... and the JSON response (or its ``key``) is a non-empty list/object
``not_null``      ... and the body is not empty / ``null`` (Firebase-style APIs)
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Any
from urllib.parse import quote

DETECTIONS = {"status", "absent", "present", "json_key", "json_nonempty", "not_null"}
# A handle used as a sub-domain (https://{}.tumblr.com) must be a valid DNS label.
_SUBDOMAIN_SAFE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_PATH_SAFE = re.compile(r"^[A-Za-z0-9._ -]{1,64}$")


@dataclass(frozen=True)
class Platform:
    name: str
    category: str
    url: str
    probe: str | None = None
    detect: str = "status"
    text: str | None = None
    key: str | None = None
    valid: str | None = None
    known: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    redirects: bool = True
    exists: int = 200

    def accepts(self, username: str) -> bool:
        """Skip sites that cannot host this handle - saves requests and avoids false positives."""
        if self.valid and not re.fullmatch(self.valid, username):
            return False
        if "{}." in self.url.split("//", 1)[-1].split("/", 1)[0]:
            return bool(_SUBDOMAIN_SAFE.match(username))
        return bool(_PATH_SAFE.match(username))

    def profile_url(self, username: str) -> str:
        return self.url.format(quote(username, safe="@._-"))

    def probe_url(self, username: str) -> str:
        return (self.probe or self.url).format(quote(username, safe="@._-"))


def _parse(raw: dict[str, Any]) -> Platform:
    unknown = set(raw) - set(Platform.__dataclass_fields__)
    if unknown:
        raise ValueError(f"{raw.get('name')}: unknown fields {sorted(unknown)}")
    platform = Platform(**raw)
    if platform.detect not in DETECTIONS:
        raise ValueError(f"{platform.name}: unknown detection {platform.detect!r}")
    if platform.detect in ("absent", "present") and not platform.text:
        raise ValueError(f"{platform.name}: '{platform.detect}' detection needs 'text'")
    if platform.detect == "json_key" and not platform.key:
        raise ValueError(f"{platform.name}: 'json_key' detection needs 'key'")
    for template in (platform.url, platform.probe or platform.url):
        if template.count("{}") != 1 or not template.startswith("https://"):
            raise ValueError(f"{platform.name}: templates must be https:// with exactly one {{}}")
    return platform


def parse_platforms(document: dict[str, Any]) -> list[Platform]:
    platforms = [_parse(item) for item in document.get("platforms", [])]
    names = [p.name for p in platforms]
    duplicates = {n for n in names if names.count(n) > 1}
    if duplicates:
        raise ValueError(f"duplicate platform names: {sorted(duplicates)}")
    return platforms


@lru_cache
def builtin_platforms() -> tuple[Platform, ...]:
    text = resources.files("argus").joinpath("data/platforms.json").read_text(encoding="utf-8")
    return tuple(parse_platforms(json.loads(text)))


def load_platforms(extra_file: str | Path | None = None) -> list[Platform]:
    """Built-in signatures plus an operator-supplied file (its entries override by name)."""
    platforms = {p.name: p for p in builtin_platforms()}
    if extra_file:
        extra = parse_platforms(json.loads(Path(extra_file).read_text(encoding="utf-8")))
        platforms.update({p.name: p for p in extra})
    return list(platforms.values())


def detect(platform: Platform, status: int, body: str | None) -> bool:
    """Pure decision: does this response mean the account exists?"""
    if status != platform.exists:
        return False
    if platform.detect == "status":
        return True
    body = body or ""
    if platform.detect == "absent":
        return (platform.text or "") not in body
    if platform.detect == "present":
        return (platform.text or "") in body
    if platform.detect == "not_null":
        return body.strip() not in ("", "null", "{}", "[]")
    try:
        data = json.loads(body)
    except ValueError:
        return False
    if platform.key is not None:
        data = data.get(platform.key) if isinstance(data, dict) else None
    if platform.detect == "json_key":
        return bool(data)
    return isinstance(data, (list, dict)) and len(data) > 0  # json_nonempty


def needs_body(platform: Platform) -> bool:
    return platform.detect != "status"
