"""Public profile details from any profile page: the information sites publish for link previews.

Most sites put a profile's public name, bio and photo into the page's metadata, so that a link to
it shows a preview in chat apps and search results: OpenGraph (``og:title``,
``og:description``, ``og:image``), Twitter cards, and structured data (JSON-LD ``Person``, often
with ``sameAs`` links to the person's other accounts). Profile pages also mark links to the
owner's own sites with ``rel="me"``.

Reading these lets Argus compare accounts on hundreds of sites, not only the handful with an
official API (``profile_enricher``). It reads only the public page anyone can see, never behind
a login.

What a page says is filtered: a title that is just the handle or the site's name is not a name, a
description that is the site's own sales pitch ("Join millions of...") is not a bio, and a page
that turns out to be a sign-in screen gives nothing.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import re
from html import unescape
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlsplit

import aiohttp

from argus.core.http import HttpClient, read_limited

MAX_PAGE = 800_000
BOILERPLATE = re.compile(
    r"(?i)\b(sign ?up|log ?in|sign ?in|create an account|join (?:millions|now|today|for free)|download the app|"
    r"cookies?|javascript is (?:disabled|required)|page not found|access denied|are you a robot|captcha)\b"
)
SEPARATORS = "|\\-\u2013\u2014\u2022\u00b7:"  # bars, hyphens, en and em dashes, bullets, colons
TITLE_SUFFIX = re.compile(r"\s*[" + SEPARATORS + r"]\s*[^" + SEPARATORS + r"]{2,40}$")


class _Meta(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.meta: dict[str, str] = {}
        self.title = ""
        self.ld: list[str] = []
        self.me: list[str] = []
        self._in_title = self._in_ld = False
        self._buf: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "meta":
            key = (a.get("property") or a.get("name") or a.get("itemprop") or "").lower()
            if key and a.get("content") and key not in self.meta:
                self.meta[key] = a["content"].strip()
        elif tag == "title":
            self._in_title, self._buf = True, []
        elif tag == "script" and a.get("type", "").lower() == "application/ld+json":
            self._in_ld, self._buf = True, []
        elif tag in ("a", "link") and "me" in a.get("rel", "").lower().split() and a.get("href"):
            self.me.append(a["href"])

    def handle_data(self, data: str) -> None:
        if self._in_title or self._in_ld:
            self._buf.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "title" and self._in_title:
            self.title, self._in_title = "".join(self._buf).strip(), False
        elif tag == "script" and self._in_ld:
            self.ld.append("".join(self._buf))
            self._in_ld = False


def _json(text: str) -> Any:
    try:
        return json.loads(text)
    except ValueError:
        return None


def _people(node: Any) -> list[dict[str, Any]]:
    """JSON-LD Person objects, wherever they sit (top level, @graph, mainEntity)."""
    found: list[dict[str, Any]] = []
    if isinstance(node, list):
        for item in node:
            found += _people(item)
    elif isinstance(node, dict):
        kind = node.get("@type")
        kinds = kind if isinstance(kind, list) else [kind]
        if "Person" in kinds:
            found.append(node)
        for key in ("@graph", "mainEntity", "author"):
            if key in node:
                found += _people(node[key])
    return found


def _clean_name(raw: str, handle: str, platform: str) -> str | None:
    name = unescape(raw).strip()
    name = re.sub(r"\s*\(@?[\w.]+\)\s*", " ", name).strip()  # "Jane Roe (@janeroe)"
    for _ in range(2):
        trimmed = TITLE_SUFFIX.sub("", name).strip()
        name = trimmed if len(trimmed) >= 2 else name
    plain = re.sub(r"[^a-z0-9]", "", name.lower())
    bare_handle = " " not in name and name.lower().lstrip("@") == handle.lower().lstrip("@")
    if not plain or bare_handle or plain == re.sub(r"[^a-z0-9]", "", platform.lower()):
        return None  # the handle or the site's own name, not a person's name
    if BOILERPLATE.search(name) or len(name) > 80:
        return None
    return name


def parse_profile_page(page: str, url: str, handle: str, platform: str) -> dict[str, Any]:
    """The public facts a profile page publishes about its owner."""
    parser = _Meta()
    with contextlib.suppress(Exception):  # malformed markup: keep what was read so far
        parser.feed(page)
    m = parser.meta
    people: list[dict[str, Any]] = [p for block in parser.ld[:5] for p in _people(_json(block))]
    person = people[0] if people else {}
    name = _clean_name(str(person.get("name") or m.get("og:title") or m.get("twitter:title") or parser.title), handle,
                       platform)  # fmt: skip
    bio = unescape(str(person.get("description") or m.get("og:description") or m.get("description")
                       or m.get("twitter:description") or "")).strip()  # fmt: skip
    if len(bio) < 12 or BOILERPLATE.search(bio):
        bio = ""
    image = person.get("image")
    if isinstance(image, dict):
        image = image.get("url")
    image = str(image or m.get("og:image") or m.get("twitter:image") or "")
    address = person.get("address") or person.get("homeLocation") or {}
    if isinstance(address, dict):
        address = address.get("addressLocality") or address.get("name") or ""
    same_as = person.get("sameAs") or []
    links = [*(same_as if isinstance(same_as, list) else [same_as]), *parser.me]
    facts: dict[str, Any] = {
        "display_name": name, "bio": bio[:400],
        "avatar_url": urljoin(url, image) if image else None,
        "location": str(address)[:80] if isinstance(address, str) else None,
        "links": [{"url": urljoin(url, str(link)), "platform": "Website", "verified": False} for link in
                  dict.fromkeys(str(x) for x in links if x) if str(link).startswith(("http://", "https://", "/"))][:10],
        "source": "page metadata",
    }  # fmt: skip
    own = (urlsplit(url).hostname or "").removeprefix("www.")
    facts["links"] = [x for x in facts["links"] if (urlsplit(x["url"]).hostname or "").removeprefix("www.") != own]
    return {k: v for k, v in facts.items() if v}


async def read_profile_page(session: HttpClient, url: str, handle: str, platform: str,
                            timeout: float) -> dict[str, Any] | None:  # fmt: skip
    if not url.startswith("https://"):
        return None
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout),
                               headers={"Accept": "text/html,application/xhtml+xml"}) as resp:  # fmt: skip
            if resp.status != 200 or "html" not in resp.headers.get("Content-Type", "html"):
                return None
            body = await read_limited(resp, MAX_PAGE)
    except (aiohttp.ClientError, asyncio.TimeoutError, ValueError):
        return None
    if not body:
        return None
    facts = parse_profile_page(body.decode("utf-8", errors="ignore"), url, handle, platform)
    return facts if set(facts) - {"source"} else None
