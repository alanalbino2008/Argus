"""A web page's history, from the Internet Archive (Wayback Machine).

Pages change and disappear: a company's "about us" before a rebrand, a profile before it was
cleaned up, a statement quietly edited. The archive keeps copies. For one web address, Argus
lists every **different version** the archive holds (identical copies are folded together),
with the date of each, and links to open it. Any version can then be captured into the case as
evidence, like a live page.

Asking the archive tells it which page is being researched, so the lookup goes through the
case's network route, like every other request a case makes.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

URL = re.compile(r"^https?://[^\s/$.?#][^\s]*$", re.IGNORECASE)
LIMIT = 200


class HistoryError(ValueError):
    pass


def clean_url(raw: str) -> str:
    """The address to look up: http(s) only, no fragment, no credentials."""
    url = (raw or "").strip()
    problem = HistoryError("Enter a web address, such as https://example.com/about")
    if re.match(r"^[a-z][a-z0-9+.-]*:(?!\d)", url, re.IGNORECASE) and not re.match(r"^https?://", url, re.IGNORECASE):
        raise problem  # javascript:, file:, data:... only web pages have a history
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url
    parts = urlsplit(url)
    try:
        parts.port  # noqa: B018 - raises for a malformed port
    except ValueError as exc:
        raise problem from exc
    if not URL.match(url) or not parts.hostname or "." not in parts.hostname or "@" in parts.netloc or len(url) > 2000:
        raise problem
    return url.split("#", 1)[0]


def _when(stamp: str) -> str | None:
    try:
        return datetime.strptime(stamp[:14], "%Y%m%d%H%M%S").isoformat() + "Z"
    except ValueError:
        return None


def versions(rows: list[list[str]], base: str, url: str) -> dict[str, Any]:
    """CDX rows (the first is the header) to the page's distinct versions, oldest first."""
    if not rows or len(rows) < 2:
        return {"url": url, "versions": [], "first_seen": None, "last_seen": None}
    header = rows[0]
    index = {name: i for i, name in enumerate(header)}
    out = []
    for row in rows[1:]:
        stamp = row[index["timestamp"]] if "timestamp" in index and len(row) > index["timestamp"] else ""
        when = _when(stamp)
        if not when:
            continue
        original = row[index["original"]] if "original" in index else url
        status = row[index["statuscode"]] if "statuscode" in index else ""
        out.append({
            "date": when, "status": status if status not in ("-", "") else None,
            "type": row[index["mimetype"]] if "mimetype" in index else None,
            "archive_url": f"{base}/web/{stamp}/{original}",
            "raw_url": f"{base}/web/{stamp}id_/{original}",  # the page as archived, without the archive's banner
        })  # fmt: skip
    return {"url": url, "versions": out, "first_seen": out[0]["date"] if out else None,
            "last_seen": out[-1]["date"] if out else None}  # fmt: skip


def query(base: str, url: str) -> tuple[str, dict[str, str]]:
    return f"{base}/cdx/search/cdx", {"url": url, "output": "json", "fl": "timestamp,original,statuscode,mimetype,digest",
                                       "collapse": "digest", "limit": str(LIMIT)}  # fmt: skip
