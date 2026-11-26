"""Argus Connect: premium data sources, reached with the operator's keys and paid for in credits.

Some intelligence sources need an account and an API key. With Argus Connect the customer needs
neither: the Argus account service holds the keys, and each lookup costs **Argus credits** from
the customer's plan (a monthly allowance, plus credits they buy).

**A fixed menu, never a proxy.** Each source exposes a short list of named lookups ("company",
"officers"...). Their parameters are validated against strict patterns and placed into
fixed URLs on the source's own host. A customer cannot make the service call any other address,
so a stolen licence can't turn the account service into a free proxy for someone's keys.

**Privacy.** A brokered lookup tells the account service what was looked up (a company number, an
officer's name). Investigators who must not reveal even that can set their own key for the
source (for example ``ARGUS_COMPANIES_HOUSE_API_KEY``): lookups then go directly from their own
Argus to the source and cost no credits.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

COMPANIES_HOUSE = "https://api.company-information.service.gov.uk"
WEB_SEARCH = "https://api.search.brave.com/res/v1"
_COMPANY_NUMBER = re.compile(r"^[A-Z0-9]{8}$")
_OFFICER_ID = re.compile(r"^[A-Za-z0-9_-]{8,64}$")


class ConnectError(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status, self.detail = status, detail


@dataclass(frozen=True)
class Operation:
    path: str  # with {placeholders} for validated parameters
    params: dict[str, re.Pattern[str] | None]  # parameter -> pattern (None: free text, length-capped)
    query: dict[str, str]  # fixed query parameters
    credits: int


CATALOGUE: dict[str, dict[str, Operation]] = {
    "companies_house": {
        "search_companies": Operation("/search/companies", {"q": None}, {"items_per_page": "5"}, 1),
        "company": Operation("/company/{number}", {"number": _COMPANY_NUMBER}, {}, 1),
        "officers": Operation("/company/{number}/officers", {"number": _COMPANY_NUMBER}, {"items_per_page": "35"}, 1),
        "psc": Operation(
            "/company/{number}/persons-with-significant-control",
            {"number": _COMPANY_NUMBER},
            {"items_per_page": "25"},
            1,
        ),
        "search_officers": Operation("/search/officers", {"q": None}, {"items_per_page": "10"}, 1),
        "appointments": Operation(
            "/officers/{officer_id}/appointments", {"officer_id": _OFFICER_ID}, {"items_per_page": "35"}, 1
        ),
    },
}
CATALOGUE["web_search"] = {
    # The web's mentions of an exact phone number or email address (Brave Search API).
    "web": Operation("/web/search", {"q": None}, {"count": "20", "safesearch": "off", "text_decorations": "false"}, 1),
}
# OpenCorporates: company registers of about 140 jurisdictions, and their officers.
_JURISDICTION = re.compile(r"^[a-z]{2}(_[a-z]{2})?$")
_REGISTER_NUMBER = re.compile(r"^(?!.*\.\.)[A-Za-z0-9][A-Za-z0-9 .-]{0,39}$")  # no slashes, no ".."
CATALOGUE["opencorporates"] = {
    "search_companies": Operation("/companies/search", {"q": None}, {"per_page": "10", "order": "score"}, 2),
    "company": Operation(
        "/companies/{jurisdiction}/{number}", {"jurisdiction": _JURISDICTION, "number": _REGISTER_NUMBER}, {}, 2
    ),
    "search_officers": Operation("/officers/search", {"q": None}, {"per_page": "20", "order": "score"}, 2),
}
# CourtListener (Free Law Project): US federal court dockets (PACER/RECAP) and opinions.
CATALOGUE["courtlistener"] = {
    "dockets": Operation("/search/", {"q": None}, {"type": "r", "order_by": "dateFiled desc"}, 2),
    "opinions": Operation("/search/", {"q": None}, {"type": "o", "order_by": "dateFiled desc"}, 2),
}
# TinEye: where else an image appears on the web (reverse image search), by the image's address.
_IMAGE_URL = re.compile(r"^https?://[^\s]{4,2000}$")
CATALOGUE["tineye"] = {
    "search": Operation("/search/", {"image_url": _IMAGE_URL}, {"limit": "50", "sort": "score", "order": "desc"}, 3),
}
# SocialFetch: public profiles as a logged-out visitor sees them, where the site itself shows a sign-in
# wall to automated visitors. Profile lookups only: never contact details, followers or stories.
_HANDLE = re.compile(r"^@?[A-Za-z0-9._-]{1,100}$")
_FACEBOOK_URL = re.compile(r"^https://(www\.|m\.)?facebook\.com/[A-Za-z0-9.\-/=?_]{1,200}$")
CATALOGUE["socialfetch"] = {
    "linkedin": Operation("/v2/linkedin/profiles", {"handle": _HANDLE}, {}, 5),
    "instagram": Operation("/v2/instagram/profiles/{profile}", {"profile": _HANDLE}, {}, 1),
    "x": Operation("/v1/twitter/profiles/{handle}", {"handle": _HANDLE}, {"by": "handle"}, 1),
    "facebook": Operation("/v1/facebook/profiles", {"url": _FACEBOOK_URL}, {}, 1),
    "tiktok": Operation("/v1/tiktok/profiles/{handle}", {"handle": _HANDLE}, {}, 1),
    "threads": Operation("/v1/threads/profiles/{handle}", {"handle": _HANDLE}, {}, 1),
    "snapchat": Operation("/v1/snapchat/profiles/{handle}", {"handle": _HANDLE}, {}, 1),
    "youtube": Operation("/v1/youtube/channel", {"handle": _HANDLE}, {}, 1),
}
BASES = {"companies_house": COMPANIES_HOUSE, "web_search": WEB_SEARCH, "tineye": "https://api.tineye.com/rest",
         "opencorporates": "https://api.opencorporates.com/v0.4", "courtlistener": "https://www.courtlistener.com/api/rest/v4",
         "socialfetch": "https://api.socialfetch.dev"}  # fmt: skip
LABELS = {"companies_house": "UK Companies House", "web_search": "Web search", "opencorporates": "OpenCorporates",
          "courtlistener": "US court records (CourtListener)", "tineye": "Reverse image search (TinEye)",
          "socialfetch": "SocialFetch"}  # fmt: skip


def _auth_query(provider: str, key: str) -> dict[str, str]:
    """Sources that take the key as a query parameter rather than a header."""
    return {"api_token": key} if provider == "opencorporates" else {}


def _auth(provider: str, key: str) -> dict[str, str]:
    if provider == "web_search":
        return {"X-Subscription-Token": key}
    if provider == "opencorporates":
        return {}
    if provider == "courtlistener":
        return {"Authorization": f"Token {key}"}
    if provider in ("tineye", "socialfetch"):
        return {"x-api-key": key}
    token = base64.b64encode(f"{key}:".encode()).decode()  # HTTP Basic: the key is the user name
    return {"Authorization": f"Basic {token}"}


def operation(provider: str, name: str) -> Operation:
    try:
        return CATALOGUE[provider][name]
    except KeyError as exc:
        raise ConnectError(404, f"Unknown lookup {provider}/{name}") from exc


def build(provider: str, name: str, params: dict[str, Any]) -> tuple[str, dict[str, str]]:
    """The exact URL and query for a lookup, with every parameter validated."""
    op = operation(provider, name)
    values: dict[str, str] = {}
    for key, pattern in op.params.items():
        value = str(params.get(key, "")).strip()
        if key == "number" and provider == "companies_house":
            value = value.upper().zfill(8)
        longest = 2000 if key == "image_url" else 160
        if not value or len(value) > longest or (pattern is not None and not pattern.match(value)):
            raise ConnectError(422, f"Invalid {key} for {provider}/{name}")
        values[key] = value
    path_keys = set(re.findall(r"{(\w+)}", op.path))
    path = op.path.format(**{k: quote(v, safe="") for k, v in values.items() if k in path_keys})
    query = {**op.query, **{k: v for k, v in values.items() if k not in path_keys}}
    return BASES[provider] + path, query


async def call_source(http: Any, provider: str, name: str, params: dict[str, Any], key: str) -> dict[str, Any]:
    """Run a lookup against the source itself with ``key`` (the operator's, or the customer's own)."""
    url, query = build(provider, name, params)
    headers = {"Accept": "application/json", **_auth(provider, key)}
    async with http.get(url, params={**query, **_auth_query(provider, key)}, headers=headers) as resp:
        if resp.status == 404:
            return {"not_found": True}
        if resp.status in (401, 403):
            raise ConnectError(502, f"{LABELS[provider]} refused the key")
        if resp.status == 402:
            raise ConnectError(402, f"{LABELS[provider]}: no credits left on the account")
        if resp.status == 429:
            raise ConnectError(503, f"{LABELS[provider]} is rate-limiting requests; try again shortly")
        if resp.status != 200:
            raise ConnectError(502, f"{LABELS[provider]} answered {resp.status}")
        data = await resp.json(content_type=None)
    return data if isinstance(data, dict) else {"items": data}
