"""Fetching breach exposures from a provider, server-side and through the case's route.

Two providers are supported, chosen by ``ARGUS_BREACH_PROVIDER``:

* **hibp**: Have I Been Pwned (needs ``ARGUS_HIBP_API_KEY``). Returns which breaches an email is in and
  what kinds of data each leaked — never a password or a hash, so there is no reuse correlation and
  nothing to reveal.
* **custom**: any provider at ``ARGUS_BREACH_PROVIDER_URL`` that answers a ``query`` with JSON records
  (the DeHashed / LeakCheck shape). Argus turns each record's password into a mask and a one-way hash
  and drops the plaintext (:func:`fetch_exposures`); the plaintext is only ever returned by
  :func:`reveal_one`, which the API guards with the case's authorisation, two-person approval and audit.

Both run through :func:`argus.intel.account_watch.client`, so an anonymous case uses its anonymous route
and nothing reaches the person.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

from argus.core.settings import Settings
from argus.intel import breaches
from argus.intel.account_watch import client

HIBP = "https://haveibeenpwned.com/api/v3"


def _records(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, dict):
        for key in ("entries", "results", "data", "records"):
            if isinstance(data.get(key), list):
                return data[key]
        return []
    return data if isinstance(data, list) else []


async def fetch_exposures(settings: Settings, identifier: str, kind: str, route: Any) -> list[dict[str, Any]]:
    """Masked exposures for one identifier (never any plaintext). Empty if the provider is off or fails."""
    provider = settings.breach_provider
    identifier = identifier.strip()
    if provider == "hibp":
        if kind != "email" or not settings.hibp_api_key:
            return []
        url = f"{HIBP}/breachedaccount/{quote(identifier.lower(), safe='')}?truncateResponse=false"
        headers = {"hibp-api-key": settings.hibp_api_key.get_secret_value()}
        try:
            async with client(settings, route) as http, http.get(url, headers=headers) as resp:
                if resp.status != 200:  # 404 = not in any breach; 401/403/429/5xx = nothing usable this time
                    return []
                data = await resp.json(content_type=None)
        except Exception:  # noqa: BLE001 - a provider failure never breaks a search
            return []
        out = []
        for b in data if isinstance(data, list) else []:
            if not isinstance(b, dict):
                continue
            classes = b.get("DataClasses") or []
            out.append(breaches.exposure(identifier, kind, {
                "breach": b.get("Name") or b.get("Title"), "breach_date": b.get("BreachDate"),
                "email": identifier, "password_hash": "" if "Passwords" not in classes else None}))  # fmt: skip
            out[-1]["has_password"] = "Passwords" in classes
            out[-1]["data_classes"] = classes[:20]
        out += await _hibp_stealer_by_email(settings, identifier, route, headers)
        return out
    if provider == "custom" and settings.breach_provider_url:
        return [breaches.exposure(identifier, kind, r) for r in await _custom(settings, identifier, route)]
    return []


async def _hibp_stealer_by_email(
    settings: Settings, email: str, route: Any, headers: dict[str, str]
) -> list[dict[str, Any]]:
    """HIBP infostealer logs for an email: the website domains its captured credentials unlock.

    Needs the stealer-logs subscription; any non-200 (not subscribed, nothing found) yields nothing."""
    url = f"{HIBP}/stealerlogsbyemail/{quote(email.lower(), safe='')}"
    try:
        async with client(settings, route) as http, http.get(url, headers=headers) as resp:
            if resp.status != 200:
                return []
            sites = await resp.json(content_type=None)
    except Exception:  # noqa: BLE001 - a provider failure never breaks a search
        return []
    return [
        breaches.exposure(email, "email", {"breach": "Infostealer logs", "type": "stealer", "url": str(site)})
        for site in sites or []
        if site
    ]


async def _custom(settings: Settings, identifier: str, route: Any) -> list[dict[str, Any]]:
    headers = {"Accept": "application/json"}
    if settings.breach_provider_api_key:
        headers["Authorization"] = f"Bearer {settings.breach_provider_api_key.get_secret_value()}"
    try:
        async with client(settings, route) as http, http.get(settings.breach_provider_url,
                                                             params={"query": identifier}, headers=headers) as resp:  # fmt: skip
            if resp.status != 200:
                return []
            return _records(await resp.json(content_type=None))[:500]
    except Exception:  # noqa: BLE001 - a provider failure never breaks a search
        return []


async def reveal_one(
    settings: Settings, identifier: str, kind: str, breach: str, want_hash: str, route: Any
) -> dict[str, Any] | None:
    """Re-fetch the provider live and return the one plaintext password for this exposure (custom only).
    Called only by the approval-gated reveal endpoint. The plaintext is returned, never stored."""
    if settings.breach_provider != "custom" or not settings.breach_provider_url:
        return None
    for record in await _custom(settings, identifier, route):
        password = str(record.get("password") or "")
        this = str(record.get("database") or record.get("breach") or record.get("source") or "unknown")
        if password and this == breach and breaches.password_hash(password) == want_hash:
            return {"identifier": identifier, "breach": breach, "password": password,
                    "username": record.get("username"), "email": record.get("email")}  # fmt: skip
    return None
