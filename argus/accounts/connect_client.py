"""How modules reach a premium source: the investigator's own key, else Argus Connect (credits).

* **Own key** (e.g. ``ARGUS_COMPANIES_HOUSE_API_KEY``): the lookup goes straight from this Argus
  to the source, through the scan's route; it costs no credits and nobody else sees it.
* **Argus Connect**: Argus Personal, signed in, asks the Argus account service, which charges
  credits and runs the lookup with its own key.
* Neither: the source is not available, and modules that need it are not run.
"""

from __future__ import annotations

import asyncio
from typing import Any

import aiohttp

from argus.accounts import own_keys, personal
from argus.accounts.connectors import LABELS, ConnectError, call_source
from argus.core.settings import get_settings

OWN_KEYS = {"companies_house": "companies_house_api_key", "web_search": "web_search_api_key"}


def own_key(provider: str) -> str:
    """The investigator's own key: entered in Argus Personal, else set in the configuration."""
    if own_keys.get(provider):
        return own_keys.get(provider)
    value = getattr(get_settings(), OWN_KEYS.get(provider, ""), None)
    return value.get_secret_value() if value else ""


def anthropic_key() -> str:
    if own_keys.get("anthropic"):
        return own_keys.get("anthropic")
    value = get_settings().anthropic_api_key
    return value.get_secret_value() if value else ""


def available(provider: str) -> bool:
    settings = get_settings()
    return bool(own_key(provider)) or (settings.edition == "personal" and bool(settings.account_server_url))


async def lookup(session: Any, provider: str, name: str, params: dict[str, Any]) -> dict[str, Any]:
    """The source's answer (``{"not_found": True}`` when it has nothing). Raises ConnectError."""
    key = own_key(provider)
    if key:
        return await call_source(session, provider, name, params, key)
    licence = personal.CURRENT
    settings = get_settings()
    if licence is None or not licence.token or not settings.account_server_url:
        raise ConnectError(503, f"{LABELS[provider]} needs an Argus account (Argus Connect) or your own API key")
    url = f"{settings.account_server_url.rstrip('/')}/api/connect/{provider}"
    async with session.post(url, json={"licence": licence.token, "operation": name, "params": params}) as resp:
        data = await resp.json(content_type=None) if resp.status != 204 else {}
        if resp.status != 200:
            detail = data.get("detail") if isinstance(data, dict) else None
            raise ConnectError(resp.status, str(detail or f"Argus Connect answered {resp.status}"))
    licence.last_credits = data.get("credits")
    return data.get("result") or {}


# ---------------------------------------------------------------------------- the AI analyst
def ai_access() -> str | None:
    """How the AI analyst is reached: "own_key", "connect" (credits), or None (not available)."""
    settings = get_settings()
    if anthropic_key():
        return "own_key"
    if settings.edition == "personal" and settings.account_server_url:
        return "connect"
    return None


async def ai(task: str, material: str) -> dict[str, Any]:
    """Run an AI analyst task: directly with the investigator's own key, else through Argus Connect.

    Returns ``{"output", "model", "cut_off", "via", "credits"}``. Raises AnalystError.
    """
    from argus.intel.analyst import AnalystError, run_task

    settings = get_settings()
    via = ai_access()
    if via == "own_key":
        result = await run_task(task, material, key=anthropic_key(), settings=settings)
        return {**result, "via": via, "credits": None}
    licence = personal.CURRENT
    if via is None or licence is None or not licence.token:
        raise AnalystError(503, "The AI analyst needs an Argus account (Argus Connect) or your own Claude API key")
    url = f"{settings.account_server_url.rstrip('/')}/api/connect/ai/{task}"
    try:
        async with (
            aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=1200)) as http,
            http.post(url, json={"licence": licence.token, "material": material}) as resp,
        ):
            data = await resp.json(content_type=None) if resp.status != 204 else {}
            if resp.status != 200:
                detail = data.get("detail") if isinstance(data, dict) else None
                raise AnalystError(resp.status, str(detail or f"Argus Connect answered {resp.status}"))
    except (aiohttp.ClientError, asyncio.TimeoutError, OSError, ValueError) as exc:
        raise AnalystError(503, "The Argus account service could not be reached") from exc
    licence.last_credits = data.get("credits")
    return {**(data.get("result") or {}), "via": via, "credits": data.get("credits")}
