"""How modules reach a premium source: the investigator's own key, else Argus Connect (credits).

* **Own key** (e.g. ``ARGUS_COMPANIES_HOUSE_API_KEY``): the lookup goes straight from this Argus
  to the source, through the scan's route; it costs no credits and nobody else sees it.
* **Argus Connect**: Argus Personal, signed in, asks the Argus account service, which charges
  credits and runs the lookup with its own key.
* Neither: the source is not available, and modules that need it are not run.
"""

from __future__ import annotations

from typing import Any

from argus.accounts import personal
from argus.accounts.connectors import LABELS, ConnectError, call_source
from argus.core.settings import get_settings

OWN_KEYS = {"companies_house": "companies_house_api_key"}


def own_key(provider: str) -> str:
    value = getattr(get_settings(), OWN_KEYS.get(provider, ""), None)
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
