"""Your own API keys, in Argus Personal: sources are reached directly, at no credit cost.

The "Bring your own keys" plan is the cheapest because the investigator pays the sources
directly. Any plan may add its own keys, which then take priority over Argus Connect:

* **UK Companies House**: free key from the Companies House developer hub;
* **Web search**: a Brave Search API key;
* **Claude** (the AI analyst): an Anthropic API key.

Keys are kept on this computer only, encrypted with this installation's own key (in its data
folder), and never sent to the Argus account service. Lookups with them go straight from this
computer to the source.
"""

from __future__ import annotations

import re
from typing import Any

from argus.security.crypto import SecretBoxError

PROVIDERS = {
    "companies_house": {"label": "UK Companies House", "where": "developer.company-information.service.gov.uk"},
    "web_search": {"label": "Web search (Brave Search API)", "where": "api-dashboard.search.brave.com"},
    "anthropic": {"label": "Claude, for the AI analyst (Anthropic API)", "where": "console.anthropic.com"},
}
STATE_KEY = "own_keys"
CONTEXT = "own-api-keys"
SHAPE = re.compile(r"^[A-Za-z0-9_\-.:]{8,256}$")
_keys: dict[str, str] = {}


def get(provider: str) -> str:
    return _keys.get(provider, "")


def listing() -> list[dict[str, Any]]:
    return [{"provider": p, "label": info["label"], "where": info["where"], "set": bool(_keys.get(p)),
             "ends_with": _keys[p][-4:] if _keys.get(p) else None} for p, info in PROVIDERS.items()]  # fmt: skip


async def load(state: Any, box: Any) -> None:
    """Read the saved keys (at start-up)."""
    _keys.clear()
    stored = await state.get(STATE_KEY)
    if not stored or not stored.get("sealed") or not box.available:
        return
    try:
        _keys.update({k: str(v) for k, v in box.open(stored["sealed"], CONTEXT).items() if k in PROVIDERS and v})
    except (
        SecretBoxError,
        ValueError,
        AttributeError,
    ):  # a moved database or a lost key file: the keys must simply be entered again
        _keys.clear()


async def _save(state: Any, box: Any) -> None:
    await state.set(STATE_KEY, {"sealed": box.seal(dict(_keys), CONTEXT)} if _keys else {})


async def put(state: Any, box: Any, provider: str, key: str) -> None:
    if provider not in PROVIDERS:
        raise ValueError("Unknown source")
    key = key.strip()
    if not SHAPE.match(key):
        raise ValueError("That doesn't look like an API key: paste it exactly as the source gave it")
    if not box.available:
        raise RuntimeError("This installation has no encryption key, so keys can't be stored safely")
    _keys[provider] = key
    await _save(state, box)


async def remove(state: Any, box: Any, provider: str) -> bool:
    if _keys.pop(provider, None) is None:
        return False
    await _save(state, box)
    return True
