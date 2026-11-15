"""Sanctions screening for cryptocurrency addresses, from the US Treasury's official list.

The US Office of Foreign Assets Control (OFAC) publishes the Specially Designated Nationals (SDN)
list: people, companies and groups that US persons may not deal with (ransomware gangs,
darknet markets, mixers, state hackers...). Since 2018 OFAC also lists their **cryptocurrency
addresses**. Sending money to one is a legal problem for whoever sends it, and receiving from one
is a strong lead.

Argus reads the list in OFAC's own published files: ``sdn.csv``, and ``sdn_comments.csv`` where
long entries continue. They are public domain, free and updated as designations change. Argus
downloads them when needed and caches them for a day; offline installs can point at saved copies.
Each address is matched exactly (Ethereum addresses case-insensitively) to the designated
party's name and sanctions programmes.

A match is a fact about the address, not a verdict about anyone who dealt with it: the
investigator decides what it means.
"""

from __future__ import annotations

import asyncio
import csv
import io
import logging
import re
import time
import weakref
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from argus.core.settings import get_settings

logger = logging.getLogger("argus.sanctions")
MAX_FILE = 40 * 1024 * 1024
TTL = 24 * 3600
_ADDRESS = re.compile(r"Digital Currency Address - ([A-Z0-9]{2,6})\s+([A-Za-z0-9]{20,110})")
CURRENCIES = {"XBT": "Bitcoin", "ETH": "Ethereum", "USDT": "Tether", "USDC": "USD Coin", "XMR": "Monero",
              "LTC": "Litecoin", "TRX": "Tron", "BCH": "Bitcoin Cash", "BSV": "Bitcoin SV", "ZEC": "Zcash",
              "DASH": "Dash", "ETC": "Ethereum Classic", "BTG": "Bitcoin Gold", "XVG": "Verge",
              "ARB": "Arbitrum", "BSC": "BNB Smart Chain", "SOL": "Solana"}  # fmt: skip


@dataclass
class _State:
    by_address: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    loaded_at: float = 0.0
    entries: int = 0
    error: str | None = None
    source: str = ""


_state = _State()
_locks: weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, asyncio.Lock] = weakref.WeakKeyDictionary()


def _lock() -> asyncio.Lock:
    loop = asyncio.get_running_loop()
    if loop not in _locks:
        _locks[loop] = asyncio.Lock()
    return _locks[loop]


def _key(address: str) -> str:
    """Matching key: Ethereum-style and Bech32 addresses are case-insensitive; Base58 ones are not."""
    return address.lower() if address.lower().startswith(("0x", "bc1", "ltc1")) else address


def parse(sdn_csv: str, comments_csv: str = "") -> dict[str, list[dict[str, Any]]]:
    """OFAC's CSV files -> {address key: [{name, programs, currency, entity}]}."""
    remarks: dict[str, list[str]] = {}
    names: dict[str, tuple[str, str]] = {}
    for row in csv.reader(io.StringIO(sdn_csv)):
        if len(row) < 12 or not row[0].strip().isdigit():
            continue
        entity = row[0].strip()
        names[entity] = (row[1].strip(), row[3].strip())
        remarks.setdefault(entity, []).append(row[11])
    for row in csv.reader(io.StringIO(comments_csv)):
        if len(row) >= 2 and row[0].strip() in names:
            remarks[row[0].strip()].append(" ".join(row[1:]))
    found: dict[str, list[dict[str, Any]]] = {}
    for entity, texts in remarks.items():
        name, programs = names[entity]
        for currency, address in _ADDRESS.findall(" ".join(texts)):
            record = {"name": name, "programs": [p.strip() for p in programs.replace("]", "").split("[") if p.strip()]
                      or [programs], "currency": CURRENCIES.get(currency, currency), "entity": entity}  # fmt: skip
            bucket = found.setdefault(_key(address), [])
            if record not in bucket:
                bucket.append(record)
    return found


async def load(http: Any) -> None:
    """Fetch (or read) the list if the cached copy is older than a day. Never raises."""
    settings = get_settings()
    if not (settings.sanctions_file or settings.sanctions_sdn_url):
        return
    async with _lock():
        if _state.loaded_at and time.monotonic() - _state.loaded_at < TTL:
            return
        try:
            if settings.sanctions_file:
                folder = Path(settings.sanctions_file)
                sdn = await asyncio.to_thread((folder / "sdn.csv").read_text, encoding="latin-1")
                comments_file = folder / "sdn_comments.csv"
                comments = (
                    await asyncio.to_thread(comments_file.read_text, encoding="latin-1")
                    if comments_file.exists()
                    else ""
                )
                source = str(folder)
            else:
                sdn = await _download(http, settings.sanctions_sdn_url)
                comments = (
                    await _download(http, settings.sanctions_comments_url) if settings.sanctions_comments_url else ""
                )
                source = settings.sanctions_sdn_url
            parsed = await asyncio.to_thread(parse, sdn, comments)
            _state.by_address, _state.entries, _state.error, _state.source = parsed, len(parsed), None, source
            logger.info("Sanctions list: %d listed cryptocurrency addresses", len(parsed))
        except Exception as exc:  # noqa: BLE001 - no list must never stop a scan; it is reported instead
            _state.error = f"{type(exc).__name__}: {str(exc)[:160]}"
            logger.warning("Sanctions list unavailable (%s)", _state.error)
        _state.loaded_at = time.monotonic() - (TTL - 900 if _state.error and not _state.by_address else 0)


async def _download(http: Any, url: str) -> str:
    async with http.get(url, headers={"Accept": "text/csv,*/*"}) as resp:
        if resp.status != 200:
            raise ValueError(f"HTTP {resp.status}")
        body = await resp.content.read(MAX_FILE + 1)
    if len(body) > MAX_FILE:
        raise ValueError("the sanctions file is too large")
    return body.decode("latin-1")


def check(address: str) -> list[dict[str, Any]]:
    """Sanctions listings for ``address`` (empty if none, or if the list could not be loaded)."""
    return list(_state.by_address.get(_key(address), []))


def status() -> dict[str, Any]:
    return {"listed_addresses": _state.entries, "source": _state.source, "error": _state.error,
            "loaded": bool(_state.loaded_at) and not (_state.error and not _state.entries)}  # fmt: skip


def reset() -> None:
    global _state
    _state = _State()
