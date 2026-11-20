"""Fingerprint watches: re-run a fingerprint's Shodan or Censys search on a schedule.

A favicon hash, JARM, HASSH or certificate shared by a handful of servers is often one operator's
infrastructure. A watch re-runs the entity's own internet-wide search (never free text) every day
or week and remembers which servers it has seen. The first run is the **baseline**; after that,
servers that start sharing the fingerprint raise one alert per run.

Each run spends one search credit (Shodan ``search``; Censys depends on the plan), so watches are
capped per workspace and checks are claimed atomically: with several replicas, a watch runs once.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from typing import Any

import aiohttp

from argus.accounts import features
from argus.core.settings import Settings
from argus.intel import internet_search
from argus.intel.account_watch import client as outbound_client
from argus.storage.fingerprint_watch_repo import FingerprintWatchRepository

logger = logging.getLogger("argus.fingerprint_watch")
ENGINE_NAMES = {"shodan": "Shodan", "censys": "Censys"}
ALERT_SAMPLE = 20  # new servers named in an alert
POLL_SECONDS = 300.0

Search = Callable[[str, str], Awaitable[dict[str, Any]]]  # (engine, query) -> internet_search result
RaiseAlert = Callable[[dict[str, Any], list[dict[str, Any]], int], Awaitable[dict[str, Any] | None]]


def engine_keys(settings: Settings) -> dict[str, str]:
    def secret(value: Any) -> str:
        return value.get_secret_value().strip() if value else ""

    return {"shodan": secret(settings.shodan_api_key), "censys": secret(settings.censys_api_token)}


def server_key(host: dict[str, Any]) -> str | None:
    """A server is its address and port: the same fingerprint on a new port of a known host is news too."""
    if not host.get("ip"):
        return None
    return f"{host['ip']}:{host['port']}" if host.get("port") else str(host["ip"])


def alert_summary(watch: dict[str, Any], new: list[dict[str, Any]], total: int) -> dict[str, Any]:
    return {
        "fingerprint_watch": {
            "id": watch["id"],
            "engine": watch["engine"],
            "label": watch["label"],
            "query": watch["query"],
            "entity_id": watch["entity_id"],
            "new_count": len(new),
            "total_count": total,
            "new_servers": [
                {k: h.get(k) for k in ("ip", "port", "org", "country", "hostnames")} for h in new[:ALERT_SAMPLE]
            ],
        }
    }


def alert_headline(watch: dict[str, Any], new_count: int) -> str:
    plural = "s" if new_count != 1 else ""
    return f"{new_count} new server{plural} share {watch['label']} ({ENGINE_NAMES[watch['engine']]})"


class FingerprintWatcher:
    def __init__(
        self,
        repo: FingerprintWatchRepository,
        settings: Settings,
        *,
        raise_alert: RaiseAlert,
        search: Search | None = None,
        poll_seconds: float = POLL_SECONDS,
    ):
        self.repo = repo
        self.settings = settings
        self.raise_alert = raise_alert
        self.search = search or self._search
        self.poll_seconds = poll_seconds
        self._running: set[asyncio.Task[Any]] = set()

    async def _search(self, engine: str, query: str) -> dict[str, Any]:
        key = engine_keys(self.settings)[engine]
        if not key:
            raise internet_search.SearchError(409, f"No {ENGINE_NAMES[engine]} key is configured")
        async with outbound_client(self.settings, None) as http:
            if engine == "shodan":
                return await internet_search.shodan(http, key, query, mode="search")
            return await internet_search.censys(
                http, key, query, mode="search", organization=self.settings.censys_organization_id
            )

    # ------------------------------------------------------------------ the loop
    async def tick(self) -> list[dict[str, Any]]:
        outcomes: list[dict[str, Any]] = []
        if not features.allows("monitoring"):
            return outcomes
        for watch in await self.repo.due():
            if not await self.repo.claim(watch["id"]):
                continue  # another replica took it
            outcomes.append(await self.check(watch))
        return outcomes

    def kick(self) -> None:
        """Run a tick soon, in the background (after "run now")."""
        task = asyncio.create_task(self.tick(), name="fingerprint-watch")
        self._running.add(task)
        task.add_done_callback(self._running.discard)

    async def run_forever(self) -> None:
        while True:
            try:
                await self.tick()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("Fingerprint watch tick failed")
            await asyncio.sleep(self.poll_seconds)

    # ------------------------------------------------------------------ one run
    async def check(self, watch: dict[str, Any]) -> dict[str, Any]:
        name = ENGINE_NAMES[watch["engine"]]
        try:
            result = await self.search(watch["engine"], watch["query"])
        except internet_search.SearchError as exc:
            await self.repo.record(watch["id"], status="error", message=str(exc.detail))
            return {"watch_id": watch["id"], "status": "error", "new": 0, "alert": None}
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
            await self.repo.record(watch["id"], status="error", message=f"{name} could not be reached")
            return {"watch_id": watch["id"], "status": "error", "new": 0, "alert": None}
        known = await self.repo.known(watch["id"])
        seen = set(known)
        baseline = not watch.get("baselined")
        new_hosts: list[dict[str, Any]] = []
        for host in result.get("hosts") or []:
            key = server_key(host)
            if key and key not in seen:
                seen.add(key)
                known.append(key)
                new_hosts.append(host)
        total = int(result.get("total") or 0)
        alert = None
        if new_hosts and not baseline:
            try:
                alert = await self.raise_alert(watch, new_hosts, total)
            except Exception:  # an alert that fails must not lose the servers: they are recorded below
                logger.exception("Raising the alert for fingerprint watch %s failed", watch["id"])
        if baseline:
            message = f"Baseline: {len(new_hosts)} server(s) of {total} recorded"
        else:
            message = f"{len(new_hosts)} new server(s); {total} share it in all"
        await self.repo.record(
            watch["id"], status="ok", total=total, known=known,
            new=[server_key(h) or "" for h in new_hosts] if not baseline else [], message=message,
            alerted=alert is not None,
        )  # fmt: skip
        logger.info("Fingerprint watch %s: %s", watch["id"], message)
        return {
            "watch_id": watch["id"],
            "status": "ok",
            "baseline": baseline,
            "new": 0 if baseline else len(new_hosts),
            "alert": alert["id"] if alert else None,
        }
