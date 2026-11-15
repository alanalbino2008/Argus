"""Account watching: notice when a subject's profile changes, or the account disappears.

People under scrutiny edit their profiles: a new name or employer, a deleted bio, a changed
photo, an account wiped the day a story runs. Each change can matter, and is easy to miss. A case
can **watch** an account. Argus re-reads it on a schedule and records:

* the profile as first seen (the baseline);
* every change, field by field (before and after), on the case's timeline;
* optionally, a full **evidence capture** of the profile page each time it changes, with the same
  fingerprints, timestamp and chain of custody as any other capture;
* when the account can no longer be found (deleted, renamed or suspended).

Reading uses each platform's official public API where Argus has one (GitHub, GitLab, Reddit,
Hacker News, Keybase, Dev.to, Mastodon, Docker Hub, Bluesky): name, bio, location, website,
employer, public email, linked accounts and a fingerprint of the profile picture. On any other
site in the username catalog Argus can still tell whether the account exists.

Checks go out through the case's route (Tor, VPN...). An anonymous case's watch never connects
directly: if its route is missing, the check is skipped and the watch says so.

An account is only reported gone after two checks in a row fail to find it, and only if the site
still finds an account known to exist, so a site blocking automated requests is not mistaken for
a deletion.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import quote

import aiohttp

from argus.core.http import NEUTRAL_USER_AGENT, HttpClient
from argus.core.models import EntityType, ScanConfig
from argus.core.settings import EgressRoute, Settings
from argus.evidence.guard_proxy import GuardProxy
from argus.intel.avatars import fetch_fingerprint
from argus.modules.identity.platforms import Platform
from argus.modules.identity.profile_enricher import EXTRACTORS, _facts
from argus.modules.identity.username_hunter import UsernameHunterModule, all_platforms
from argus.security.auth import Principal, Role
from argus.security.network import GuardedResolver, configured_proxy_hosts

logger = logging.getLogger("argus.account_watch")
WATCHER = Principal(key_id="account-watcher", name="account-watcher", role=Role.ANALYST)
RECHECK_MISSING = timedelta(hours=1)  # a missing account is re-checked soon, before it is reported gone
TRACKED = {
    "display_name": "Name", "bio": "Bio", "location": "Location", "website": "Website", "company": "Employer",
    "public_email": "Public email", "avatar_hash": "Profile picture", "links": "Linked accounts",
}  # fmt: skip
SHOWN = (*TRACKED, "created_at", "followers")


async def _github(session: HttpClient, handle: str) -> dict[str, Any] | None:
    async with session.get(f"https://api.github.com/users/{quote(handle)}",
                           headers={"Accept": "application/vnd.github+json"}) as resp:  # fmt: skip
        if resp.status != 200:
            return None
        user = await resp.json()
    links = [{"url": f"https://twitter.com/{user['twitter_username']}"}] if user.get("twitter_username") else []
    return _facts(display_name=user.get("name"), bio=user.get("bio"), location=user.get("location"),
                  website=user.get("blog"), company=user.get("company"), created_at=user.get("created_at"),
                  public_email=user.get("email"), followers=user.get("followers"),
                  avatar_url=user.get("avatar_url"), links=links)  # fmt: skip


READERS: dict[str, Callable[[HttpClient, str], Awaitable[dict[str, Any] | None]]] = {"GitHub": _github, **EXTRACTORS}


@dataclass
class Observation:
    exists: bool | None  # None: could not tell
    facts: dict[str, Any] = field(default_factory=dict)
    error: str = ""


def snapshot_of(facts: dict[str, Any]) -> dict[str, Any]:
    """The facts worth keeping, normalised so that formatting noise is never reported as a change."""
    out: dict[str, Any] = {}
    for key in SHOWN:
        value = facts.get(key)
        if key == "links":
            value = sorted({str(item.get("url", "")).rstrip("/").lower() for item in value or [] if item.get("url")})
        elif isinstance(value, str):
            value = " ".join(value.split())[:1000]
        if value not in (None, "", []):
            out[key] = value
    return out


def diff(before: dict[str, Any], after: dict[str, Any]) -> list[dict[str, Any]]:
    changes = []
    for key, label in TRACKED.items():
        old, new = before.get(key), after.get(key)
        if old != new:
            changes.append({"field": key, "label": label, "before": old, "after": new})
    return changes


def describe(change: dict[str, Any]) -> str:
    def show(value: Any) -> str:
        if value in (None, "", []):
            return "(none)"
        return ", ".join(value) if isinstance(value, list) else f"“{value}”"

    if change["field"] == "avatar_hash":
        return "Profile picture changed" if change["before"] and change["after"] else (
            "Profile picture added" if change["after"] else "Profile picture removed")  # fmt: skip
    if change["field"] == "exists":
        return str(change["after"])
    return f"{change['label']}: {show(change['before'])} → {show(change['after'])}"


def signature(platforms: list[Platform], name: str) -> Platform | None:
    return next((p for p in platforms if p.name.lower() == name.lower()), None)


async def present(http: HttpClient, platform: Platform, handle: str) -> bool:
    config = ScanConfig(target=handle, target_type=EntityType.USERNAME)
    return await UsernameHunterModule()._exists(platform, handle, http, config)


async def observe(http: HttpClient, platform: str, handle: str) -> Observation:
    """How the account looks now."""
    reader = READERS.get(platform)
    if reader is not None:
        try:
            facts = await reader(http, handle)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - a platform's odd answer is reported, not raised
            return Observation(None, error=f"{platform} did not answer as expected ({type(exc).__name__})")
        if facts:
            facts = {**facts, "avatar_hash": await fetch_fingerprint(http, facts.get("avatar_url"))}
            return Observation(True, snapshot_of(facts))
    sig = signature(await all_platforms(http), platform)
    if sig is None:
        return Observation(None, error="Argus cannot check this platform")
    try:
        return Observation(await present(http, sig, handle))
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # noqa: BLE001
        return Observation(None, error=f"{platform} could not be reached ({type(exc).__name__})")


@contextlib.asynccontextmanager
async def client(settings: Settings, route: EgressRoute | None) -> AsyncIterator[HttpClient]:
    """An HTTP client for one check: through the route if there is one, guarded either way."""
    timeout = aiohttp.ClientTimeout(total=45)
    if route is None:
        resolver = None if settings.allow_private_targets else GuardedResolver(trusted_hosts=configured_proxy_hosts())
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(resolver=resolver), timeout=timeout,
                                         trust_env=True) as session:  # fmt: skip
            yield HttpClient(session, max_retries=1, allow_private=settings.allow_private_targets)
        return
    async with (
        GuardProxy(allow_private=settings.allow_private_targets, upstream=route) as proxy,
        aiohttp.ClientSession(timeout=timeout, trust_env=False) as session,
    ):
        yield HttpClient(session, max_retries=1, allow_private=settings.allow_private_targets, proxy=proxy.url,
                         user_agent=NEUTRAL_USER_AGENT)  # fmt: skip


def profile_url(platform: str, handle: str, platforms: list[Platform]) -> str:
    sig = signature(platforms, platform)
    return sig.profile_url(handle) if sig else ""


class AccountWatcher:
    """Checks due watches (cluster-safe: each is claimed by exactly one replica)."""

    def __init__(self, repo: Any, cases: Any, settings: Settings, audit: Any,
                 capture: Callable[..., Awaitable[Any]] | None = None):  # fmt: skip
        self.repo, self.cases, self.settings, self.audit = repo, cases, settings, audit
        if capture is None:
            from argus.evidence.capture import capture_url

            capture = capture_url
        self.capture = capture
        self._running: set[asyncio.Task[Any]] = set()

    async def tick(self) -> list[dict[str, Any]]:
        return [await self.check(watch) for watch in await self.repo.due() if await self.repo.claim(watch["id"])]

    async def run_forever(self) -> None:
        while True:
            try:
                await self.tick()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("Account watch tick failed")
            await asyncio.sleep(self.settings.account_watch_poll_seconds)

    def _route(self, case: dict[str, Any]) -> tuple[EgressRoute | None, str]:
        name = case.get("egress") or ""
        route = next((r for r in self.settings.egress_routes if r.name == name), None) if name else None
        if name and route is None:
            return None, f"The case's route “{name}” is no longer configured"
        if case.get("opsec_mode") == "anonymous" and (route is None or not route.is_anonymous):
            return None, "This case is anonymous and has no anonymous route: the check was not made"
        return route, ""

    async def check(self, watch: dict[str, Any]) -> dict[str, Any]:
        """Look at the account now and record what changed. Never connects directly for an anonymous case."""
        case = await self.cases.info(watch["case_id"])
        if case is None:
            return watch
        route, refusal = self._route(case)
        if refusal:
            return await self.repo.record(watch["id"], status="error", message=refusal, snapshot=None,
                                          missing_count=watch["missing_count"], changes=[], exists=None,
                                          baseline=False) or watch  # fmt: skip
        try:
            async with client(self.settings, route) as http:
                seen = await observe(http, watch["platform"], watch["handle"])
                result = await self._apply(watch, case, seen, http)
        except (OSError, aiohttp.ClientError, asyncio.TimeoutError) as exc:
            result = {"status": "error", "message": f"The check failed ({type(exc).__name__})", "snapshot": None,
                      "missing_count": watch["missing_count"], "changes": [], "exists": None, "baseline": False}  # fmt: skip
        capture_id = None
        if result["changes"] and watch["capture_on_change"] and result["exists"] is not False and watch["profile_url"]:
            capture_id = await self._capture(watch, route, result["changes"])
        recheck_soon = result.pop("recheck_soon", False)
        saved = await self.repo.record(watch["id"], capture_id=capture_id, **result)
        if recheck_soon:
            await self.repo.update(watch["id"], watch["case_id"],
                                   next_check_at=datetime.now(timezone.utc) + RECHECK_MISSING)  # fmt: skip
        if result["changes"]:
            await self._report(watch, result["changes"], capture_id)
        return saved or watch

    async def _apply(self, watch: dict[str, Any], case: dict[str, Any], seen: Observation,
                     http: HttpClient) -> dict[str, Any]:  # fmt: skip
        before = watch["snapshot"]
        baseline = before is None
        out: dict[str, Any] = {"status": "active", "message": "", "snapshot": None, "missing_count": 0,
                               "changes": [], "exists": seen.exists, "baseline": baseline}  # fmt: skip
        if seen.exists is None:
            return {**out, "status": "error", "message": seen.error, "missing_count": watch["missing_count"],
                    "baseline": False}  # fmt: skip
        if seen.exists:
            now = {"exists": True, **seen.facts}
            if not seen.facts and before:  # only existence is known: keep the details last read
                now = {**before, "exists": True}
            out["snapshot"] = now
            if not baseline:
                out["changes"] = diff(before or {}, now)
                if before and before.get("exists") is False:
                    out["changes"].insert(0, {"field": "exists", "label": "Account", "before": "not found",
                                              "after": "The account is back"})  # fmt: skip
            out["message"] = "Watching: no changes yet" if baseline else ""
            return out
        missing = watch["missing_count"] + 1
        if baseline:
            return {**out, "status": "gone", "snapshot": {"exists": False}, "missing_count": missing,
                    "message": "The account was not found on the first check"}  # fmt: skip
        if before and before.get("exists") is False:
            return {**out, "status": "gone", "missing_count": missing, "message": "Still not found"}
        if missing < 2:
            return {**out, "status": watch["status"], "missing_count": missing, "recheck_soon": True,
                    "message": "Not found on the last check; checking again before reporting it gone"}  # fmt: skip
        sig = signature(await all_platforms(http), watch["platform"])
        if sig is not None and sig.known and not await _safe_present(http, sig, sig.known):
            return {**out, "exists": None, "status": "error", "missing_count": missing,
                    "message": f"{watch['platform']} is not answering checks reliably; not reported as deleted"}  # fmt: skip
        return {**out, "status": "gone", "missing_count": missing, "snapshot": {**(before or {}), "exists": False},
                "changes": [{"field": "exists", "label": "Account", "before": "exists",
                             "after": "The account can no longer be found (deleted, renamed or suspended)"}],
                "message": "The account can no longer be found"}  # fmt: skip

    async def _capture(self, watch: dict[str, Any], route: EgressRoute | None,
                       changes: list[dict[str, Any]]) -> str | None:  # fmt: skip
        try:
            capture = await self.capture(watch["profile_url"], self.settings, route)
        except Exception as exc:  # noqa: BLE001 - the change is still recorded without its capture
            logger.warning("Automatic capture of %s failed: %s", watch["profile_url"], type(exc).__name__)
            return None
        note = "Captured automatically when the profile changed: " + "; ".join(describe(c) for c in changes)
        saved = await self.cases.add_capture(watch["case_id"], watch["workspace_id"], capture,
                                             by=WATCHER.name, note=note[:1000])  # fmt: skip
        return str(saved["id"])

    async def _report(self, watch: dict[str, Any], changes: list[dict[str, Any]], capture_id: str | None) -> None:
        labels = ", ".join(c["label"] for c in changes)
        await self.cases.add_item(
            watch["case_id"], by=WATCHER.name, kind="event",
            title=f"{watch['platform']} @{watch['handle']}: {labels} changed"[:300]
            if changes[0]["field"] != "exists" else f"{watch['platform']} @{watch['handle']}: {changes[0]['after']}"[:300],
            body="\n".join(describe(c) for c in changes),
            data={"watch_id": watch["id"], "changes": changes, "capture_id": capture_id},
            occurred_at=datetime.now(timezone.utc),
        )  # fmt: skip
        await self.audit.record(WATCHER, "account_watch.change", watch["id"],
                                details={"case": watch["case_id"], "platform": watch["platform"],
                                         "handle": watch["handle"], "fields": [c["field"] for c in changes],
                                         "capture": capture_id},
                                workspace_id=watch["workspace_id"])  # fmt: skip


async def _safe_present(http: HttpClient, sig: Platform, handle: str) -> bool:
    try:
        return await present(http, sig, handle)
    except asyncio.CancelledError:
        raise
    except Exception:  # noqa: BLE001 - unreachable counts as "not answering"
        return False
