"""Investigator safety: egress routes (Tor, VPN, proxy) and how a case uses them.

People being investigated can see who looks at them: their web server logs every visitor's
address and browser. An investigator who visits from their own office, or from a server that
can be traced back to them, can tip off the subject.

The operator configures **routes** (``ARGUS_EGRESS_ROUTES``). Investigators only ever see a
route's name, kind and description: its address and credentials stay with the operator and are
never stored with a scan, capture or case.

A case can be **anonymous**: then nothing in it may touch its subjects directly. Captures must use
an anonymous route (Tor, or a route the operator marked anonymous), and scans started for the case
are passive and routed.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
from typing import Any

import aiohttp
from fastapi import APIRouter, Depends, HTTPException, Request

from argus.api.deps import WorkspaceContext, audit, in_workspace
from argus.core.http import NEUTRAL_USER_AGENT
from argus.core.settings import EgressRoute, Settings
from argus.evidence.guard_proxy import GuardProxy
from argus.security.auth import Role
from argus.security.ratelimit import SlidingWindowLimiter

router = APIRouter(prefix="/api/opsec", tags=["opsec"])
VIEWER = Depends(in_workspace(Role.VIEWER))
ANALYST = Depends(in_workspace(Role.ANALYST))
_check_limiter = SlidingWindowLimiter(limit=6, window=60)
CHECK_TIMEOUT = 40


def public_route(route: EgressRoute) -> dict[str, Any]:
    """What an investigator may know about a route: never its address or credentials."""
    return {"name": route.name, "kind": route.kind, "anonymous": route.is_anonymous, "description": route.description}


def find_route(settings: Settings, name: str | None) -> EgressRoute | None:
    """The route called ``name``; ``None`` (or "" / "direct") means a direct connection."""
    if not name or name == "direct":
        return None
    for route in settings.egress_routes:
        if route.name == name:
            return route
    raise HTTPException(status_code=422, detail=f"There is no route called {name!r}")


def route_for(settings: Settings, case: dict[str, Any] | None, override: str | None) -> EgressRoute | None:
    """The route a capture or scan uses: the one asked for, else the case's, else direct.

    An anonymous case refuses anything that would not hide where the request comes from.
    """
    name = override if override is not None else (case or {}).get("egress") or None
    route = find_route(settings, name)
    if case and case.get("opsec_mode") == "anonymous" and (route is None or not route.is_anonymous):
        raise HTTPException(
            status_code=409,
            detail="This case is anonymous: it must not touch its subjects directly. Choose an anonymous route "
            "(such as Tor), or change the case's safety settings.",
        )
    return route


def _address(body: bytes) -> tuple[str | None, bool | None]:
    """The caller's address (and whether it is a Tor exit) from an IP-echo service's reply."""
    text = body.decode("utf-8", "replace").strip()
    is_tor = None
    try:
        data = json.loads(text)
    except ValueError:
        data = None
    if isinstance(data, dict):
        is_tor = data.get("IsTor") if isinstance(data.get("IsTor"), bool) else None
        text = str(data.get("IP") or data.get("ip") or data.get("origin") or "")
    candidate = text.split(",")[0].strip()
    try:
        return str(ipaddress.ip_address(candidate)), is_tor
    except ValueError:
        return None, is_tor


async def _ask(url: str, settings: Settings, route: EgressRoute | None) -> tuple[str | None, bool | None]:
    async with (
        GuardProxy(allow_private=settings.allow_private_targets, upstream=route) as proxy,
        aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=CHECK_TIMEOUT), trust_env=False) as http,
        http.get(url, proxy=proxy.url, allow_redirects=False, headers={"User-Agent": NEUTRAL_USER_AGENT}) as resp,
    ):
        if resp.status != 200:
            raise aiohttp.ClientError(f"HTTP {resp.status}")
        return _address(await resp.content.read(4096))


async def check_route(route: EgressRoute, settings: Settings) -> dict[str, Any]:
    """Ask an IP-echo service who is calling, through the route and directly, and compare."""
    url = settings.egress_check_url
    result: dict[str, Any] = {"route": public_route(route), "working": False, "exit_ip": None, "is_tor": None,
                              "direct_ip": None, "hides_address": None, "error": None}  # fmt: skip
    routed, direct = await asyncio.gather(_ask(url, settings, route), _ask(url, settings, None),
                                          return_exceptions=True)  # fmt: skip
    if isinstance(routed, BaseException):
        result["error"] = "The route did not answer. Is the Tor or proxy service running and reachable?"
        return result
    result["exit_ip"], result["is_tor"] = routed
    result["working"] = result["exit_ip"] is not None
    if not isinstance(direct, BaseException):
        result["direct_ip"] = direct[0]
    if result["exit_ip"] and result["direct_ip"]:
        result["hides_address"] = result["exit_ip"] != result["direct_ip"]
    if result["hides_address"] is False:
        result["error"] = "The route leaks: sites see this server's own address through it"
    elif route.kind == "tor" and result["is_tor"] is False:
        result["error"] = "Traffic leaves through this route, but not through the Tor network"
    return result


@router.get("/routes")
async def list_routes(request: Request, ws: WorkspaceContext = VIEWER):
    """The egress routes investigators can choose (names and kinds only)."""
    settings: Settings = request.app.state.settings
    return {"routes": [public_route(r) for r in settings.egress_routes], "check_url": settings.egress_check_url}


@router.post("/routes/{name}/check")
async def verify_route(name: str, request: Request, ws: WorkspaceContext = ANALYST):
    """Check a route works and hides this server's address (asks an IP-echo service both ways)."""
    settings: Settings = request.app.state.settings
    route = find_route(settings, name)
    if route is None:
        raise HTTPException(status_code=422, detail="Choose a route to test")
    if not _check_limiter.hit(ws.principal.key_id):
        raise HTTPException(status_code=429, detail="Too many route tests; wait a minute")
    result = await check_route(route, settings)
    await audit(request, ws.principal, "opsec.route_check", name,
                details={"working": result["working"], "hides_address": result["hides_address"]})  # fmt: skip
    return result
