"""Brand watches: lookalike domains of the organisation's brand, found in Certificate Transparency.

Watch ``acme.com``: every day Argus asks the Certificate Transparency logs for new certificates
on names that imitate it (``acme-login.com``, ``acrne.com``, ``acme.com.evil.example``…) and
alerts on new ones. Domains the organisation owns can be listed so they are never reported.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from argus.api.deps import WorkspaceContext, audit, cooldown, in_workspace, throttle
from argus.intel.brand_watch import HOSTNAME
from argus.intel.lookalikes import registrable
from argus.security.auth import Role
from argus.security.ratelimit import SlidingWindowLimiter
from argus.storage.brand_watch_repo import MAX_WATCHES

router = APIRouter(prefix="/api", tags=["monitoring"])
VIEWER = Depends(in_workspace(Role.VIEWER))
ANALYST = Depends(in_workspace(Role.ANALYST))
MAX_ALLOW = 50
# Each draft asks RDAP (registrar and up to three networks); campaign drafts up to 30 domains.
_rdap_limiter = SlidingWindowLimiter(limit=10, window=60)


class BrandWatchRequest(BaseModel):
    domain: str = Field(min_length=3, max_length=253, examples=["acme.com"])
    allow: list[str] = Field(default_factory=list, max_length=MAX_ALLOW,
                             description="Other domains the organisation owns: never reported")  # fmt: skip
    interval_hours: Literal[24, 168] = Field(default=24, description="Every day (24) or every week (168)")
    web_check: str = Field(default="off", max_length=64,
                           description="Visit lookalikes' websites: 'off', 'direct', or an egress route's name")  # fmt: skip
    reference_urls: list[str] = Field(default_factory=list, max_length=5,
                                      description="Your pages lookalikes are compared with (default: your home page)")  # fmt: skip


class BrandWatchUpdate(BaseModel):
    allow: list[str] | None = Field(default=None, max_length=MAX_ALLOW)
    web_check: str | None = Field(default=None, max_length=64)
    reference_urls: list[str] | None = Field(default=None, max_length=5)


def _repo(request: Request) -> Any:
    return request.app.state.brand_watches


def _domain(value: str) -> str:
    name = value.strip().lower().removeprefix("https://").removeprefix("http://").split("/")[0].rstrip(".")
    if not HOSTNAME.match(name):
        raise HTTPException(status_code=422, detail=f"{value!r} is not a domain name")
    try:
        return registrable(name)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"{value!r} is not a domain name") from exc


def _web_check(request: Request, value: str) -> str:
    """'off', 'direct' or a configured route: visiting a phishing site tells its operator who looked."""
    from argus.api.opsec_routes import find_route

    value = value.strip() or "off"
    if value not in ("off", "direct") and find_route(request.app.state.settings, value) is None:
        raise HTTPException(status_code=422, detail=f"No route called '{value}' (see Settings → Investigator safety)")
    return value


def _references(values: list[str]) -> list[str]:
    """Pages of the brand's own to compare lookalikes with: full http(s) addresses."""
    urls = []
    for value in values:
        url = value.strip()
        if not url:
            continue
        if not re.match(r"^https?://[^/\s]+", url) or len(url) > 500:
            raise HTTPException(status_code=422, detail=f"{value!r} is not a web address (https://…)")
        urls.append(url)
    return list(dict.fromkeys(urls))


def _allow(values: list[str], own: str) -> list[str]:
    return sorted({d for d in (_domain(v) for v in values if v.strip()) if d != own})


@router.get("/brand-watches")
async def list_brand_watches(request: Request, ws: WorkspaceContext = VIEWER):
    """The workspace's brand watches, with the lookalikes found most recently."""
    return await _repo(request).list_watches(ws.id)


@router.post("/brand-watches", status_code=201)
async def create_brand_watch(body: BrandWatchRequest, request: Request, ws: WorkspaceContext = ANALYST):
    """Watch a brand. The first run (straight away) records the lookalikes that exist today and alerts
    only on certificates issued in the last 14 days."""
    domain = _domain(body.domain)
    allow = _allow(body.allow, domain)
    if await _repo(request).find(ws.id, domain):
        raise HTTPException(status_code=409, detail=f"{domain} is already watched")
    if await _repo(request).count(ws.id) >= MAX_WATCHES:
        raise HTTPException(status_code=422, detail=f"A workspace can watch up to {MAX_WATCHES} brands")
    web_check = _web_check(request, body.web_check)
    watch = await _repo(request).create(workspace_id=ws.id, domain=domain, allow=allow, web_check=web_check,
                                        interval_hours=body.interval_hours, by=ws.principal.name)  # fmt: skip
    if body.reference_urls:
        watch = await _repo(request).update(watch["id"], ws.id, reference_urls=_references(body.reference_urls))
    await audit(request, ws.principal, "brand_watch.create", watch["id"], details={"domain": domain})
    request.app.state.brand_watcher.kick()
    return watch


@router.patch("/brand-watches/{watch_id}")
async def update_brand_watch(watch_id: str, body: BrandWatchUpdate, request: Request, ws: WorkspaceContext = ANALYST):
    """Change the domains the organisation owns (never reported) or whether lookalikes' sites are visited."""
    current = await _repo(request).get(watch_id, ws.id)
    if current is None:
        raise HTTPException(status_code=404, detail="Brand watch not found")
    changes: dict[str, Any] = {}
    if body.allow is not None:
        changes["allow"] = _allow(body.allow, current["domain"])
    if body.web_check is not None:
        changes["web_check"] = _web_check(request, body.web_check)
    if body.reference_urls is not None:
        changes["reference_urls"] = _references(body.reference_urls)
    updated = await _repo(request).update(watch_id, ws.id, **changes)
    await audit(request, ws.principal, "brand_watch.update", watch_id,
                details={"allow": len(updated["allow"]), "web_check": updated["web_check"]})  # fmt: skip
    return updated


@router.post("/brand-watches/{watch_id}/run", status_code=202)
async def run_brand_watch(watch_id: str, request: Request, ws: WorkspaceContext = ANALYST):
    """Run a watch now. Not more often than every 10 minutes (each run spends Cert Spotter queries)."""
    current = await _repo(request).get(watch_id, ws.id)
    if current is not None:
        cooldown(current.get("last_run_at"), request.app.state.settings.watch_run_cooldown_seconds, "brand watch")
    if not await _repo(request).make_due(watch_id, ws.id):
        raise HTTPException(status_code=404, detail="Brand watch not found")
    await audit(request, ws.principal, "brand_watch.run", watch_id)
    request.app.state.brand_watcher.kick()
    return {"queued": True}


@router.delete("/brand-watches/{watch_id}", status_code=204)
async def delete_brand_watch(watch_id: str, request: Request, ws: WorkspaceContext = ANALYST):
    if not await _repo(request).delete(watch_id, ws.id):
        raise HTTPException(status_code=404, detail="Brand watch not found")
    await audit(request, ws.principal, "brand_watch.delete", watch_id)
    return Response(status_code=204)


# ----------------------------------------------------------------------------- takedowns
class TakedownRequest(BaseModel):
    domain: str = Field(min_length=3, max_length=253, description="A lookalike this watch found")
    organisation: str = Field(default="", max_length=200, description="Who the report is from (signs it)")


class TakedownClose(BaseModel):
    reason: str = Field(default="", max_length=300)


@router.post("/brand-watches/{watch_id}/takedowns", status_code=201)
async def draft_takedown(watch_id: str, body: TakedownRequest, request: Request, ws: WorkspaceContext = ANALYST):
    """Draft an abuse report for a lookalike: its registrar's and host's abuse contacts (from RDAP) and
    the evidence triage found. Argus does not send it: send it from your mailbox, then mark it reported."""
    from argus.intel import takedown

    watch = await _repo(request).get(watch_id, ws.id)
    if watch is None:
        raise HTTPException(status_code=404, detail="Brand watch not found")
    name = body.domain.strip().lower()
    finding = await _repo(request).lookalike(watch_id, ws.id, name)
    if finding is None:
        raise HTTPException(status_code=404, detail="This watch has not found that domain")
    current = finding.get("takedown")
    if current and current.get("status") in ("drafted", "reported"):
        raise HTTPException(status_code=409, detail="A takedown is already open for this domain")
    triage = finding.get("triage") or {}
    throttle(_rdap_limiter, ws.principal.key_id, "Too many takedown look-ups; wait a minute")
    found = await request.app.state.brand_watcher.takedown_contacts(name, (triage.get("dns") or {}).get("ips") or [])
    letter = takedown.draft(domain=name, display=finding.get("display") or name, brand=watch["domain"],
                            finding=finding, triage=triage, found=found, organisation=body.organisation.strip())  # fmt: skip
    record = await _repo(request).put_takedown(
        watch_id, ws.id, name,
        {"status": "drafted", "contacts": found, "draft": letter, "created_by": ws.principal.name,
         "verdict_at_report": triage.get("verdict"), "misses": 0},
        {"event": "drafted", "by": ws.principal.name},
    )  # fmt: skip
    await audit(
        request, ws.principal, "takedown.draft", watch_id, details={"domain": name, "recipients": len(letter["to"])}
    )
    return record


@router.post("/brand-watches/{watch_id}/takedowns/{domain}/reported")
async def takedown_reported(watch_id: str, domain: str, request: Request, ws: WorkspaceContext = ANALYST):
    """Record that the abuse report was sent; Argus then watches for the domain going down."""
    record = await _takedown(request, ws, watch_id, domain)
    if record.get("status") not in ("drafted", "reported"):
        raise HTTPException(status_code=409, detail=f"This takedown is {record.get('status')}")
    from datetime import datetime, timezone

    changed = await _repo(request).put_takedown(
        watch_id, ws.id, domain, {"status": "reported", "reported_at": datetime.now(timezone.utc).isoformat(),
                                  "reported_by": ws.principal.name},
        {"event": "reported", "by": ws.principal.name},
    )  # fmt: skip
    await audit(request, ws.principal, "takedown.reported", watch_id, details={"domain": domain})
    return changed


@router.post("/brand-watches/{watch_id}/takedowns/{domain}/close")
async def takedown_close(
    watch_id: str, domain: str, body: TakedownClose, request: Request, ws: WorkspaceContext = ANALYST
):
    """Stop tracking a takedown (refused, handled elsewhere, a false alarm)."""
    await _takedown(request, ws, watch_id, domain)
    changed = await _repo(request).put_takedown(
        watch_id, ws.id, domain, {"status": "closed", "close_reason": body.reason.strip()},
        {"event": "closed", "by": ws.principal.name, "reason": body.reason.strip()},
    )  # fmt: skip
    await audit(request, ws.principal, "takedown.close", watch_id, details={"domain": domain})
    return changed


async def _takedown(request: Request, ws: WorkspaceContext, watch_id: str, domain: str) -> dict[str, Any]:
    item = await _repo(request).lookalike(watch_id, ws.id, domain.strip().lower())
    record = (item or {}).get("takedown")
    if record is None:
        raise HTTPException(status_code=404, detail="No takedown for that domain")
    return dict(record)


# ----------------------------------------------------------------------------- lookalike -> case
class LookalikeCase(BaseModel):
    case_id: str | None = Field(default=None, description="Add to this case instead of opening a new one")
    capture: bool = Field(default=True, description="Capture the lookalike's website as evidence")
    confirmed: bool = Field(default=False, description="Confirms a legitimate purpose (needed for a new case)")


def _day(value: Any) -> datetime | None:
    try:
        moment = datetime.fromisoformat(str(value).replace("Z", "+00:00")) if value else None
    except ValueError:
        return None
    return moment.replace(tzinfo=timezone.utc) if moment and moment.tzinfo is None else moment


@router.post("/brand-watches/{watch_id}/lookalikes/{domain}/case", status_code=201)
async def lookalike_case(watch_id: str, domain: str, body: LookalikeCase, request: Request,
                         ws: WorkspaceContext = ANALYST):  # fmt: skip
    """Open a case for a lookalike (or add it to one): the domain, what it imitates and how, its timeline
    (first certificate, found by Argus, takedown steps), the triage evidence, and a capture of its website
    as preserved evidence (through the watch's route). Ready for a takedown escalation or legal action."""
    from argus.api.case_routes import _case
    from argus.api.opsec_routes import find_route, route_for
    from argus.evidence.capture import CaptureError, capture_url

    watch = await _repo(request).get(watch_id, ws.id)
    item = await _repo(request).lookalike(watch_id, ws.id, domain.strip().lower()) if watch else None
    if watch is None or item is None:
        raise HTTPException(status_code=404, detail="This watch has not found that domain")
    if body.capture:  # the same limit as "Capture a page" (each runs a browser), checked before anything is created
        from argus.api.case_routes import _limit as capture_limit

        capture_limit(ws)
    cases, settings, name = request.app.state.cases, request.app.state.settings, item["name"]
    triage = item.get("triage") or {}
    if body.case_id:
        case = await _case(request, ws, body.case_id)
    else:
        if not body.confirmed:
            raise HTTPException(status_code=422, detail="Confirm there is a legitimate purpose for this case")
        mode = watch.get("web_check") or "off"
        route = find_route(settings, mode) if mode not in ("off", "direct") else None
        case = await cases.create(
            workspace_id=ws.id, by=ws.principal.name, title=f"Lookalike {item.get('display') or name} imitating {watch['domain']}"[:200],
            purpose=f"Brand protection: {name} imitates {watch['domain']}; preserve evidence for takedown and legal action",
            summary="\n".join(f"- {r}" for r in triage.get("reasons") or []),
            tags=["brand-protection", *([triage["verdict"]] if triage.get("verdict") else [])],
            egress=route.name if route else "", opsec_mode="anonymous" if route and route.is_anonymous else "standard",
        )  # fmt: skip
        await audit(request, ws.principal, "case.create", case["id"],
                    details={"title": case["title"], "from_lookalike": name, "route": case["egress"] or "direct"})  # fmt: skip

    by = ws.principal.name
    reg = ((item.get("takedown") or {}).get("contacts") or {}).get("registrar") or {}
    attributes = {k: v for k, v in {
        "imitates": watch["domain"], "technique": f"{item.get('technique') or ''}: {item.get('detail') or ''}".strip(": "),
        "verdict": triage.get("label") or item.get("verdict") or "", "severity": item.get("severity") or "",
        "addresses": ", ".join((triage.get("dns") or {}).get("ips") or []),
        "mail servers": ", ".join((triage.get("dns") or {}).get("mx") or []),
        "registrar": reg.get("registrar") or "", "takedown": (item.get("takedown") or {}).get("status") or "",
    }.items() if v}  # fmt: skip
    added = [await cases.add_item(case["id"], by=by, kind="entity", title=item.get("display") or name,
                                  data={"type": "domain", "value": name, "attributes": attributes})]  # fmt: skip
    ours = await cases.add_item(case["id"], by=by, kind="entity", title=watch["domain"],
                                data={"type": "domain", "value": watch["domain"], "attributes": {"role": "our domain"}})  # fmt: skip
    added.append(ours)
    added.append(await cases.add_item(case["id"], by=by, kind="link", title="link", data={
        "from": added[0]["id"], "to": ours["id"], "relation": "other", "label": "imitates", "confidence": "confirmed"}))  # fmt: skip
    events = [("First certificate issued" + (f" ({item['issuer']})" if item.get("issuer") else ""), item.get("not_before")),
              ("Found by the Argus brand watch", item.get("first_seen"))]  # fmt: skip
    events.extend(
        (f"Takedown {step['event']}" + (f" by {step['by']}" if step.get("by") else ""), step.get("at"))
        for step in (item.get("takedown") or {}).get("history") or []
        if step.get("event") in ("drafted", "reported", "down", "closed")
    )
    for title, when in events:
        moment = _day(when)
        if moment is not None:
            added.append(await cases.add_item(case["id"], by=by, kind="event", title=title[:300], occurred_at=moment))
    if triage.get("reasons"):
        added.append(await cases.add_item(case["id"], by=by, kind="note", title=f"Why {name} is a threat",
                                          body="\n".join(f"- {r}" for r in triage["reasons"])))  # fmt: skip

    capture, warning = None, None
    if body.capture:
        try:
            route = route_for(settings, case, None)  # an anonymous case never captures directly
            evidence = await capture_url(f"https://{name}/", settings, route)
            capture = await cases.add_capture(case["id"], ws.id, evidence, by=by,
                                              note=f"Captured from the brand watch for {watch['domain']}")  # fmt: skip
            await audit(request, ws.principal, "evidence.capture", capture["id"],
                        details={"case": case["id"], "url": f"https://{name}/", "digest": capture["digest"],
                                 "route": route.name if route else "direct"})  # fmt: skip
        except HTTPException as exc:
            warning = str(exc.detail)
        except CaptureError as exc:
            warning = f"The website could not be captured: {exc}"
    await _repo(request).set_case(watch_id, ws.id, name, case["id"])
    await audit(
        request, ws.principal, "brand_watch.case", case["id"], details={"domain": name, "captured": bool(capture)}
    )
    return {"case": case, "items": len(added), "capture": capture, "warning": warning}
