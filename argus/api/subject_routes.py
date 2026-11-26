"""Known details: a person in a case, everything known about them, one run from all of it, and review.

* ``POST /api/cases/{case}/subjects`` adds a person with what is known (names, usernames, emails,
  phones, profile links, websites, town, employer, year of birth);
* ``POST .../subjects/{id}/photo`` adds a known photo: only its fingerprint is kept, to recognise the
  same picture on a profile; the image itself is not stored;
* ``POST .../subjects/{id}/run`` searches from every known detail not searched before, follows the
  candidates that match very well, and scores everything found against what is known;
* ``POST .../candidates/{cid}/confirm`` and ``.../reject`` record the investigator's judgement.

Runs use the case's route, are passive-only in an anonymous case, count against the workspace's
quotas, and are audited scan by scan like playbooks. See :mod:`argus.intel.subjects`.
"""

from __future__ import annotations

import asyncio
import logging
import secrets
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from pydantic import BaseModel, Field

from argus.api.case_routes import _case
from argus.api.deps import WorkspaceContext, audit, in_workspace
from argus.api.opsec_routes import route_for
from argus.api.playbook_routes import RUNS, ScanFn, _available
from argus.core.models import ScanConfig
from argus.intel import subjects as S
from argus.intel.avatars import fingerprint
from argus.security.auth import Principal, Role
from argus.security.network import validate_scan_target
from argus.security.quotas import QuotaExceeded
from argus.storage.db import SubjectRow

logger = logging.getLogger("argus.subjects")
router = APIRouter(prefix="/api", tags=["subjects"])
VIEWER = Depends(in_workspace(Role.VIEWER))
ANALYST = Depends(in_workspace(Role.ANALYST))
MAX_SEARCHES = 40  # per run, however many details and follow-ups there are
MAX_PHOTO = 5 * 1024 * 1024
WATCH_DAYS = 7


class Known(BaseModel):
    names: list[str] = Field(default_factory=list, description="Full names, and other names they use")
    usernames: list[str] = Field(default_factory=list)
    emails: list[str] = Field(default_factory=list)
    phones: list[str] = Field(default_factory=list, description="With the country code")
    profiles: list[str] = Field(default_factory=list, description="Links to their accounts")
    websites: list[str] = Field(default_factory=list)
    city: str = Field(default="", max_length=200)
    employer: str = Field(default="", max_length=200)
    birth_year: int | None = Field(default=None, description="Only used to rule matches out")
    utc_offset: str | None = Field(default=None, max_length=6, description="Their usual time zone, e.g. +01:00")


class SubjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=300, description="How the person is referred to in the case")
    known: Known = Field(default_factory=Known)
    confirmed: bool = Field(description="Confirms there is a legitimate purpose for researching this person")


class SubjectUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=300)
    known: Known | None = None


class RunRequest(BaseModel):
    confirmed: bool = Field(description="Confirms there is a legitimate purpose for researching this person")
    rounds: int = Field(default=2, ge=1, le=3, description="How far to follow what is found (1: known details only)")
    fresh: bool = Field(default=False, description="Search again from details already searched")


class Decision(BaseModel):
    search: bool = Field(default=False, description="Confirming: search from it straight away")
    note: str = Field(default="", max_length=500)


class WatchRequest(BaseModel):
    on: bool


def _clean(known: dict[str, Any], keep_photo: str | None = None) -> dict[str, Any]:
    try:
        cleaned = S.clean_known({**known, "photo_hash": keep_photo})
    except S.KnownDetailsError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return cleaned


async def _subject(request: Request, ws: WorkspaceContext, case_id: str, subject_id: str) -> tuple[dict, dict]:
    case = await _case(request, ws, case_id)
    subject = await request.app.state.subjects.get(subject_id, case_id)
    if subject is None:
        raise HTTPException(status_code=404, detail="Person not found in this case")
    return case, subject


def _open(case: dict[str, Any]) -> None:
    if case["status"] != "open":
        raise HTTPException(status_code=409, detail="Reopen the case to change it")


@router.get("/cases/{case_id}/subjects")
async def list_subjects(case_id: str, request: Request, ws: WorkspaceContext = VIEWER):
    await _case(request, ws, case_id)
    return await request.app.state.subjects.for_case(case_id)


@router.post("/cases/{case_id}/subjects", status_code=201)
async def create_subject(case_id: str, body: SubjectCreate, request: Request, ws: WorkspaceContext = ANALYST):
    """Add a person to research, with everything already known about them."""
    case = await _case(request, ws, case_id)
    _open(case)
    if not body.confirmed:
        raise HTTPException(status_code=422, detail="Confirm there is a legitimate purpose for researching this person")
    known = _clean(body.known.model_dump())
    subject = await request.app.state.subjects.create(workspace_id=ws.id, case_id=case_id, name=body.name.strip(),
                                                      known=known, by=ws.principal.name)  # fmt: skip
    await audit(request, ws.principal, "subject.create", subject["id"],
                details={"case": case_id, "known": {k: len(v) for k, v in known.items() if isinstance(v, list)},
                         "purpose": case["purpose"]})  # fmt: skip
    return subject


@router.get("/cases/{case_id}/subjects/{subject_id}")
async def get_subject(case_id: str, subject_id: str, request: Request, ws: WorkspaceContext = VIEWER):
    return (await _subject(request, ws, case_id, subject_id))[1]


@router.put("/cases/{case_id}/subjects/{subject_id}")
async def update_subject(case_id: str, subject_id: str, body: SubjectUpdate, request: Request,
                         ws: WorkspaceContext = ANALYST):  # fmt: skip
    """Change the name or the known details; open candidates are scored again against them."""
    case, subject = await _subject(request, ws, case_id, subject_id)
    _open(case)
    known = _clean(body.known.model_dump(), subject["known"].get("photo_hash")) if body.known is not None else None

    def apply(row: SubjectRow, data: dict[str, Any]) -> None:
        if body.name is not None:
            row.name = body.name.strip()
        if known is not None:
            data["known"] = known
            _settle(data)

    updated, _ = await request.app.state.subjects.change(subject_id, apply)
    await audit(request, ws.principal, "subject.update", subject_id, details={"case": case_id})
    return updated


def _settle(data: dict[str, Any]) -> None:
    """After the known details change: candidates now known are confirmed, the rest scored again."""
    keys = S.known_keys(data["known"])
    for cand in data["candidates"].values():
        if cand.get("status") == "open" and cand["key"] in keys:
            cand["status"] = "confirmed"
    S.rescore(data["candidates"], data["known"])


@router.delete("/cases/{case_id}/subjects/{subject_id}", status_code=204)
async def delete_subject(case_id: str, subject_id: str, request: Request, ws: WorkspaceContext = ANALYST):
    case, subject = await _subject(request, ws, case_id, subject_id)
    _open(case)
    if subject["status"] == "running":
        raise HTTPException(status_code=409, detail="Stop the search first")
    await request.app.state.subjects.delete(subject_id)
    await audit(request, ws.principal, "subject.delete", subject_id, details={"case": case_id})


@router.post("/cases/{case_id}/subjects/{subject_id}/photo")
async def add_photo(case_id: str, subject_id: str, request: Request, file: UploadFile = File(...),
                    ws: WorkspaceContext = ANALYST):  # fmt: skip
    """A known photo of the person. Only a fingerprint of it is kept (to recognise the same picture on a
    profile found); the image itself is not stored."""
    case, _ = await _subject(request, ws, case_id, subject_id)
    _open(case)
    data = await file.read(MAX_PHOTO + 1)
    if len(data) > MAX_PHOTO:
        raise HTTPException(status_code=413, detail="The photo is larger than 5 MB")
    digest = await asyncio.to_thread(fingerprint, data)
    if digest is None:
        raise HTTPException(status_code=422, detail="That is not a photo Argus can recognise again (too small, "
                                                    "blank, or not an image)")  # fmt: skip

    def apply(row: SubjectRow, d: dict[str, Any]) -> None:
        d["known"] = {**d.get("known", {}), "photo_hash": digest}
        _settle(d)

    updated, _ = await request.app.state.subjects.change(subject_id, apply)
    await audit(request, ws.principal, "subject.photo", subject_id, details={"case": case_id})
    return updated


@router.delete("/cases/{case_id}/subjects/{subject_id}/photo")
async def remove_photo(case_id: str, subject_id: str, request: Request, ws: WorkspaceContext = ANALYST):
    case, _ = await _subject(request, ws, case_id, subject_id)
    _open(case)

    def apply(row: SubjectRow, d: dict[str, Any]) -> None:
        d["known"] = {**d.get("known", {}), "photo_hash": None}
        _settle(d)

    updated, _ = await request.app.state.subjects.change(subject_id, apply)
    return updated


# ---------------------------------------------------------------------------- runs
@router.post("/cases/{case_id}/subjects/{subject_id}/run", status_code=202)
async def run_subject(case_id: str, subject_id: str, body: RunRequest, request: Request,
                      ws: WorkspaceContext = ANALYST):  # fmt: skip
    """Search from everything known (not searched before, unless ``fresh``). Runs in the background."""
    case, subject = await _subject(request, ws, case_id, subject_id)
    if not body.confirmed:
        raise HTTPException(status_code=422, detail="Confirm there is a legitimate purpose for researching this person")
    return await start(request.app, case, subject, ws.principal, ws.id, rounds=body.rounds, fresh=body.fresh,
                       reason="manual", request=request)  # fmt: skip


@router.post("/cases/{case_id}/subjects/{subject_id}/run/cancel")
async def cancel_subject_run(case_id: str, subject_id: str, request: Request, ws: WorkspaceContext = ANALYST):
    """Stop the search: a scan already running finishes, and nothing after it starts."""
    await _subject(request, ws, case_id, subject_id)

    def apply(row: SubjectRow, data: dict[str, Any]) -> bool:
        run = data.get("run") or {}
        if row.status != "running" or run.get("status") != "running":
            return False
        data["run"] = {**run, "status": "cancelled", "finished_at": _now()}
        row.status = "idle"
        return True

    updated, stopped = await request.app.state.subjects.change(subject_id, apply)
    if not stopped:
        raise HTTPException(status_code=409, detail="No search is running for this person")
    await audit(request, ws.principal, "subject.cancel", subject_id, details={"case": case_id})
    return updated


async def start(app: Any, case: dict[str, Any], subject: dict[str, Any], principal: Principal, workspace_id: str, *,
                rounds: int, fresh: bool, reason: str, request: Request | None = None) -> dict[str, Any]:  # fmt: skip
    """Start a run for a subject (by hand, after a confirmation, or by its watch)."""
    if case["status"] != "open":
        raise HTTPException(status_code=409, detail="Reopen the case to search from it")
    settings = app.state.settings
    route = route_for(settings, case, None)  # 409 if it would expose an anonymous case
    data = await app.state.subjects.data(subject["id"]) or {}
    first = S.searches(data.get("known") or {}, set() if fresh else set(data.get("searched") or []))
    if not first:
        raise HTTPException(status_code=409, detail="Everything known about this person has already been searched. "
                                                    "Add a detail, confirm a candidate, or search again from the start")  # fmt: skip
    for search in first:
        if search["kind"] == "website" and not settings.allow_private_targets:
            try:
                validate_scan_target(search["value"], S.SEARCHES["website"]["type"])
            except ValueError as exc:
                raise HTTPException(status_code=422, detail=f"{search['value']}: {exc}") from exc
    if not await app.state.scan_limiter.allow(principal.key_id):
        raise HTTPException(status_code=429, detail="Scan rate limit exceeded")
    run_id = f"sr_{secrets.token_hex(8)}"
    steps = [{**s, "round": 1, "status": "pending", "detail": ""} for s in first[:MAX_SEARCHES]]
    run = {"id": run_id, "status": "running", "reason": reason, "rounds": rounds, "by": principal.name,
           "owner": settings.instance_id, "started_at": _now(), "finished_at": None, "steps": steps, "new": 0,
           "route": route.name if route else "direct", "passive_only": case["opsec_mode"] == "anonymous"}  # fmt: skip

    def claim(row: SubjectRow, data: dict[str, Any]) -> bool:
        if row.status == "running":
            return False
        row.status = "running"
        data["run"] = run
        return True

    updated, claimed = await app.state.subjects.change(subject["id"], claim)
    if not claimed:
        raise HTTPException(
            status_code=409, detail="A search is already running for this person; wait for it or stop it"
        )
    details = {"case": case["id"], "searches": len(steps), "rounds": rounds, "reason": reason,
               "route": run["route"], "purpose": case["purpose"]}  # fmt: skip
    if request is not None:
        await audit(request, principal, "subject.run", subject["id"], details=details)
    else:
        await app.state.audit.record(principal, "subject.run", subject["id"], "success", None, details, workspace_id)
    runner = SubjectRun(app, subject["id"], run_id, case, principal, workspace_id, route, rounds, reason=reason)
    task = asyncio.create_task(runner.run(), name=f"subject-{run_id}")
    RUNS[run_id] = task
    task.add_done_callback(lambda _t: RUNS.pop(run_id, None))
    return updated


class SubjectRun:
    """Searches each known detail, merges and scores what is found, and follows the best matches."""

    def __init__(self, app: Any, subject_id: str, run_id: str, case: dict[str, Any], principal: Principal,
                 workspace_id: str, route: Any, rounds: int, reason: str = "manual"):  # fmt: skip
        self.app, self.subject_id, self.run_id, self.case, self.reason = app, subject_id, run_id, case, reason
        self.principal, self.workspace_id, self.route, self.rounds = principal, workspace_id, route, rounds
        self.new_ids: list[str] = []

    async def _change(self, fn: Any) -> Any:
        _, result = await self.app.state.subjects.change(self.subject_id, fn)
        return result

    def _mine(self, row: SubjectRow, data: dict[str, Any]) -> dict[str, Any] | None:
        run = data.get("run") or {}
        return run if run.get("id") == self.run_id and run.get("status") == "running" else None

    async def _finish(self, status: str, error: str | None = None) -> None:
        def apply(row: SubjectRow, data: dict[str, Any]) -> None:
            run = self._mine(row, data)
            if run is None:
                return
            data["run"] = {**run, "status": status, "finished_at": _now(), **({"error": error[:300]} if error else {})}
            row.status = "idle"

        await self._change(apply)
        if self.reason == "watch" and status == "completed":
            await self._alert()

    async def _alert(self) -> None:
        """A watch found new candidates worth looking at: one alert, naming neither the person nor the accounts
        (alerts can be sent to chat and email); the details stay in the case."""
        subject = await self.app.state.subjects.get(self.subject_id)
        if subject is None:
            return
        worth = [c for c in subject["candidates"] if c["id"] in self.new_ids and c.get("status") == "open"
                 and c.get("verdict") in ("likely", "possible")]  # fmt: skip
        if not worth:
            return
        likely = sum(1 for c in worth if c["verdict"] == "likely")
        plural = "s" if len(worth) != 1 else ""
        alert = await self.app.state.monitors.create_alert(
            monitor_id=None, investigation_id="", previous_investigation_id="", target=f"case {self.case['id']}",
            severity="medium" if likely else "low",
            headline=f"Known-details watch: {len(worth)} new candidate{plural} to review ({likely} likely)",
            summary={"subject_watch": {"case_id": self.case["id"], "subject_id": self.subject_id,
                                       "new_count": len(worth), "likely": likely}},
            workspace_id=self.workspace_id, public_url=self.app.state.settings.public_url,
        )  # fmt: skip
        await self.app.state.audit.record(self.principal, "subject_watch.alert", alert["id"], "success", None,
                                          {"subject": self.subject_id, "case": self.case["id"],
                                           "new": len(worth)}, self.workspace_id)  # fmt: skip

    async def run(self) -> None:
        try:
            await self._run()
        except asyncio.CancelledError:
            await self._finish("interrupted")
            raise
        except Exception as exc:
            logger.exception("Subject run %s failed", self.run_id)
            await self._finish("failed", str(exc))

    async def _run(self) -> None:
        available = _available()
        while True:

            def next_step(row: SubjectRow, data: dict[str, Any]) -> tuple[int, dict[str, Any]] | bool | None:
                run = self._mine(row, data)
                if run is None:
                    return False  # stopped
                for index, step in enumerate(run["steps"]):
                    if step["status"] == "pending":
                        step["status"], step["started_at"] = "running", _now()
                        data["run"] = run
                        return index, dict(step)
                return None

            picked = await self._change(next_step)
            if picked is False:
                return
            if picked is None:  # every step done: follow the best new matches, or finish
                if not await self._follow():
                    failed = await self._change(lambda row, data: all(
                        s["status"] == "failed" for s in (data.get("run") or {}).get("steps", [])))  # fmt: skip
                    await self._finish("failed" if failed else "completed")
                    return
                continue
            index, step = picked
            try:
                status, detail, found = await self._search(step, available)
            except QuotaExceeded as exc:
                status, detail, found = "failed", str(exc), []
            except Exception as exc:  # one search failing never stops the others
                logger.exception("Subject run %s search failed", self.run_id)
                status, detail, found = "failed", f"{type(exc).__name__}: {exc}"[:300], []

            def record(row: SubjectRow, data: dict[str, Any], index: int = index, step: dict[str, Any] = step,
                       status: str = status, detail: str = detail, found: list = found) -> None:  # fmt: skip
                run = data.get("run") or {}
                if run.get("id") != self.run_id:
                    return
                skip = S.known_keys(data.get("known") or {}) | set(data.get("rejected") or [])
                new = S.merge(data["candidates"], found, skip=skip, known=data.get("known") or {})
                self.new_ids += [c["id"] for c in new]
                searched = list(dict.fromkeys([*(data.get("searched") or []), step["key"]]))
                data["searched"] = searched[-500:]
                run["steps"][index].update(status=status, detail=detail + (f"; {len(new)} new" if found else ""),
                                           finished_at=_now(), investigation_id=step.get("investigation_id"))  # fmt: skip
                run["new"] = run.get("new", 0) + len(new)
                data["run"] = run

            await self._change(record)

    async def _follow(self) -> bool:
        """Queue searches for details that became known meanwhile, and from new candidates that match very well
        if rounds are left. True if any."""

        def apply(row: SubjectRow, data: dict[str, Any]) -> bool:
            run = self._mine(row, data)
            if run is None:
                return False
            last = max((s["round"] for s in run["steps"]), default=1)
            searched = set(data.get("searched") or []) | {s["key"] for s in run["steps"]}
            added = 0
            # Details that became known while this ran (a confirmation, an accepted suggestion): search them too.
            for search in S.searches(data.get("known") or {}, searched):
                if len(run["steps"]) >= MAX_SEARCHES:
                    break
                searched.add(search["key"])
                run["steps"].append({**search, "round": last, "status": "pending", "detail": ""})
                added += 1
            if last >= self.rounds or len(run["steps"]) >= MAX_SEARCHES:
                data["run"] = run
                return bool(added)
            for cand in data["candidates"].values():
                if cand.get("status") != "open" or (cand.get("score") or 0) < S.AUTO_FOLLOW:
                    continue
                if cand["id"] not in self.new_ids:
                    continue
                follow = S.follow_up(cand)
                if follow is None or follow["key"] in searched or len(run["steps"]) >= MAX_SEARCHES:
                    continue
                searched.add(follow["key"])
                run["steps"].append({**follow, "round": last + 1, "status": "pending", "detail": ""})
                added += 1
            data["run"] = run
            return bool(added)

        return bool(await self._change(apply))

    async def _search(self, step: dict[str, Any], available: set[str]) -> tuple[str, str, list[dict[str, Any]]]:
        spec = S.SEARCHES[step["kind"]]
        modules = [m for m in spec["modules"] if m in available]
        if not modules:
            return "skipped", "None of the sources for this can run here", []
        settings = self.app.state.settings
        config = ScanConfig(
            target=step["value"], target_type=spec["type"], max_depth=spec["depth"], enabled_modules=modules,
            passive_only=self.case["opsec_mode"] == "anonymous", handle_variants=bool(spec.get("variants")),
            allow_private_targets=settings.allow_private_targets,
            hints={**S.hints((await self.app.state.subjects.data(self.subject_id) or {}).get("known") or {}),
                   **(spec.get("hints") or {})},
        )  # fmt: skip
        purpose = f"{self.case['purpose']} (known details)"[:500]
        scan: ScanFn = self.app.state.playbook_scan
        investigation_id, graph = await scan(self.app, config, by=self.principal.name, purpose=purpose,
                                             workspace_id=self.workspace_id, egress=self.route)  # fmt: skip
        step["investigation_id"] = investigation_id
        try:
            await self.app.state.audit.record(
                self.principal, "scan.start", investigation_id, "success", None,
                {"target": step["value"], "target_type": spec["type"].value, "case": self.case["id"], "modules": modules,
                 "route": self.route.name if self.route else "direct", "passive_only": config.passive_only,
                 "purpose": purpose, "subject": self.subject_id}, self.workspace_id)  # fmt: skip
        except Exception:
            logger.exception("Failed to write audit event scan.start")
        await self.app.state.cases.add_item(
            self.case["id"], by=self.principal.name, kind="scan", title=step["value"], body="",
            data={"investigation_id": investigation_id, "target": step["value"], "subject": self.subject_id},
            occurred_at=None,
        )  # fmt: skip
        found = S.from_graph(graph, step, investigation_id)
        return "done", f"Found {graph.node_count} items", found


# ---------------------------------------------------------------------------- the weekly watch
@router.put("/cases/{case_id}/subjects/{subject_id}/watch")
async def set_watch(case_id: str, subject_id: str, body: WatchRequest, request: Request,
                    ws: WorkspaceContext = ANALYST):  # fmt: skip
    """Search again every week from everything known, and raise an alert when new candidates turn up."""
    case, subject = await _subject(request, ws, case_id, subject_id)
    if body.on:
        _open(case)
        route_for(request.app.state.settings, case, None)  # an anonymous case needs its route
        if not subject["watch"]:
            await request.app.state.quotas.check(ws.id, "watches")
    updated = await request.app.state.subjects.set_watch(subject_id, body.on, WATCH_DAYS, by=ws.principal.name)
    await audit(request, ws.principal, "subject.watch", subject_id, details={"case": case_id, "on": body.on})
    return updated


WATCH_POLL_SECONDS = 3600


async def watch_tick(app: Any) -> list[str]:
    """Start the searches of the watches that are due. Each is claimed first, so one replica runs it."""
    started = []
    for row in await app.state.subjects.due():
        if not await app.state.subjects.claim_watch(row.id, WATCH_DAYS):
            continue
        case = await app.state.cases.info(row.case_id)
        principal = Principal(key_id="subject-watch", name=f"{(row.data or {}).get('watch_by') or 'scheduler'} "
                                                           "(weekly watch)", role=Role.ANALYST)  # fmt: skip
        outcome, detail = "started", ""
        if case is None or case["status"] != "open":
            outcome, detail = "stopped", "The case is closed: the watch was turned off"
            await app.state.subjects.set_watch(row.id, False, WATCH_DAYS)
        else:
            try:
                subject = await app.state.subjects.get(row.id)
                await start(app, case, subject, principal, row.workspace_id, rounds=1, fresh=True, reason="watch")
                started.append(row.id)
            except HTTPException as exc:
                outcome, detail = "refused", str(exc.detail)
            except QuotaExceeded as exc:
                outcome, detail = "refused", str(exc)
        await app.state.subjects.note_watch(row.id, {"at": _now(), "outcome": outcome, "detail": detail})
    return started


async def watch_forever(app: Any, poll_seconds: float = WATCH_POLL_SECONDS) -> None:
    from argus.security import vault

    while True:
        try:
            if vault.ready():
                await watch_tick(app)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Known-details watch tick failed")
        await asyncio.sleep(poll_seconds)


# ---------------------------------------------------------------------------- review
@router.post("/cases/{case_id}/subjects/{subject_id}/candidates/{candidate_id}/confirm")
async def confirm_candidate(case_id: str, subject_id: str, candidate_id: str, body: Decision, request: Request,
                            ws: WorkspaceContext = ANALYST):  # fmt: skip
    """It is theirs: it becomes a known detail, the rest are scored again, and it goes into the case."""
    case, _ = await _subject(request, ws, case_id, subject_id)
    _open(case)

    def apply(row: SubjectRow, data: dict[str, Any]) -> dict[str, Any] | None:
        cand = data["candidates"].get(candidate_id)
        if cand is None:
            return None
        cand.update(status="confirmed", decided_by=ws.principal.name, decided_at=_now(), note=body.note)
        data["known"] = S.add_to_known(data.get("known") or {}, cand)
        _settle(data)
        dismissed = set(data.get("dismissed_suggestions") or [])
        pending = {x["id"] for x in data.get("suggestions") or []}
        new = [x for x in S.suggestions(cand, data["known"]) if x["id"] not in dismissed and x["id"] not in pending]
        data["suggestions"] = [*(data.get("suggestions") or []), *new][-50:]
        return dict(cand)

    subject, cand = await request.app.state.subjects.change(subject_id, apply)
    if cand is None:
        raise HTTPException(status_code=404, detail="Candidate not found")
    reasons = "; ".join(cand.get("agree") or []) or "confirmed by the investigator"
    await request.app.state.cases.add_item(
        case_id, by=ws.principal.name, kind="entity", title=cand["label"][:300],
        body=f"Confirmed as belonging to {subject['name']} ({reasons}){': ' + body.note if body.note else ''}"[:5000],
        data={"type": S.CASE_ITEM_TYPES.get(cand["kind"], "other"), "value": cand["value"],
              "attributes": {"subject": subject_id, "score": cand.get("score"), "platform": cand.get("platform") or ""}},
        occurred_at=None,
    )  # fmt: skip
    await audit(request, ws.principal, "subject.confirm", subject_id,
                details={"case": case_id, "candidate": candidate_id, "kind": cand["kind"], "score": cand.get("score")})  # fmt: skip
    if body.search:
        subject = await _search_new(request, case, subject, ws, reason="confirmed")
    return subject


async def _search_new(request: Request, case: dict[str, Any], subject: dict[str, Any], ws: WorkspaceContext,
                      reason: str) -> dict[str, Any]:  # fmt: skip
    """Search whatever is known but not searched yet. A search already running picks it up itself."""
    data = await request.app.state.subjects.data(subject["id"]) or {}
    if not S.searches(data.get("known") or {}, set(data.get("searched") or [])):
        return subject
    if subject["status"] == "running":
        return {**subject, "search_note": "The search already running will search it too"}
    try:
        return await start(request.app, case, subject, ws.principal, ws.id, rounds=1, fresh=False, reason=reason,
                           request=request)  # fmt: skip
    except HTTPException as exc:
        return {**subject, "search_refused": exc.detail}


class SuggestionDecision(BaseModel):
    ids: list[str] = Field(min_length=1, max_length=50)
    search: bool = Field(default=True, description="Accepting: search from them straight away")


@router.post("/cases/{case_id}/subjects/{subject_id}/suggestions/accept")
async def accept_suggestions(case_id: str, subject_id: str, body: SuggestionDecision, request: Request,
                             ws: WorkspaceContext = ANALYST):  # fmt: skip
    """Add the ticked suggestions (found on confirmed accounts) to what is known, and search from them."""
    case, _ = await _subject(request, ws, case_id, subject_id)
    _open(case)
    wanted = set(body.ids)

    def apply(row: SubjectRow, data: dict[str, Any]) -> list[dict[str, Any]]:
        picked = [x for x in data.get("suggestions") or [] if x["id"] in wanted]
        if not picked:
            return []
        data["known"] = S.accept_suggestions(data.get("known") or {}, picked)
        data["suggestions"] = [x for x in data.get("suggestions") or [] if x["id"] not in wanted]
        _settle(data)
        return picked

    try:
        subject, picked = await request.app.state.subjects.change(subject_id, apply)
    except S.KnownDetailsError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if not picked:
        raise HTTPException(status_code=404, detail="No such suggestions")
    await audit(request, ws.principal, "subject.learn", subject_id,
                details={"case": case_id, "fields": sorted({x["field"] for x in picked}), "count": len(picked)})  # fmt: skip
    if body.search:
        subject = await _search_new(request, case, subject, ws, reason="learned")
    return subject


@router.post("/cases/{case_id}/subjects/{subject_id}/suggestions/dismiss")
async def dismiss_suggestions(case_id: str, subject_id: str, body: SuggestionDecision, request: Request,
                              ws: WorkspaceContext = ANALYST):  # fmt: skip
    """Not useful: they are not suggested again."""
    case, _ = await _subject(request, ws, case_id, subject_id)
    _open(case)
    wanted = set(body.ids)

    def apply(row: SubjectRow, data: dict[str, Any]) -> int:
        before = len(data.get("suggestions") or [])
        data["suggestions"] = [x for x in data.get("suggestions") or [] if x["id"] not in wanted]
        data["dismissed_suggestions"] = list(dict.fromkeys([*(data.get("dismissed_suggestions") or []), *wanted]))[
            -500:
        ]
        return before - len(data["suggestions"])

    subject, removed = await request.app.state.subjects.change(subject_id, apply)
    if not removed:
        raise HTTPException(status_code=404, detail="No such suggestions")
    return subject


@router.post("/cases/{case_id}/subjects/{subject_id}/candidates/{candidate_id}/reject")
async def reject_candidate(case_id: str, subject_id: str, candidate_id: str, body: Decision, request: Request,
                           ws: WorkspaceContext = ANALYST):  # fmt: skip
    """Not theirs: it is never suggested for this person again."""
    case, _ = await _subject(request, ws, case_id, subject_id)
    _open(case)

    def apply(row: SubjectRow, data: dict[str, Any]) -> dict[str, Any] | None:
        cand = data["candidates"].get(candidate_id)
        if cand is None:
            return None
        cand.update(status="rejected", decided_by=ws.principal.name, decided_at=_now(), note=body.note)
        data["rejected"] = list(dict.fromkeys([*(data.get("rejected") or []), cand["key"]]))[-2000:]
        return dict(cand)

    subject, cand = await request.app.state.subjects.change(subject_id, apply)
    if cand is None:
        raise HTTPException(status_code=404, detail="Candidate not found")
    await audit(request, ws.principal, "subject.reject", subject_id,
                details={"case": case_id, "candidate": candidate_id, "kind": cand["kind"]})  # fmt: skip
    return subject


@router.post("/cases/{case_id}/subjects/{subject_id}/candidates/{candidate_id}/reopen")
async def reopen_candidate(case_id: str, subject_id: str, candidate_id: str, request: Request,
                           ws: WorkspaceContext = ANALYST):  # fmt: skip
    """Undo a rejection (a confirmed detail is removed from the known details by editing them)."""
    case, _ = await _subject(request, ws, case_id, subject_id)
    _open(case)

    def apply(row: SubjectRow, data: dict[str, Any]) -> bool | None:
        cand = data["candidates"].get(candidate_id)
        if cand is None:
            return None
        if cand.get("status") != "rejected":
            return False
        cand["status"] = "open"
        data["rejected"] = [k for k in data.get("rejected") or [] if k != cand["key"]]
        S.rescore(data["candidates"], data.get("known") or {})
        return True

    subject, done = await request.app.state.subjects.change(subject_id, apply)
    if done is None:
        raise HTTPException(status_code=404, detail="Candidate not found")
    if not done:
        raise HTTPException(status_code=409, detail="Only a rejected candidate can be reopened")
    await audit(
        request, ws.principal, "subject.reopen", subject_id, details={"case": case_id, "candidate": candidate_id}
    )
    return subject


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
