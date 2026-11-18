"""Playbooks in a case: start one, watch its steps, see what stood out, stop it.

A run belongs to a case and inherits its safety settings: the case's route, and for an
anonymous case, passive modules only. Starting one is confirmed the same way as a scan, and is
recorded in the audit log, as is every scan it starts. The AI briefing step runs only when the
investigator asked for it *and* confirmed sending the case to Anthropic.

The run itself happens in the background. Each step's progress is saved as it goes, so the page
can follow it, and a run left unfinished by a server restart is marked *interrupted*.
"""

from __future__ import annotations

import asyncio
import logging
import re
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from argus.accounts.connect_client import ai_access
from argus.api.analyst_routes import analyse
from argus.api.case_routes import _case
from argus.api.deps import WorkspaceContext, audit, in_workspace
from argus.api.opsec_routes import route_for
from argus.api.people_routes import auto_import
from argus.core.graph import IntelligenceGraph
from argus.core.models import EntityType, ScanConfig
from argus.evidence.capture import CaptureError, capture_url
from argus.intel.analyst import AnalystError
from argus.intel.playbooks import CASE_TYPES, CATALOGUE, Playbook, capture_urls, findings_note, highlights
from argus.modules import get_module_catalog
from argus.security.auth import Principal, Role
from argus.security.network import validate_scan_target

logger = logging.getLogger("argus.playbooks")
router = APIRouter(prefix="/api", tags=["playbooks"])
VIEWER = Depends(in_workspace(Role.VIEWER))
ANALYST = Depends(in_workspace(Role.ANALYST))
RUNS: dict[str, asyncio.Task[None]] = {}  # runs in progress on this server

# (app, config, by, purpose, workspace id, route) -> (investigation id, graph); set by the server
ScanFn = Callable[..., Awaitable[tuple[str, IntelligenceGraph]]]


class PlaybookRequest(BaseModel):
    playbook: str = Field(max_length=64)
    seed: str = Field(min_length=1, max_length=253, description="The starting point: a name, username, address...")
    confirmed: bool = Field(description="Confirms there is a legitimate purpose for running it on this subject")
    ai_brief: bool = Field(default=False, description="End with an AI analyst briefing")
    ai_acknowledged: bool = Field(
        default=False, description="Confirms the case's material may be sent to Anthropic for the briefing"
    )


def _available() -> set[str]:
    return {name for name, module in get_module_catalog().items() if module.is_configured()}


def _seed_type(seed: str, playbook: Playbook) -> EntityType:
    from argus.cli.console import detect_target_type

    detected = detect_target_type(seed)
    if detected in playbook.seed_types:
        return detected
    if len(playbook.seed_types) == 1 and playbook.seed_types[0] in (EntityType.PERSON, EntityType.ORGANIZATION) \
            and detected in (EntityType.PERSON, EntityType.ORGANIZATION, EntityType.USERNAME, EntityType.GENERIC):  # fmt: skip
        return playbook.seed_types[0]  # a name: the playbook says whether it is a person or a company
    if EntityType.CRYPTO_WALLET in playbook.seed_types and re.fullmatch(r"(bc1|tb1|0x|[13LM])[A-Za-z0-9]{20,90}", seed):
        raise HTTPException(status_code=422, detail="That looks like a wallet address, but its checksum does not "
                                                    "match, so it was probably mistyped")  # fmt: skip
    wanted = " or ".join(t.value.replace("_", " ") for t in playbook.seed_types)
    raise HTTPException(status_code=422, detail=f"This playbook starts from a {wanted}; that looks like a "
                                                f"{detected.value.replace('_', ' ')}")  # fmt: skip


@router.get("/playbooks")
async def list_playbooks(ws: WorkspaceContext = VIEWER):
    """The playbooks, their steps, and which of their modules can't run here (they need a key)."""
    available = _available()
    return [p.as_dict(available) for p in CATALOGUE.values()]


@router.get("/cases/{case_id}/playbooks")
async def case_runs(case_id: str, request: Request, ws: WorkspaceContext = VIEWER):
    await _case(request, ws, case_id)
    return await request.app.state.playbooks.for_case(case_id)


@router.get("/cases/{case_id}/playbooks/{run_id}")
async def get_run(case_id: str, run_id: str, request: Request, ws: WorkspaceContext = VIEWER):
    await _case(request, ws, case_id)
    run = await request.app.state.playbooks.get(run_id, case_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Playbook run not found")
    return run


@router.post("/cases/{case_id}/playbooks/{run_id}/cancel")
async def cancel_run(case_id: str, run_id: str, request: Request, ws: WorkspaceContext = ANALYST):
    """Stop a run: a scan already running finishes, and nothing after it starts."""
    await _case(request, ws, case_id)
    if await request.app.state.playbooks.get(run_id, case_id) is None:
        raise HTTPException(status_code=404, detail="Playbook run not found")
    if not await request.app.state.playbooks.cancel(run_id):
        raise HTTPException(status_code=409, detail="This run has already finished")
    await audit(request, ws.principal, "playbook.cancel", run_id, details={"case": case_id})
    return await request.app.state.playbooks.get(run_id, case_id)


@router.post("/cases/{case_id}/playbooks", status_code=202)
async def start_run(case_id: str, body: PlaybookRequest, request: Request, ws: WorkspaceContext = ANALYST):
    """Start a playbook in this case. It runs in the background; follow it with GET .../playbooks/{id}."""
    case = await _case(request, ws, case_id)
    playbook = CATALOGUE.get(body.playbook)
    if playbook is None:
        raise HTTPException(status_code=404, detail=f"Unknown playbook {body.playbook!r}")
    if not body.confirmed:
        raise HTTPException(status_code=422, detail="Confirm there is a legitimate purpose for running this playbook")
    if case["status"] != "open":
        raise HTTPException(status_code=409, detail="Reopen the case to run a playbook in it")
    if body.ai_brief and not body.ai_acknowledged:
        raise HTTPException(status_code=428, detail="Confirm that this case's material may be sent to Anthropic "
                                                    "for the AI briefing, or leave the briefing out")  # fmt: skip
    seed = body.seed.strip()
    seed_type = _seed_type(seed, playbook)
    settings = request.app.state.settings
    if seed_type == EntityType.CRYPTO_WALLET:
        from argus.intel.crypto import classify

        if classify(seed) is None:
            raise HTTPException(status_code=422, detail="That is not a valid wallet address: its checksum does not "
                                                        "match, so it was probably mistyped")  # fmt: skip
    if not settings.allow_private_targets:
        try:
            validate_scan_target(seed, seed_type)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
    route = route_for(settings, case, None)  # 409 if it would expose an anonymous case
    runs = request.app.state.playbooks
    if any(r["status"] == "running" for r in await runs.for_case(case_id)):
        raise HTTPException(
            status_code=409, detail="A playbook is already running in this case; wait for it or stop it"
        )
    if not request.app.state.scan_limiter.hit(ws.principal.key_id):
        raise HTTPException(status_code=429, detail="Scan rate limit exceeded")
    available = _available()
    steps = []
    for step in playbook.steps:
        entry: dict[str, Any] = {"kind": step.kind, "title": step.title, "status": "pending", "detail": ""}
        if step.kind == "scan":
            entry["modules"] = [m for m in step.modules if m in available]
            entry["unavailable"] = [m for m in step.modules if m not in available]
        steps.append(entry)
    options = {"ai_brief": body.ai_brief, "route": route.name if route else "direct",
               "passive_only": case["opsec_mode"] == "anonymous", "name": playbook.name}  # fmt: skip
    run = await runs.create(workspace_id=ws.id, case_id=case_id, playbook=playbook.id, seed=seed,
                            seed_type=seed_type.value, by=ws.principal.name, steps=steps, options=options,
                            owner=settings.instance_id)  # fmt: skip
    await audit(request, ws.principal, "playbook.start", run["id"],
                details={"case": case_id, "playbook": playbook.id, "seed": seed, "seed_type": seed_type.value,
                         "route": options["route"], "ai_brief": body.ai_brief, "purpose": case["purpose"]})  # fmt: skip
    runner = PlaybookRun(request.app, run["id"], case, playbook, seed, seed_type, steps, ws.principal, ws.id, route,
                         body.ai_brief)  # fmt: skip
    task = asyncio.create_task(runner.run(), name=f"playbook-{run['id']}")
    RUNS[run["id"]] = task
    task.add_done_callback(lambda _t: RUNS.pop(run["id"], None))
    return run


class PlaybookRun:
    """Runs one playbook's steps in order, saving progress after each."""

    def __init__(self, app: Any, run_id: str, case: dict[str, Any], playbook: Playbook, seed: str,
                 seed_type: EntityType, steps: list[dict[str, Any]], principal: Principal, workspace_id: str,
                 route: Any, ai_brief: bool):  # fmt: skip
        self.app, self.id, self.case, self.playbook = app, run_id, case, playbook
        self.seed, self.seed_type, self.steps, self.principal = seed, seed_type, steps, principal
        self.workspace_id, self.route, self.ai_brief = workspace_id, route, ai_brief
        self.graph = IntelligenceGraph(run_id)
        self.found: list[dict[str, Any]] = []
        self.brief: dict[str, Any] | None = None

    async def _save(self, status: str | None = None, error: str | None = None) -> None:
        await self.app.state.playbooks.save(self.id, steps=self.steps, highlights=self.found, status=status,
                                            error=error)  # fmt: skip

    async def _audit(self, action: str, resource: str, details: dict[str, Any]) -> None:
        try:
            await self.app.state.audit.record(self.principal, action, resource, "success", None,
                                              {**details, "playbook_run": self.id}, self.workspace_id)  # fmt: skip
        except Exception:
            logger.exception("Failed to write audit event %s", action)

    async def run(self) -> None:
        try:
            for index, (definition, step) in enumerate(zip(self.playbook.steps, self.steps, strict=True)):
                if await self.app.state.playbooks.status(self.id) != "running":
                    for later in self.steps[index:]:
                        later.update(status="skipped", detail="The run was stopped")
                    await self._save()
                    return
                step.update(status="running", started_at=_now())
                await self._save()
                try:
                    outcome, detail = await getattr(self, f"_{definition.kind}")(definition, step)
                except Exception as exc:  # one step failing never stops the others
                    logger.exception("Playbook %s step %s failed", self.id, definition.kind)
                    outcome, detail = "failed", f"{type(exc).__name__}: {exc}"[:300]
                step.update(status=outcome, detail=detail, finished_at=_now())
                await self._save()
            failed = all(s["status"] in ("failed", "skipped") for s in self.steps if s["kind"] == "scan")
            await self._save(status="failed" if failed else "completed")
        except asyncio.CancelledError:
            await self._save(status="interrupted")
            raise
        except Exception as exc:
            logger.exception("Playbook run %s failed", self.id)
            await self._save(status="failed", error=str(exc))

    # ------------------------------------------------------------------ steps
    async def _scan(self, definition: Any, step: dict[str, Any]) -> tuple[str, str]:
        modules = step.get("modules") or []
        if not modules:
            return "skipped", "None of this step's sources can run here: " + ", ".join(step.get("unavailable") or [])
        settings = self.app.state.settings
        config = ScanConfig(
            target=self.seed, target_type=self.seed_type, max_depth=definition.depth, enabled_modules=modules,
            passive_only=self.case["opsec_mode"] == "anonymous",
            handle_variants=definition.variants and self.seed_type == EntityType.USERNAME,
            allow_private_targets=settings.allow_private_targets,
        )  # fmt: skip
        purpose = f"{self.case['purpose']} (playbook: {self.playbook.name})"[:500]
        scan: ScanFn = self.app.state.playbook_scan
        investigation_id, graph = await scan(self.app, config, by=self.principal.name, purpose=purpose,
                                             workspace_id=self.workspace_id, egress=self.route)  # fmt: skip
        step["investigation_id"] = investigation_id
        await self._audit("scan.start", investigation_id,
                          {"target": self.seed, "target_type": self.seed_type.value, "case": self.case["id"],
                           "modules": modules, "route": self.route.name if self.route else "direct",
                           "passive_only": config.passive_only, "purpose": purpose})  # fmt: skip
        await self.app.state.cases.add_item(
            self.case["id"], by=self.principal.name, kind="scan", title=self.seed, body="",
            data={"investigation_id": investigation_id, "target": self.seed}, occurred_at=None,
        )  # fmt: skip
        await auto_import(self.app, self.case["id"], investigation_id, self.principal, self.workspace_id)
        for entity in graph.get_all_entities():
            self.graph.add_entity(entity, is_seed=entity.depth == 0)
        for relation in graph.get_all_relations():
            self.graph.add_relation(relation)
        skipped = f"; not run (need a key): {', '.join(step['unavailable'])}" if step.get("unavailable") else ""
        return "done", f"Found {graph.node_count} items and {graph.edge_count} links{skipped}"

    async def _capture(self, definition: Any, step: dict[str, Any]) -> tuple[str, str]:
        urls = capture_urls(self.graph, definition.capture, self.seed, definition.limit)
        if not urls:
            return "skipped", "Nothing to preserve"
        saved, problems = 0, []
        for url in urls:
            if await self.app.state.playbooks.status(self.id) != "running":
                break
            try:
                capture = await capture_url(url, self.app.state.settings, self.route)
            except CaptureError as exc:
                problems.append(f"{url}: {exc}")
                continue
            stored = await self.app.state.cases.add_capture(self.case["id"], self.workspace_id, capture,
                                                            by=self.principal.name,
                                                            note=f"Preserved by the {self.playbook.name} playbook")  # fmt: skip
            await self._audit("evidence.capture", stored["id"], {"case": self.case["id"], "url": url,
                                                                 "digest": stored["digest"]})  # fmt: skip
            saved += 1
        step["problems"] = problems[:10]
        if not saved:
            return "failed", f"No page could be preserved ({problems[0] if problems else 'stopped'})"
        return "done", f"Preserved {saved} of {len(urls)} page(s)" + (f"; {len(problems)} failed" if problems else "")

    async def _findings(self, definition: Any, step: dict[str, Any]) -> tuple[str, str]:
        found = highlights(self.graph)
        self.found = [h.as_dict() for h in found]
        cases = self.app.state.cases
        items = await cases.items(self.case["id"])
        case_type = CASE_TYPES.get(self.seed_type, "other")
        if not any(i["kind"] == "entity" and str((i["data"] or {}).get("value", "")).lower() == self.seed.lower()
                   for i in items):  # fmt: skip
            await cases.add_item(self.case["id"], by=self.principal.name, kind="entity", title=self.seed,
                                 body=f"Starting point of the {self.playbook.name} playbook",
                                 data={"type": case_type, "value": self.seed, "attributes": {}}, occurred_at=None)  # fmt: skip
        note = findings_note(self.playbook.name, self.seed, found,
                             {"entities": self.graph.node_count, "relations": self.graph.edge_count})  # fmt: skip
        await cases.add_item(self.case["id"], by=self.principal.name, kind="note",
                             title=f"Playbook findings: {self.playbook.name}, {self.seed}"[:300], body=note[:50000],
                             data={"playbook_run": self.id}, occurred_at=None)  # fmt: skip
        counts = {lvl: sum(1 for h in found if h.level == lvl) for lvl in ("high", "medium", "info")}
        return "done", (f"{counts['high']} need attention, {counts['medium']} worth checking, {counts['info']} also "
                        "found; written to the case as a note")  # fmt: skip

    async def _brief(self, definition: Any, step: dict[str, Any]) -> tuple[str, str]:
        if not self.ai_brief:
            return "skipped", "Not requested"
        if ai_access() is None:
            return "skipped", "The AI analyst is not set up (an Argus account or your own Claude key is needed)"
        case = await self.app.state.cases.info(self.case["id"]) or self.case
        try:
            result, details = await analyse(self.app, {**self.case, **case}, "brief", by=self.principal.name)
        except AnalystError as exc:
            await self._audit("case.analyst", self.case["id"], exc.details)
            return "failed", exc.detail
        await self._audit("case.analyst", self.case["id"], details)
        step["brief"] = result
        return "done", "Briefing ready"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
