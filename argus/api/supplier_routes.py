"""Supplier (third-party) risk: the register, passive continuous assessment, risk matrix and export.

Every supplier is watched by a **passive-only** monitor: Argus consults public sources about the
supplier and never contacts its systems, because a supplier has not agreed to be tested. The
legitimate basis for assessing it (e.g. "contracted payroll provider, processes staff data") is
recorded with it and in the audit log.
"""

from __future__ import annotations

import csv
import io
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from argus.api.deps import WorkspaceContext, audit, in_workspace
from argus.api.rating_routes import ensure_history, rate
from argus.intel.suppliers import TIERS, normalise_domain, parse_register, risk, status
from argus.intel.suppliers import min_grade as policy_min_grade
from argus.security.auth import Role
from argus.security.network import validate_scan_target

router = APIRouter(prefix="/api/suppliers", tags=["supplier risk"])
VIEWER = Depends(in_workspace(Role.VIEWER))
ANALYST = Depends(in_workspace(Role.ANALYST))
ADMIN = Depends(in_workspace(Role.ADMIN))

Tier = Literal["critical", "high", "medium", "low"]
DataAccess = Literal["none", "internal", "personal", "sensitive"]
Grade = Literal["A", "B", "C", "D", "F"]
DEPTH = 2


class SupplierRequest(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    domain: str = Field(min_length=3, max_length=253)
    tier: Tier = "medium"
    data_access: DataAccess = "none"
    owner: str = Field(default="", max_length=200)
    notes: str = Field(default="", max_length=500)
    basis: str = Field(min_length=5, max_length=300, description="Why assessing this third party is legitimate")
    authorized: bool = Field(description="Confirms there is a legitimate business reason to assess this supplier")


class ImportRequest(BaseModel):
    csv: str = Field(min_length=1, max_length=500_000)
    basis: str = Field(min_length=5, max_length=300)
    authorized: bool


class SupplierUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    tier: Tier | None = None
    data_access: DataAccess | None = None
    owner: str | None = Field(default=None, max_length=200)
    notes: str | None = Field(default=None, max_length=500)
    min_grade_override: Grade | None = None


def _repo(request: Request) -> Any:
    return request.app.state.suppliers


async def _add(request: Request, ws: WorkspaceContext, fields: dict[str, Any], basis: str) -> dict[str, Any]:
    """Register one supplier and start its passive monitor (the first assessment starts on the next tick)."""
    if not request.app.state.settings.allow_private_targets:
        from argus.core.models import EntityType

        try:
            validate_scan_target(fields["domain"], EntityType.DOMAIN)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
    monitor = await request.app.state.monitors.create(
        target=fields["domain"],
        target_type="domain",
        max_depth=DEPTH,
        interval_hours=TIERS[fields["tier"]]["interval_hours"],
        purpose=f"Supplier risk assessment (passive) of {fields['name']}: {basis}"[:500],
        created_by=ws.principal.name,
        workspace_id=ws.id,
        passive_only=True,  # never contact a third party's systems
    )
    supplier = await _repo(request).create(workspace_id=ws.id, by=ws.principal.name, monitor_id=monitor["id"],
                                           basis=basis, **fields)  # fmt: skip
    # Suppliers are also swept for public breach and ransomware leak-site reports.
    await request.app.state.exposure.ensure_supplier_watch(workspace_id=ws.id, by=ws.principal.name)
    return supplier


async def _view(request: Request, ws_id: str, supplier: dict[str, Any]) -> dict[str, Any]:
    """The supplier with its current rating (synced from its latest completed assessment), policy and risk."""
    inv = await request.app.state.repo.latest_completed(supplier["domain"], workspace_id=ws_id)
    grade, score, history = supplier["last_grade"], supplier["last_score"], []
    if inv is not None:
        rating = await rate(request.app, inv)
        if rating.get("grade"):
            grade, score = rating["grade"], rating["score"]
            if supplier["last_investigation_id"] != inv.id:
                await _repo(request).record_assessment(
                    supplier["id"], grade=grade, score=score, investigation_id=inv.id,
                    assessed_at=inv.completed_at or inv.created_at,
                )  # fmt: skip
                supplier = {**supplier, "last_investigation_id": inv.id,
                            "last_assessed_at": (inv.completed_at or inv.created_at).isoformat()}  # fmt: skip
        await ensure_history(request.app, ws_id, supplier["domain"])
        history = await request.app.state.ratings.history(supplier["domain"], workspace_id=ws_id, limit=6)
    floor = policy_min_grade(supplier["tier"], supplier["min_grade_override"])
    return {
        **supplier,
        "grade": grade,
        "score": score,
        "min_grade": floor,
        "status": status(supplier["tier"], grade, supplier["min_grade_override"]),
        "risk": risk(supplier["tier"], supplier["data_access"], grade),
        "trend": [h["score"] for h in history],
        "reassessed_every_days": TIERS[supplier["tier"]]["interval_hours"] // 24,
    }


@router.get("")
async def list_suppliers(request: Request, ws: WorkspaceContext = VIEWER):
    suppliers = [await _view(request, ws.id, s) for s in await _repo(request).list_suppliers(workspace_id=ws.id)]
    exposure = await request.app.state.exposure.open_by_subject(workspace_id=ws.id)
    for s in suppliers:
        s["exposure"] = exposure.get(s["domain"], {})
    order = {"below_minimum": 0, "not_assessed": 2, "within_tolerance": 1}
    suppliers.sort(key=lambda s: (order[s["status"]], -(s["risk"]["score"] or 0), s["name"].lower()))
    matrix = {str(i): dict.fromkeys("ABCDF", 0) for i in range(1, 6)}  # impact -> grade -> count
    for s in suppliers:
        if s["grade"]:
            matrix[str(s["risk"]["impact"])][s["grade"]] += 1
    return {
        "suppliers": suppliers,
        "summary": {
            "total": len(suppliers),
            "below_minimum": sum(1 for s in suppliers if s["status"] == "below_minimum"),
            "not_assessed": sum(1 for s in suppliers if s["status"] == "not_assessed"),
            "by_risk": {
                lvl: sum(1 for s in suppliers if s["risk"]["level"] == lvl)
                for lvl in ("critical", "high", "medium", "low", "unknown")
            },
        },
        "matrix": matrix,
        "policy": {
            tier: {"min_grade": t["min_grade"], "reassessed_every_days": t["interval_hours"] // 24}
            for tier, t in TIERS.items()
        },
    }


@router.post("", status_code=201)
async def create_supplier(body: SupplierRequest, request: Request, ws: WorkspaceContext = ANALYST):
    if not body.authorized:
        raise HTTPException(
            status_code=422, detail="Confirm there is a legitimate business reason to assess this supplier"
        )
    domain = normalise_domain(body.domain)
    if not domain:
        raise HTTPException(status_code=422, detail="Enter the supplier's domain, e.g. supplier.com")
    if domain in await _repo(request).domains(workspace_id=ws.id):
        raise HTTPException(status_code=409, detail=f"{domain} is already in the supplier register")
    fields = body.model_dump(exclude={"basis", "authorized", "domain"}) | {"domain": domain}
    supplier = await _add(request, ws, fields, body.basis.strip())
    await audit(request, ws.principal, "supplier.create", supplier["id"],
                details={"name": body.name, "domain": domain, "tier": body.tier, "basis": body.basis})  # fmt: skip
    if request.app.state.settings.monitors_enabled:
        await request.app.state.scheduler.tick()
    return await _view(request, ws.id, supplier)


@router.post("/import")
async def import_suppliers(body: ImportRequest, request: Request, ws: WorkspaceContext = ANALYST):
    """Bulk-add suppliers from a spreadsheet export (CSV). Existing domains are skipped."""
    if not body.authorized:
        raise HTTPException(
            status_code=422, detail="Confirm there is a legitimate business reason to assess these suppliers"
        )
    parsed = parse_register(body.csv)
    existing = await _repo(request).domains(workspace_id=ws.id)
    created, skipped, errors = [], [], list(parsed.errors)
    for row in parsed.rows:
        if row["domain"] in existing:
            skipped.append(row["domain"])
            continue
        try:
            supplier = await _add(request, ws, row, body.basis.strip())
        except HTTPException as exc:
            errors.append({"line": None, "error": f"{row['domain']}: {exc.detail}"})
            continue
        created.append(supplier["domain"])
    await audit(request, ws.principal, "supplier.import", None,
                details={"created": len(created), "skipped": len(skipped), "errors": len(errors), "basis": body.basis})  # fmt: skip
    if created and request.app.state.settings.monitors_enabled:
        await request.app.state.scheduler.tick()
    return {"created": created, "skipped": skipped, "errors": errors}


@router.patch("/{supplier_id}")
async def update_supplier(supplier_id: str, body: SupplierUpdate, request: Request, ws: WorkspaceContext = ANALYST):
    changes = body.model_dump(exclude_unset=True)
    supplier = await _repo(request).update(supplier_id, workspace_id=ws.id, **changes)
    if supplier is None:
        raise HTTPException(status_code=404, detail="Supplier not found")
    if "tier" in changes and supplier["monitor_id"]:
        await request.app.state.monitors.reschedule(
            supplier["monitor_id"], workspace_id=ws.id, interval_hours=TIERS[supplier["tier"]]["interval_hours"]
        )
    await audit(request, ws.principal, "supplier.update", supplier_id, details={k: str(v) for k, v in changes.items()})
    return await _view(request, ws.id, supplier)


@router.post("/{supplier_id}/assess", status_code=202)
async def assess_now(supplier_id: str, request: Request, ws: WorkspaceContext = ANALYST):
    supplier = await _repo(request).get(supplier_id, workspace_id=ws.id)
    if supplier is None or not supplier["monitor_id"]:
        raise HTTPException(status_code=404, detail="Supplier not found")
    await request.app.state.monitors.reschedule(supplier["monitor_id"], workspace_id=ws.id, run_now=True)
    await audit(request, ws.principal, "supplier.assess", supplier_id)
    if request.app.state.settings.monitors_enabled:
        await request.app.state.scheduler.tick()
    return {"status": "queued", "supplier_id": supplier_id}


@router.delete("/{supplier_id}", status_code=204)
async def delete_supplier(supplier_id: str, request: Request, ws: WorkspaceContext = ADMIN):
    supplier = await _repo(request).delete(supplier_id, workspace_id=ws.id)
    if supplier is None:
        raise HTTPException(status_code=404, detail="Supplier not found")
    if supplier["monitor_id"]:
        await request.app.state.monitors.delete(supplier["monitor_id"], workspace_id=ws.id)
    await audit(request, ws.principal, "supplier.delete", supplier_id, details={"domain": supplier["domain"]})
    return Response(status_code=204)


@router.get("/export.csv")
async def export_register(request: Request, ws: WorkspaceContext = VIEWER):
    """The supplier register with current ratings, for compliance records (e.g. a DORA register of information)."""
    data = await list_suppliers(request, ws)
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["Supplier", "Domain", "Tier", "Data handled", "Owner", "Grade", "Score", "Minimum grade", "Status",
                     "Risk level", "Risk score", "Last assessed", "Basis for assessment", "Notes"])  # fmt: skip
    for s in data["suppliers"]:
        writer.writerow([s["name"], s["domain"], s["tier"], s["data_access"], s["owner"], s["grade"] or "",
                         "" if s["score"] is None else round(s["score"]), s["min_grade"] or "", s["status"],
                         s["risk"]["level"], s["risk"]["score"] or "", s["last_assessed_at"] or "", s["basis"],
                         s["notes"]])  # fmt: skip
    await audit(request, ws.principal, "supplier.export", None, details={"suppliers": len(data["suppliers"])})
    return Response(out.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": 'attachment; filename="supplier-register.csv"'})  # fmt: skip
