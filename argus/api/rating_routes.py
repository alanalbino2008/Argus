"""Security ratings: per investigation, over time, and across the workspace's portfolio.

Benchmarks are honest by construction: a rating is compared with the **other organisations
assessed in the same workspace** (a supplier portfolio, a client base), never with invented
"industry averages".
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, Request

from argus.api.deps import WorkspaceContext, in_workspace
from argus.core.models import Investigation, InvestigationStatus
from argus.intel.paths import find_attack_paths
from argus.intel.rating import compute_rating
from argus.security.auth import Role
from argus.storage.rating_repo import RatingRepository

router = APIRouter(prefix="/api/ratings", tags=["ratings"])
VIEWER = Depends(in_workspace(Role.VIEWER))
MIN_BENCHMARK = 3  # a percentile among fewer organisations means nothing
MAX_COMPUTE_PER_REQUEST = 40
TREND_POINTS = 6


async def rate(app: Any, inv: Investigation, graph: Any = None) -> dict[str, Any]:
    """The investigation's rating: from the cache, or computed (and cached once the scan has finished)."""
    ratings: RatingRepository = app.state.ratings
    if (cached := await ratings.get(inv.id, workspace_id=inv.workspace_id)) is not None:
        return cached
    graph = graph if graph is not None else await app.state.repo.load_graph(inv.id)
    if graph is None:
        return {}
    rating = compute_rating(graph, find_attack_paths(graph)["paths"])
    if inv.status == InvestigationStatus.COMPLETED:
        assessed = inv.completed_at or inv.created_at
        assessed = assessed if assessed.tzinfo else assessed.replace(tzinfo=timezone.utc)
        await ratings.save(investigation_id=inv.id, workspace_id=inv.workspace_id, target=inv.config.target,
                           rating=rating, assessed_at=assessed)  # fmt: skip
    return {**rating, "target": inv.config.target.lower(), "investigation_id": inv.id}


def percentile(score: float, others: list[float]) -> int | None:
    """Share of the *other* organisations this one beats (ties count half)."""
    if len(others) + 1 < MIN_BENCHMARK:
        return None
    beaten = sum(1.0 if s < score else 0.5 if s == score else 0.0 for s in others)
    return round(100 * beaten / len(others))


async def benchmark(app: Any, workspace_id: str, target: str, score: float) -> dict[str, Any]:
    ratings: RatingRepository = app.state.ratings
    latest = await ratings.latest_per_target(workspace_id=workspace_id)
    others = [r["score"] for r in latest if r["target"] != target.lower()]
    return {
        "percentile": percentile(score, others),
        "peers": len(others),
        "median": sorted(others)[len(others) // 2] if others else None,
        "basis": "organisations assessed in this workspace",
    }


async def ensure_history(app: Any, workspace_id: str, target: str | None = None) -> None:
    """Rate the recent completed scans of every target, or of one (bounded per request)."""
    repo = app.state.repo
    rows = await repo.list_investigations(workspace_id=workspace_id, status="completed", limit=200, target=target)
    if target:
        rows = [r for r in rows if r["target"].lower() == target.lower()]
    per_target: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        per_target.setdefault(row["target"].lower(), []).append(row)
    budget = MAX_COMPUTE_PER_REQUEST
    ratings: RatingRepository = app.state.ratings
    for items in per_target.values():
        for row in items[:TREND_POINTS]:
            if budget <= 0:
                return
            if await ratings.get(row["id"], workspace_id=workspace_id) is not None:
                continue
            inv = await repo.get_investigation(row["id"])
            if inv is not None:
                await rate(app, inv)
                budget -= 1


@router.get("")
async def portfolio(request: Request, ws: WorkspaceContext = VIEWER):
    """Every assessed organisation in this workspace: latest grade, trend and benchmark."""
    app = request.app
    await ensure_history(app, ws.id)
    ratings: RatingRepository = app.state.ratings
    latest = await ratings.latest_per_target(workspace_id=ws.id)
    scores = {r["target"]: r["score"] for r in latest}
    rows = []
    for r in sorted(latest, key=lambda r: r["score"]):
        history = await ratings.history(r["target"], workspace_id=ws.id, limit=TREND_POINTS)
        assessed = [f for f in r["factors"] if f["assessed"]]
        weakest = min(assessed, key=lambda f: f["score"]) if assessed else None
        rows.append({
            "target": r["target"],
            "investigation_id": r["investigation_id"],
            "score": r["score"],
            "grade": r["grade"],
            "confidence": r["confidence"],
            "provisional": r["provisional"],
            "assessed_at": r["assessed_at"],
            "critical_issues": r["critical_issues"],
            "weakest": {"name": weakest["name"], "score": weakest["score"]} if weakest else None,
            "trend": [h["score"] for h in history],
            "change": round(history[-1]["score"] - history[-2]["score"], 1) if len(history) > 1 else None,
            "percentile": percentile(r["score"], [s for t, s in scores.items() if t != r["target"]]),
        })  # fmt: skip
    distribution = {g: sum(1 for r in rows if r["grade"] == g) for g in ("A", "B", "C", "D", "F")}
    return {
        "organisations": rows,
        "distribution": distribution,
        "median": sorted(scores.values())[len(scores) // 2] if scores else None,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
