"""Hunts and query alerts: Argus Query Language beyond one investigation.

* **Hunt** — run one query across a workspace's recent investigations ("which of our scans ever
  found a host serving this favicon?", "every exposed Redis we have seen"). Bounded by a number
  of investigations and a time budget; each graph is queried in a worker thread.
* **Query alerts** — after every completed scan, the workspace's alerting saved queries run on the
  new graph. A query alerts when the scan matches something the previous scan of the same target
  did not (entity ids are deterministic, so they compare across scans). The first scan of a
  target alerts on any match.
"""

from __future__ import annotations

import logging
import time
from typing import Any

import anyio

from argus.core.graph import IntelligenceGraph
from argus.core.models import Investigation, InvestigationStatus
from argus.intel.query import QueryError, run_query

logger = logging.getLogger("argus.hunt")

DEFAULT_HUNT_INVESTIGATIONS = 25
MAX_HUNT_INVESTIGATIONS = 200
HUNT_TIME_BUDGET_SECONDS = 25.0
HUNT_ROWS_PER_INVESTIGATION = 5
ALERT_SAMPLE = 10  # new matches named in an alert


def validate(text: str) -> None:
    """Raise :class:`QueryError` if ``text`` does not parse (checked against an empty graph)."""
    run_query(IntelligenceGraph("validate"), text)


async def hunt(
    repo: Any,
    workspace_id: str,
    text: str,
    *,
    investigations: int = DEFAULT_HUNT_INVESTIGATIONS,
    include_running: bool = False,
    budget_seconds: float = HUNT_TIME_BUDGET_SECONDS,
) -> dict[str, Any]:
    """Run ``text`` over the workspace's most recent investigations (completed ones by default)."""
    validate(text)
    started = time.perf_counter()
    limit = max(1, min(investigations, MAX_HUNT_INVESTIGATIONS))
    rows = await repo.list_investigations(
        workspace_id=workspace_id, limit=limit, status=None if include_running else InvestigationStatus.COMPLETED.value
    )
    results: list[dict[str, Any]] = []
    searched = 0
    total = 0
    partial = False
    for inv in rows:
        if time.perf_counter() - started > budget_seconds:
            partial = True
            break
        graph = await repo.load_graph(inv["id"], shared=True)  # read-only
        if graph is None:
            continue
        searched += 1
        result = await anyio.to_thread.run_sync(run_query, graph, text)
        if not result["count"]:
            continue
        total += result["count"]
        results.append(
            {
                "investigation_id": inv["id"],
                "target": inv["target"],
                "target_type": inv["target_type"],
                "status": inv["status"],
                "created_at": inv["created_at"],
                "count": result["count"],
                "kind": result["kind"],
                "rows": result["rows"][:HUNT_ROWS_PER_INVESTIGATION],
                "groups": result["groups"][:HUNT_ROWS_PER_INVESTIGATION],
            }
        )
    return {
        "query": text,
        "investigations_searched": searched,
        "investigations_matched": len(results),
        "total_matches": total,
        "partial": partial,
        "results": results,
        "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
    }


def _match_ids(graph: IntelligenceGraph, text: str) -> dict[str, str]:
    """Matching entity id -> label: every match, whatever ``limit`` or ``count`` the query ends with."""
    result = run_query(graph, text, collect_ids=True)
    labels = {}
    for nid in result["match_ids"]:
        entity = graph.get_entity(nid)
        labels[nid] = entity.label if entity else nid
    return labels


async def check_after_scan(
    *,
    investigation: Investigation,
    graph: IntelligenceGraph,
    repo: Any,
    saved_queries: Any,
    raise_alert: Any,
) -> list[dict[str, Any]]:
    """Run the workspace's alerting queries on a finished scan; returns the alerts raised.

    ``raise_alert(query, new_matches, total, previous_id)`` creates and delivers one alert.
    """
    if investigation.status != InvestigationStatus.COMPLETED:
        return []
    queries = await saved_queries.list(investigation.workspace_id, alerting_only=True)
    if not queries:
        return []
    previous = await repo.find_previous(investigation)
    previous_graph = await repo.load_graph(previous.id) if previous else None
    raised: list[dict[str, Any]] = []
    for saved in queries:
        try:
            now = await anyio.to_thread.run_sync(_match_ids, graph, saved["query"])
            before = (
                await anyio.to_thread.run_sync(_match_ids, previous_graph, saved["query"]) if previous_graph else {}
            )
        except QueryError as exc:  # saved before a syntax change, say: skip it, don't break the others
            logger.warning("Saved query %s no longer runs: %s", saved["id"], exc)
            await saved_queries.mark_checked(saved["id"], alerted=False)
            continue
        new = {nid: label for nid, label in now.items() if nid not in before}
        if new:
            alert = await raise_alert(saved, new, len(now), previous.id if previous else None)
            if alert is not None:
                raised.append(alert)
        await saved_queries.mark_checked(saved["id"], alerted=bool(new))
    return raised


def alert_summary(saved: dict[str, Any], new: dict[str, str], total: int) -> dict[str, Any]:
    """The ``summary`` stored on a query alert (and sent to webhooks)."""
    return {
        "saved_query": {
            "id": saved["id"],
            "name": saved["name"],
            "query": saved["query"],
            "new_count": len(new),
            "total_count": total,
            "new_matches": sorted(new.values(), key=str.lower)[:ALERT_SAMPLE],
            "new_ids": sorted(new)[:200],
        }
    }


def alert_headline(saved: dict[str, Any], new_count: int, target: str) -> str:
    plural = "es" if new_count != 1 else ""
    return f"Saved query “{saved['name']}”: {new_count} new match{plural} on {target}"
