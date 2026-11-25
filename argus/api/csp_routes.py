"""Content-Security-Policy violation reports from browsers (Phase 99).

Argus's pages may only load what Argus serves. When a browser refuses something (an injected script,
a browser extension's stylesheet, a connection to another host), it reports it here. Reports are
counted by directive (``argus_csp_violations_total``) and logged with the blocked host only, so a
burst of violations, the sign of an injection attempt, shows up on the dashboard and in alerts.

The endpoint is public (browsers send reports without credentials), takes at most 16 KB, is limited
per address, never stores report bodies, and answers 204 whatever it receives.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any
from urllib.parse import urlsplit

from fastapi import APIRouter, Request, Response

from argus.api.deps import client_ip
from argus.observability import metrics
from argus.security.headers import CSP_REPORT_PATH
from argus.security.ratelimit import SlidingWindowLimiter

router = APIRouter(tags=["security"])
logger = logging.getLogger("argus.csp")
MAX_BYTES = 16 * 1024
_limiter = SlidingWindowLimiter(limit=30, window=60, name="csp_report")
DIRECTIVE = re.compile(r"^[a-z-]{3,40}$")


def _reports(body: Any) -> list[dict[str, Any]]:
    """Both report formats: the legacy ``{"csp-report": {...}}`` and the Reporting API's list."""
    if isinstance(body, dict) and isinstance(body.get("csp-report"), dict):
        return [body["csp-report"]]
    if isinstance(body, list):
        return [r["body"] for r in body if isinstance(r, dict) and isinstance(r.get("body"), dict)][:20]
    return []


def _host(uri: Any) -> str:
    text = str(uri or "")[:300]
    if text in ("inline", "eval", "self", "data", "blob") or not text:
        return text or "unknown"
    return urlsplit(text).hostname or text.split(":")[0][:40]


@router.post(CSP_REPORT_PATH, status_code=204, include_in_schema=False)
async def csp_report(request: Request) -> Response:
    if not await _limiter.allow(client_ip(request) or "unknown"):
        return Response(status_code=204)  # quietly: a flood is itself visible in the metric already counted
    raw = await request.body()
    if len(raw) > MAX_BYTES:
        return Response(status_code=204)
    try:
        reports = _reports(json.loads(raw or b"null"))
    except ValueError:
        return Response(status_code=204)
    for report in reports:
        directive = str(report.get("effectiveDirective") or report.get("effective-directive")
                        or report.get("violated-directive") or "unknown").split(" ")[0].lower()  # fmt: skip
        directive = directive if DIRECTIVE.match(directive) else "unknown"
        metrics.CSP_VIOLATIONS.labels(directive).inc()
        blocked = _host(report.get("blockedURL") or report.get("blocked-uri"))
        page = urlsplit(str(report.get("documentURL") or report.get("document-uri") or "")).path[:120]
        logger.warning("CSP violation: %s blocked %s on %s", directive, blocked, page or "?")
    return Response(status_code=204)
