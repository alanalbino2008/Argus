"""Official Python client for the Argus API.

    from argus_client import ArgusClient

    argus = ArgusClient("https://argus.example.com", api_key="argus_…")
    scan = argus.scan("example.com", purpose="Annual external assessment, ticket SEC-42")
    investigation = argus.wait(scan["investigation_id"])
    print(argus.rating(investigation["id"])["grade"])

Rate limits are handled for you: a ``429`` or ``503`` is retried after the server's
``Retry-After`` (a few times, then :class:`RateLimited` is raised). Every other error raises an
:class:`ArgusError` subclass carrying the server's human-readable ``detail``.

Polling is cheap: answers the server marks with an ``ETag`` (campaigns, TAXII) are remembered, and
asked for again with ``If-None-Match``; while nothing changed the server answers ``304`` and the
remembered answer is returned. :meth:`ArgusClient.taxii_objects` reads a TAXII collection, page by
page, as a SIEM connector would.

Webhooks: :func:`verify_webhook` checks a delivery's Standard Webhooks signature.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import time
from collections import OrderedDict
from collections.abc import Iterator, Mapping
from typing import Any

import httpx

__all__ = [
    "ArgusClient",
    "ArgusError",
    "AuthenticationError",
    "NotFound",
    "PermissionDenied",
    "RateLimited",
    "ValidationError",
    "WebhookVerificationError",
    "verify_webhook",
]
__version__ = "1.126.0"

FINISHED = {"completed", "cancelled", "failed"}
TAXII_MEDIA_TYPE = "application/taxii+json;version=2.1"
MAX_REMEMBERED = 256  # answers kept for conditional requests
USER_AGENT = f"argus-client-python/{__version__}"


class ArgusError(Exception):
    """The API refused the request. ``detail`` is a message that can be shown to a person."""

    def __init__(self, status_code: int, detail: Any, response: httpx.Response | None = None):
        self.status_code = status_code
        self.detail = detail
        self.response = response
        super().__init__(f"HTTP {status_code}: {detail}")


class AuthenticationError(ArgusError):
    """401: the API key is missing, wrong or revoked."""


class PermissionDenied(ArgusError):
    """403: the key's role in this workspace is not enough."""


class NotFound(ArgusError):
    """404: it does not exist, or belongs to a workspace this key cannot see."""


class ValidationError(ArgusError):
    """422: the request was invalid; ``detail`` explains what to fix."""


class RateLimited(ArgusError):
    """429: still over the rate limit after retrying. ``retry_after`` is in seconds."""

    def __init__(self, status_code: int, detail: Any, response: httpx.Response | None = None):
        super().__init__(status_code, detail, response)
        self.retry_after = _retry_after(response) if response is not None else None


_ERRORS = {401: AuthenticationError, 403: PermissionDenied, 404: NotFound, 422: ValidationError, 429: RateLimited}


def _retry_after(response: httpx.Response) -> float | None:
    try:
        return float(response.headers["Retry-After"])
    except (KeyError, ValueError):
        return None


KNOWN_LISTS = ("names", "usernames", "emails", "phones", "profiles", "websites")


def _known(known: dict[str, Any]) -> dict[str, Any]:
    """Known details as the server takes them: a single value is accepted where a list is expected."""
    return {k: ([v] if k in KNOWN_LISTS and isinstance(v, str) else v) for k, v in known.items()}


class ArgusClient:
    """A connection to one Argus server, acting in one workspace.

    :param base_url: e.g. ``https://argus.example.com``
    :param api_key: an API key (Settings → API keys)
    :param workspace: slug or id of the workspace to act in (default: the key's default)
    :param max_retries: how many times a ``429``/``503`` is retried before giving up
    :param http: an existing ``httpx.Client`` to use (for proxies, custom TLS or tests)
    """

    def __init__(
        self,
        base_url: str = "",
        api_key: str | None = None,
        *,
        workspace: str | None = None,
        timeout: float = 30.0,
        max_retries: int = 3,
        max_wait: float = 60.0,
        http: httpx.Client | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.workspace = workspace
        self.max_retries = max_retries
        self.max_wait = max_wait
        self._own_http = http is None
        self._http = http or httpx.Client(timeout=timeout, follow_redirects=False)
        self._remembered: OrderedDict[tuple[Any, ...], tuple[str, Any]] = OrderedDict()  # key -> (ETag, answer)
        self.not_modified = 0  # answers served from what the server confirmed unchanged

    # ------------------------------------------------------------------ plumbing
    def close(self) -> None:
        if self._own_http:
            self._http.close()

    def __enter__(self) -> ArgusClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def in_workspace(self, workspace: str) -> ArgusClient:
        """The same connection, acting in another workspace."""
        clone = ArgusClient(self.base_url, self.api_key, workspace=workspace, max_retries=self.max_retries,
                            max_wait=self.max_wait, http=self._http)  # fmt: skip
        clone._own_http = False
        clone._remembered = self._remembered  # keyed by workspace, so sharing is safe
        return clone

    def _headers(self) -> dict[str, str]:
        headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        if self.workspace:
            headers["X-Argus-Workspace"] = self.workspace
        return headers

    def request(self, method: str, path: str, *, json: Any = None, params: Mapping[str, Any] | None = None,
                raw: bool = False, accept: str | None = None, approval: str | None = None,
                files: Mapping[str, Any] | None = None) -> Any:  # fmt: skip
        """Call any endpoint. Returns parsed JSON (or the raw response with ``raw=True``)."""
        url = f"{self.base_url}{path}"
        clean = {k: v for k, v in (params or {}).items() if v is not None}
        headers = self._headers()
        if accept:
            headers["Accept"] = accept
        if approval:  # a second administrator approved this action (see approvals())
            headers["X-Argus-Approval"] = approval
        key = (self.workspace, path, tuple(sorted((k, str(v)) for k, v in clean.items())), accept)
        remembered = self._remembered.get(key) if method == "GET" and not raw else None
        if remembered:
            headers["If-None-Match"] = remembered[0]
        for attempt in range(self.max_retries + 1):
            if files is not None:  # a file upload (multipart form)
                response = self._http.request(method, url, files=files, params=clean, headers=headers)
            else:
                response = self._http.request(method, url, json=json, params=clean, headers=headers)
            if response.status_code in (429, 503) and attempt < self.max_retries:
                wait = _retry_after(response)
                time.sleep(min(self.max_wait, wait if wait is not None else 2.0**attempt))
                continue
            break
        if response.status_code >= 400:
            try:
                detail = response.json().get("detail", response.text)
            except ValueError:
                detail = response.text
            raise _ERRORS.get(response.status_code, ArgusError)(response.status_code, detail, response)
        if response.status_code == 304 and remembered:
            self.not_modified += 1
            self._remembered.move_to_end(key)
            return copy.deepcopy(remembered[1])
        if raw:
            return response
        if response.status_code == 204 or not response.content:
            return None
        body = response.json()
        tag = response.headers.get("ETag")
        if method == "GET" and tag:
            self._remembered[key] = (tag, copy.deepcopy(body))
            self._remembered.move_to_end(key)
            while len(self._remembered) > MAX_REMEMBERED:
                self._remembered.popitem(last=False)
        return body

    def get(self, path: str, **params: Any) -> Any:
        return self.request("GET", path, params=params)

    def post(self, path: str, body: Any = None) -> Any:
        return self.request("POST", path, json=body)

    def patch(self, path: str, body: Any) -> Any:
        return self.request("PATCH", path, json=body)

    def put(self, path: str, body: Any) -> Any:
        return self.request("PUT", path, json=body)

    def delete(self, path: str) -> None:
        self.request("DELETE", path)

    # ------------------------------------------------------------------ identity
    def me(self) -> dict[str, Any]:
        return self.get("/api/me")

    def workspaces(self) -> list[dict[str, Any]]:
        return self.get("/api/workspaces")

    # ------------------------------------------------------------------ investigations
    def scan(self, target: str, *, purpose: str, depth: int = 2, passive_only: bool = False,
             target_type: str | None = None, authorized: bool = True, **options: Any) -> dict[str, Any]:  # fmt: skip
        """Launch an investigation. You confirm you are authorised to investigate ``target``."""
        body = {"target": target, "purpose": purpose, "max_depth": depth, "passive_only": passive_only,
                "target_type": target_type, "authorized": authorized, **options}  # fmt: skip
        return self.post("/api/scan", {k: v for k, v in body.items() if v is not None})

    def investigations(self, *, target: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
        return self.get("/api/investigations", target=target, limit=limit)

    def investigation(self, investigation_id: str) -> dict[str, Any]:
        return self.get(f"/api/investigation/{investigation_id}")

    def wait(self, investigation_id: str, *, timeout: float = 1800.0, poll: float = 5.0) -> dict[str, Any]:
        """Block until the investigation finishes; returns it (status completed, cancelled or failed)."""
        deadline = time.monotonic() + timeout
        while True:
            investigation = self.investigation(investigation_id)
            if investigation["status"] in FINISHED:
                return investigation
            if time.monotonic() >= deadline:
                raise TimeoutError(f"Investigation {investigation_id} still {investigation['status']} after {timeout}s")
            time.sleep(poll)

    def graph(self, investigation_id: str) -> dict[str, Any]:
        return self.get(f"/api/investigation/{investigation_id}/graph")

    def attack_paths(self, investigation_id: str) -> dict[str, Any]:
        return self.get(f"/api/investigation/{investigation_id}/paths")

    def query(self, investigation_id: str, aql: str) -> dict[str, Any]:
        """Run an Argus Query Language query on one investigation's graph."""
        return self.post(f"/api/investigation/{investigation_id}/query", {"query": aql})

    def links(self, investigation_id: str) -> dict[str, Any]:
        """Link analysis: key entities, brokers, single points of failure and clusters."""
        return self.get(f"/api/investigation/{investigation_id}/links")

    def internet_search(self, investigation_id: str, entity_id: str, *, mode: str = "count") -> dict[str, Any]:
        """Who else shares a fingerprint, per Shodan: ``count`` (free, how common) or ``search`` (hosts, 1 credit)."""
        return self.post(
            f"/api/investigation/{investigation_id}/internet-search", {"entity_id": entity_id, "mode": mode}
        )

    def hunt(self, aql: str, *, investigations: int = 25, include_running: bool = False) -> dict[str, Any]:
        """Run one query across the workspace's most recent investigations."""
        return self.post(
            "/api/hunt", {"query": aql, "investigations": investigations, "include_running": include_running}
        )

    def annotate(self, entity_id: str, entity_type: str, value: str, *, tags: list[str] | None = None,
                 note: str = "") -> dict[str, Any]:  # fmt: skip
        """Set the team's tags and note on an entity (in every investigation); empty removes them."""
        return self.request("PUT", f"/api/annotations/{entity_id}",
                            json={"entity_type": entity_type, "value": value, "tags": tags or [], "note": note})  # fmt: skip

    def annotations(self) -> list[dict[str, Any]]:
        return self.get("/api/annotations")

    def watch_fingerprint(self, investigation_id: str, entity_id: str, *, engine: str = "shodan",
                          interval_hours: int = 24, severity: str = "high") -> dict[str, Any]:  # fmt: skip
        """Re-run a fingerprint's Shodan or Censys search every day (24) or week (168); alert on new servers."""
        return self.post("/api/fingerprint-watches", {"investigation_id": investigation_id, "entity_id": entity_id,
                         "engine": engine, "interval_hours": interval_hours, "severity": severity})  # fmt: skip

    def watch_brand(self, domain: str, *, allow: list[str] | None = None, interval_hours: int = 24) -> dict[str, Any]:
        """Look for lookalike domains of ``domain`` in Certificate Transparency; ``allow`` lists domains you own."""
        return self.post(
            "/api/brand-watches", {"domain": domain, "allow": allow or [], "interval_hours": interval_hours}
        )

    def brand_watches(self) -> list[dict[str, Any]]:
        return self.get("/api/brand-watches")

    def campaigns(self) -> list[dict[str, Any]]:
        """Lookalikes, watched servers and tagged indicators grouped by shared infrastructure, worst first."""
        return self.get("/api/campaigns")["campaigns"]

    def brand_protection(self, *, days: int = 90) -> dict[str, Any]:
        """Lookalikes, open threats, takedowns (median time to takedown), campaigns and weekly trend."""
        return self.get("/api/brand-protection/summary", days=days)

    def brand_protection_report(self, *, days: int = 90, prepared_for: str = "") -> bytes:
        """The brand-protection report as a PDF (registered and verifiable by its SHA-256)."""
        return self.request("POST", "/api/brand-protection/report", json={"days": days, "prepared_for": prepared_for},
                            raw=True).content  # fmt: skip

    def lookalike_case(self, watch_id: str, domain: str, *, case_id: str | None = None,
                       capture: bool = True) -> dict[str, Any]:  # fmt: skip
        """Open a case for a lookalike (or add it to ``case_id``), with its evidence and a capture of its website."""
        body: dict[str, Any] = {"capture": capture, "confirmed": True}
        if case_id:
            body["case_id"] = case_id
        return self.post(f"/api/brand-watches/{watch_id}/lookalikes/{domain}/case", body)

    def take_down_campaign(self, campaign_id: str, *, organisation: str = "") -> dict[str, Any]:
        """Draft one abuse report per registrar and host for a campaign (each domain tracked on its own)."""
        return self.post(f"/api/campaigns/{campaign_id}/takedown", {"organisation": organisation})

    def draft_takedown(self, watch_id: str, domain: str, *, organisation: str = "") -> dict[str, Any]:
        """Draft an abuse report for a lookalike (registrar and host contacts from RDAP, with the evidence)."""
        return self.post(f"/api/brand-watches/{watch_id}/takedowns", {"domain": domain, "organisation": organisation})

    def takedown_reported(self, watch_id: str, domain: str) -> dict[str, Any]:
        """Record that the abuse report was sent: Argus then watches for the domain going down."""
        return self.post(f"/api/brand-watches/{watch_id}/takedowns/{domain}/reported", {})

    def fingerprint_watches(self) -> list[dict[str, Any]]:
        return self.get("/api/fingerprint-watches")

    def run_watch(self, kind: str, watch_id: str) -> None:
        """Run a brand or fingerprint watch now (``kind``: ``brand`` or ``fingerprint``); resumes a paused one."""
        self.post(f"/api/{_watch_path(kind)}/{watch_id}/run", {})

    def delete_watch(self, kind: str, watch_id: str) -> None:
        self.delete(f"/api/{_watch_path(kind)}/{watch_id}")

    def watch_health(self) -> list[dict[str, Any]]:
        """Brand and fingerprint watches that are failing or were paused by Argus, worst first."""
        every = [("brand", w) for w in self.brand_watches()] + [("fingerprint", w) for w in self.fingerprint_watches()]
        found = [{"kind": kind, "id": w["id"], "name": w.get("domain") or w.get("label"),
                  "paused": not w.get("enabled", True), "failures": w.get("failures", 0),
                  "failing_since": w.get("failing_since"), "paused_reason": w.get("paused_reason"),
                  "last_message": w.get("last_message", "")}
                 for kind, w in every if w.get("failures") or w.get("paused_reason")]  # fmt: skip
        return sorted(found, key=lambda w: (not w["paused"], -w["failures"]))

    # ------------------------------------------------------------------ TAXII 2.1
    def taxii_root(self) -> str:
        """The path of this workspace's TAXII API root, e.g. ``/taxii2/ws_default/``."""
        if self.workspace:
            return f"/taxii2/{self.workspace}/"
        default = self.request("GET", "/taxii2/", accept=TAXII_MEDIA_TYPE)["default"]
        return "/" + default.split("://", 1)[-1].split("/", 1)[-1].lstrip("/")

    def taxii_collections(self) -> list[dict[str, Any]]:
        return self.request("GET", f"{self.taxii_root()}collections/", accept=TAXII_MEDIA_TYPE)["collections"]

    def taxii_objects(self, collection: str, *, added_after: str | None = None,
                      page_size: int = 500) -> Iterator[dict[str, Any]]:  # fmt: skip
        """Every STIX object of a collection (``tagged``, ``lookalikes``, ``fingerprint-servers``,
        ``campaigns`` or its id), oldest first, following ``next`` across pages. Pass the last
        ``date_added`` you saw as ``added_after`` to read only what is new."""
        path = f"{self.taxii_root()}collections/{collection}/objects/"
        params: dict[str, Any] = {"limit": page_size, "added_after": added_after}
        while True:
            page = self.request("GET", path, params=params, accept=TAXII_MEDIA_TYPE)
            yield from page.get("objects") or []
            if not page.get("more") or not page.get("next"):
                return
            params = {"limit": page_size, "added_after": added_after, "next": page["next"]}

    def case_report(self, case_id: str) -> bytes:
        """The whole case as one self-contained HTML file (opens offline; loads nothing, runs no scripts)."""
        return self.request("GET", f"/api/cases/{case_id}/report.html", raw=True).content

    def create_key(self, name: str, *, role: str = "analyst", expires_in_days: int | None = 90,
                   allowed_networks: list[str] | None = None) -> dict[str, Any]:  # fmt: skip
        """A new API key for this workspace (``key`` in the answer is shown only once)."""
        return self.post("/api/keys", {"name": name, "role": role, "expires_in_days": expires_in_days,
                                       "allowed_networks": allowed_networks or []})  # fmt: skip

    def rotate_key(self, key_id: str, *, overlap_hours: int = 24) -> dict[str, Any]:
        """Replace a key; the old one keeps working for ``overlap_hours``. Returns the new key (shown once)."""
        return self.post(f"/api/keys/{key_id}/rotate", {"overlap_hours": overlap_hours})

    def key_report(self) -> dict[str, Any]:
        """Keys expiring soon, unused for 90 days, that never expire, or usable from anywhere."""
        return self.get("/api/keys/report")

    def audit_export(self, *, format: str = "jsonl", **filters: Any) -> bytes:
        """The audit log as a file: signed JSON Lines (check with ``argus --verify-audit``) or CSV.
        Filters: ``since``, ``until`` (ISO dates), ``action``, ``actor_id``, ``scope`` ("workspace" or "all")."""
        return self.request("GET", "/api/audit/export", params={"format": format, **filters}, raw=True).content

    def audit_streams(self) -> list[dict[str, Any]]:
        return self.get("/api/audit/streams")

    def stream_audit(self, channel_id: str, *, start: str = "now", platform: bool = False) -> dict[str, Any]:
        """Forward the audit log to a Splunk, Sentinel or webhook destination (``start``: now or beginning)."""
        return self.post("/api/audit/streams", {"channel_id": channel_id, "start": start, "platform": platform})

    def scim_group_roles(self) -> dict[str, Any]:
        """Whether SCIM provisioning is on, its endpoint, and which groups give which workspace roles."""
        return self.get("/api/scim/group-roles")

    def map_scim_group(self, group: str, workspace_id: str, role: str | None) -> dict[str, Any]:
        """Members of the identity provider's ``group`` get ``role`` in the workspace (None removes it)."""
        return self.request(
            "PUT", "/api/scim/group-roles", json={"group": group, "workspace_id": workspace_id, "role": role}
        )

    def access_policy(self) -> dict[str, Any]:
        """The networks this workspace may be used from (empty: anywhere)."""
        return self.get("/api/access-policy")

    def set_access_policy(self, networks: list[str]) -> dict[str, Any]:
        """Limit this workspace to these networks; refused if it would shut out the caller."""
        return self.request("PUT", "/api/access-policy", json={"allowed_networks": networks})

    def sign_user_out(self, user_id: str) -> dict[str, Any]:
        """End every browser session of a person (platform administrators)."""
        return self.post(f"/api/users/{user_id}/sign-out", {})

    def retention(self) -> dict[str, Any]:
        """The workspace's retention periods, and what a purge would delete now."""
        return self.get("/api/retention")

    def set_retention(
        self, *, investigations_days: int = 0, alerts_days: int = 0, cases_days: int = 0
    ) -> dict[str, Any]:
        """Days to keep finished investigations, resolved alerts and closed cases (0 keeps them forever)."""
        return self.request("PUT", "/api/retention", json={"investigations_days": investigations_days,
                                                           "alerts_days": alerts_days, "cases_days": cases_days})  # fmt: skip

    def legal_hold(self, case_id: str, *, hold: bool = True, note: str = "") -> dict[str, Any]:
        """Put a case on legal hold (never deleted, by hand or by retention), or release it."""
        return self.request("PUT", f"/api/cases/{case_id}/legal-hold", json={"hold": hold, "note": note})

    def approvals(self, *, status: str = "pending") -> list[dict[str, Any]]:
        """Requests for protected actions in this workspace (pending, approved, rejected, used, expired, all)."""
        return self.get("/api/approvals", status=status)

    def approve(self, approval_id: str, *, note: str = "") -> dict[str, Any]:
        """Approve someone else's request; they then repeat their call with ``approval=approval_id``."""
        return self.post(f"/api/approvals/{approval_id}/approve", {"note": note})

    def reject(self, approval_id: str, *, note: str = "") -> dict[str, Any]:
        return self.post(f"/api/approvals/{approval_id}/reject", {"note": note})

    def report_signing_key(self) -> dict[str, Any]:
        """The public key that signs this server's case reports (compare its ``key_id`` with a report's)."""
        return self.get("/api/report-signing-key")

    def saved_queries(self) -> list[dict[str, Any]]:
        return self.get("/api/saved-queries")

    def save_query(self, name: str, aql: str, *, alert: bool = False, severity: str = "medium",
                   description: str = "") -> dict[str, Any]:  # fmt: skip
        """Save a query; with ``alert`` it runs after every scan and alerts on new matches."""
        return self.post(
            "/api/saved-queries",
            {"name": name, "query": aql, "alert": alert, "severity": severity, "description": description},
        )

    def stix(self, investigation_id: str) -> dict[str, Any]:
        """A STIX 2.1 bundle, for threat-intelligence platforms."""
        return self.get(f"/api/investigation/{investigation_id}/export/stix")

    def report_pdf(self, investigation_id: str, **options: Any) -> bytes:
        """A signed PDF report (options: prepared_for, tlp, include_inventory, compare_previous)."""
        return self.request("POST", f"/api/investigation/{investigation_id}/report", json=options or None,
                            raw=True).content  # fmt: skip

    # ------------------------------------------------------------------ ratings and suppliers
    def rating(self, investigation_id: str) -> dict[str, Any]:
        return self.get(f"/api/investigation/{investigation_id}/rating")

    def ratings(self) -> dict[str, Any]:
        return self.get("/api/ratings")

    def suppliers(self) -> dict[str, Any]:
        return self.get("/api/suppliers")

    def add_supplier(self, name: str, domain: str, *, basis: str, tier: str = "medium", data_access: str = "none",
                     **fields: Any) -> dict[str, Any]:  # fmt: skip
        """Register a supplier; it is assessed passively. ``basis``: why assessing it is legitimate."""
        return self.post("/api/suppliers", {"name": name, "domain": domain, "tier": tier, "data_access": data_access,
                                            "basis": basis, "authorized": True, **fields})  # fmt: skip

    def import_suppliers(self, csv_text: str, *, basis: str) -> dict[str, Any]:
        return self.post("/api/suppliers/import", {"csv": csv_text, "basis": basis, "authorized": True})

    # ------------------------------------------------------------------ breach and dark-web exposure
    def exposure(self, *, status: str = "open", reveal: bool = False) -> dict[str, Any]:
        """Watched domains and findings. ``reveal=True`` (analyst) includes staff addresses and is audited."""
        return self.get("/api/exposure", status=status, reveal="true" if reveal else None)

    def watch_exposure(self, domain: str, *, basis: str, organisation: str = "") -> dict[str, Any]:
        """Check ``domain`` daily for breached accounts, infostealer logs and ransomware leak-site posts."""
        return self.post("/api/exposure/watches", {"domain": domain, "organisation": organisation, "basis": basis,
                                                   "authorized": True})  # fmt: skip

    def resolve_exposure(self, finding_ids: list[str], *, note: str = "", status: str = "resolved") -> int:
        return self.post("/api/exposure/findings/status", {"ids": finding_ids, "status": status, "note": note})[
            "updated"
        ]

    # ------------------------------------------------------------------ cases and evidence
    def cases(self) -> list[dict[str, Any]]:
        return self.get("/api/cases")

    def create_case(self, title: str, *, purpose: str, restricted: bool = False, members: list[str] | None = None,
                    tags: list[str] | None = None, egress: str = "", anonymous: bool = False) -> dict[str, Any]:  # fmt: skip
        """Open a case. You confirm there is a legitimate purpose for the investigation.

        ``egress``: the route (see :meth:`routes`) its captures and scans use. ``anonymous``: nothing
        in the case may touch its subjects directly (needs an anonymous route, such as Tor).
        """
        return self.post("/api/cases", {"title": title, "purpose": purpose, "restricted": restricted,
                                        "members": members or [], "tags": tags or [], "egress": egress,
                                        "opsec_mode": "anonymous" if anonymous else "standard", "confirmed": True})  # fmt: skip

    def capture(self, case_id: str, url: str, *, note: str = "", egress: str | None = None) -> dict[str, Any]:
        """Preserve a web page as evidence: response, full-page screenshot, text, fingerprints.

        ``egress``: a route name, or "direct"; by default the case's route.
        """
        body: dict[str, Any] = {"url": url, "note": note}
        if egress is not None:
            body["egress"] = egress
        return self.post(f"/api/cases/{case_id}/captures", body)

    def watch_account(self, case_id: str, platform: str, handle: str, *, interval_hours: int = 24,
                      capture_on_change: bool = True) -> dict[str, Any]:  # fmt: skip
        """Watch an account: changes to it are recorded on the case's timeline (and captured)."""
        return self.post(f"/api/cases/{case_id}/watches", {"platform": platform, "handle": handle,
                                                           "interval_hours": interval_hours,
                                                           "capture_on_change": capture_on_change})  # fmt: skip

    def watches(self, case_id: str) -> list[dict[str, Any]]:
        return self.get(f"/api/cases/{case_id}/watches")

    def check_account(self, case_id: str, watch_id: str) -> dict[str, Any]:
        """Check a watched account now instead of waiting for its schedule."""
        return self.post(f"/api/cases/{case_id}/watches/{watch_id}/check")

    def account_history(self, case_id: str, watch_id: str) -> list[dict[str, Any]]:
        """The account when first seen and after each change, newest first."""
        return self.get(f"/api/cases/{case_id}/watches/{watch_id}/history")

    def routes(self) -> list[dict[str, Any]]:
        """Egress routes (Tor, VPN, proxy) the operator set up: names and kinds, never addresses."""
        return self.get("/api/opsec/routes")["routes"]

    def check_route(self, name: str) -> dict[str, Any]:
        """Test a route: the address sites see through it, and whether it leaks this server's own."""
        return self.post(f"/api/opsec/routes/{name}/check")

    def add_to_case(self, case_id: str, kind: str, **fields: Any) -> dict[str, Any]:
        """Add a note, entity, link, scan or event, e.g. ``add_to_case(id, "entity", data={...})``."""
        return self.post(f"/api/cases/{case_id}/items", {"kind": kind, **fields})

    def inspect_evidence(self, capture_id: str, name: str) -> dict[str, Any]:
        """What an evidence file reveals: metadata (camera, GPS, authors...) and signs of editing."""
        return self.get(f"/api/evidence/{capture_id}/files/{name}/inspect")

    def clean_copy(self, capture_id: str, name: str) -> bytes:
        """An image from the evidence with all metadata removed, for publishing or sharing safely."""
        return self.request("GET", f"/api/evidence/{capture_id}/files/{name}/clean", raw=True).content

    def sun(self, lat: float, lon: float, at: str) -> dict[str, Any]:
        """Where the sun was (and where shadows pointed) at a place and ISO 8601 time with offset."""
        return self.get("/api/tools/sun", lat=lat, lon=lon, at=at)

    def case_timeline(self, case_id: str) -> list[dict[str, Any]]:
        """Everything dated in a case, oldest first (events, account changes, evidence, scans, photo dates)."""
        return self.get(f"/api/cases/{case_id}/timeline")

    def case_places(self, case_id: str) -> dict[str, Any]:
        """Everything placed in a case, and the addresses not yet on the map."""
        return self.get(f"/api/cases/{case_id}/places")

    def geocode(self, case_id: str, item_id: str) -> dict[str, Any]:
        """Look up an address entity's position (sends the address to the geocoder, via the case's route)."""
        return self.post(f"/api/cases/{case_id}/items/{item_id}/geocode")

    def analyst_preview(self, case_id: str, task: str = "brief") -> dict[str, Any]:
        """What an AI analyst request would send (size, sources, documents left out) and cost. Sends nothing."""
        return self.get(f"/api/cases/{case_id}/analyst/preview", task=task)

    def analyse_case(self, case_id: str, task: str, *, documents: list[str] | None = None) -> dict[str, Any]:
        """Run the AI analyst ("brief", "extract" or "report"). Calling this confirms that the case's
        material may be sent to Anthropic. Suggestions are returned for review, never added."""
        body: dict[str, Any] = {"task": task, "acknowledged": True}
        if documents is not None:
            body["documents"] = documents
        return self.post(f"/api/cases/{case_id}/analyst", body)

    def playbooks(self) -> list[dict[str, Any]]:
        """The playbooks, their steps, and which of their sources need a key here."""
        return self.get("/api/playbooks")

    def run_playbook(self, case_id: str, playbook: str, seed: str, *, ai_brief: bool = False) -> dict[str, Any]:
        """Start a playbook in a case (calling this confirms a legitimate purpose; with ``ai_brief``, also that
        the case's material may be sent to Anthropic). Follow it with ``playbook_run()``."""
        return self.post(
            f"/api/cases/{case_id}/playbooks",
            {"playbook": playbook, "seed": seed, "confirmed": True, "ai_brief": ai_brief, "ai_acknowledged": ai_brief},
        )

    def playbook_run(self, case_id: str, run_id: str) -> dict[str, Any]:
        """A playbook run: its status, each step, and what stood out."""
        return self.get(f"/api/cases/{case_id}/playbooks/{run_id}")

    # ------------------------------------------------------------------ people: known details (Phases 101-102)
    def people(self, case_id: str) -> list[dict[str, Any]]:
        """The people researched in a case, with their known details and how many candidates wait."""
        return self.get(f"/api/cases/{case_id}/subjects")

    def add_person(self, case_id: str, name: str, **known: Any) -> dict[str, Any]:
        """Add a person with what is known (``names``, ``usernames``, ``emails``, ``phones``, ``profiles``,
        ``websites`` as lists; ``city``, ``employer``, ``birth_year``). Calling this confirms a legitimate
        purpose for researching them."""
        return self.post(f"/api/cases/{case_id}/subjects", {"name": name, "known": _known(known), "confirmed": True})

    def person(self, case_id: str, person_id: str) -> dict[str, Any]:
        """A person, their known details, the latest search and every candidate (best first)."""
        return self.get(f"/api/cases/{case_id}/subjects/{person_id}")

    def update_person(self, case_id: str, person_id: str, *, name: str | None = None,
                      known: Mapping[str, Any] | None = None) -> dict[str, Any]:  # fmt: skip
        """Rename, and/or replace the known details entirely (see ``add_known`` to add to them)."""
        body: dict[str, Any] = {}
        if name is not None:
            body["name"] = name
        if known is not None:
            body["known"] = _known(dict(known))
        return self.put(f"/api/cases/{case_id}/subjects/{person_id}", body)

    def add_known(self, case_id: str, person_id: str, **details: Any) -> dict[str, Any]:
        """Add to what is known: list fields are extended (a single value is fine), the others replaced."""
        known = dict(self.person(case_id, person_id)["known"])
        for field, value in details.items():
            if field in KNOWN_LISTS:
                values = [value] if isinstance(value, str) else list(value)
                known[field] = list(known.get(field) or []) + [v for v in values if v not in (known.get(field) or [])]
            else:
                known[field] = value
        return self.update_person(case_id, person_id, known=known)

    def person_photo(
        self, case_id: str, person_id: str, image: bytes, *, filename: str = "photo.jpg"
    ) -> dict[str, Any]:
        """A known photo of the person: only its fingerprint is kept, to recognise the same picture on a profile."""
        return self.request("POST", f"/api/cases/{case_id}/subjects/{person_id}/photo",
                            files={"file": (filename, image, "application/octet-stream")})  # fmt: skip

    def search_person(self, case_id: str, person_id: str, *, rounds: int = 2, fresh: bool = False) -> dict[str, Any]:
        """Search from everything known (only what was not searched before, unless ``fresh``); ``rounds`` is how
        far to follow very good matches (1: known details only). Confirms a legitimate purpose. Runs in the
        background: follow it with ``wait_for_person()``."""
        return self.post(f"/api/cases/{case_id}/subjects/{person_id}/run",
                         {"confirmed": True, "rounds": rounds, "fresh": fresh})  # fmt: skip

    def wait_for_person(self, case_id: str, person_id: str, *, timeout: float = 3600.0,
                        poll: float = 5.0) -> dict[str, Any]:  # fmt: skip
        """Block until the person's search finishes; returns the person with every candidate."""
        deadline = time.monotonic() + timeout
        while True:
            found = self.person(case_id, person_id)
            if found["status"] != "running":
                return found
            if time.monotonic() >= deadline:
                raise TimeoutError(f"The search for {person_id} was still running after {timeout}s")
            time.sleep(poll)

    def stop_person_search(self, case_id: str, person_id: str) -> dict[str, Any]:
        return self.post(f"/api/cases/{case_id}/subjects/{person_id}/run/cancel")

    def candidates(self, case_id: str, person_id: str, *, status: str | None = "open",
                   verdicts: tuple[str, ...] | None = None, min_score: int = 0) -> list[dict[str, Any]]:  # fmt: skip
        """A person's candidates, best first: by ``status`` (open, confirmed, rejected; None for all), verdict
        (likely, possible, weak, unlikely) and score. Each says why it scored as it did (``agree``,
        ``conflict``). Scores are possibilities, never identifications."""
        return [c for c in self.person(case_id, person_id)["candidates"]
                if (status is None or c.get("status") == status) and (verdicts is None or c.get("verdict") in verdicts)
                and (c.get("score") or 0) >= min_score]  # fmt: skip

    def confirm_candidate(self, case_id: str, person_id: str, candidate_id: str, *, search: bool = False,
                          note: str = "") -> dict[str, Any]:  # fmt: skip
        """It is theirs: it becomes a known detail and a case entity (``search``: search from it now)."""
        return self.post(f"/api/cases/{case_id}/subjects/{person_id}/candidates/{candidate_id}/confirm",
                         {"search": search, "note": note})  # fmt: skip

    def reject_candidate(self, case_id: str, person_id: str, candidate_id: str, *, note: str = "") -> dict[str, Any]:
        """Not theirs: it is never suggested for this person again."""
        return self.post(f"/api/cases/{case_id}/subjects/{person_id}/candidates/{candidate_id}/reject", {"note": note})

    def reopen_candidate(self, case_id: str, person_id: str, candidate_id: str) -> dict[str, Any]:
        """Undo a rejection."""
        return self.post(f"/api/cases/{case_id}/subjects/{person_id}/candidates/{candidate_id}/reopen")

    def watch_person(self, case_id: str, person_id: str, *, on: bool = True) -> dict[str, Any]:
        """Search again every week from everything known, with an alert when new candidates turn up."""
        return self.put(f"/api/cases/{case_id}/subjects/{person_id}/watch", {"on": on})

    def remove_person(self, case_id: str, person_id: str) -> None:
        self.delete(f"/api/cases/{case_id}/subjects/{person_id}")

    def case_network(self, case_id: str) -> dict[str, Any]:
        """A case's people and organisations, their relationships, and the network analysis."""
        return self.get(f"/api/cases/{case_id}/network")

    def connection(self, case_id: str, source: str, target: str) -> dict[str, Any]:
        """The best-supported chain of relationships between two entities of a case."""
        return self.get(f"/api/cases/{case_id}/network/path", source=source, target=target)

    def suggested_relationships(self, case_id: str) -> dict[str, Any]:
        """Relationships the case's material shows that are not linked yet (nothing is added)."""
        return self.get(f"/api/cases/{case_id}/network/suggestions")

    def profile(self, case_id: str, item_id: str) -> dict[str, Any]:
        """Everything a case knows about one person or organisation."""
        return self.get(f"/api/cases/{case_id}/entities/{item_id}/profile")

    def scan_people(self, case_id: str, investigation_id: str) -> dict[str, Any]:
        """What a linked scan found that could join the case (people, accounts, contacts, relationships)."""
        return self.get(f"/api/cases/{case_id}/scan-people", investigation_id=investigation_id)

    def add_scan_people(self, case_id: str, investigation_id: str, keys: list[str], *,
                        relationships: bool = True) -> dict[str, Any]:  # fmt: skip
        """Add the chosen finds of a linked scan to the case, with the relationships between them."""
        return self.post(f"/api/cases/{case_id}/scan-people",
                         {"investigation_id": investigation_id, "keys": keys, "relationships": relationships})  # fmt: skip

    def network_pdf(self, case_id: str, *, as_of: str | None = None) -> bytes:
        """The case's network as a PDF report (optionally as it stood in a year, month or on a day)."""
        return self.request(
            "POST", f"/api/cases/{case_id}/network.pdf", json={"as_of": as_of} if as_of else {}, raw=True
        ).content

    def profile_pdf(self, case_id: str, item_id: str) -> bytes:
        """One person's profile as a PDF."""
        return self.request("POST", f"/api/cases/{case_id}/entities/{item_id}/profile.pdf", json={}, raw=True).content

    def vault_status(self) -> dict[str, Any]:
        """Whether the case vault is set up, and whether it is locked."""
        return self.get("/api/vault/status")

    def unlock_vault(self, passphrase: str) -> dict[str, Any]:
        """Unlock the case vault (Argus answers 423 to everything else while it is locked)."""
        return self.post("/api/vault/unlock", {"passphrase": passphrase})

    def lock_vault(self) -> dict[str, Any]:
        return self.post("/api/vault/lock")

    def subscription_accounts(self) -> list[dict[str, Any]]:
        """Account service (platform admins): every subscription account."""
        return self.get("/api/accounts")

    def set_subscription(self, account_id: str, **changes: Any) -> dict[str, Any]:
        """Account service: change plan, status or valid_until, e.g. from a payment provider's webhook handler."""
        return self.patch(f"/api/accounts/{account_id}", changes)

    def add_credits(self, account_id: str, amount: int, *, detail: str = "") -> dict[str, Any]:
        """Account service: add purchased Argus credits (e.g. from a payment provider's webhook handler)."""
        return self.post(
            f"/api/accounts/{account_id}/credits", {"amount": amount, "kind": "purchase", "detail": detail}
        )

    def verify_evidence(self, capture_id: str) -> dict[str, Any]:
        return self.post(f"/api/evidence/{capture_id}/verify")

    def export_case(self, case_id: str) -> bytes:
        """The self-verifying evidence bundle (ZIP)."""
        return self.request("GET", f"/api/cases/{case_id}/export", raw=True).content

    # ------------------------------------------------------------------ compliance
    def compliance(self) -> dict[str, Any]:
        """Evidence mapped to Cyber Essentials, ISO 27001, NIST CSF 2.0 and DORA, control by control."""
        return self.get("/api/compliance")

    # ------------------------------------------------------------------ executive
    def executive(self, *, days: int = 90) -> dict[str, Any]:
        """Overall status, five red/amber/green areas with reasons, key messages and top risks."""
        return self.get("/api/executive", days=days)

    def board_report(self, *, days: int = 90, tlp: str = "AMBER", prepared_for: str = "") -> bytes:
        """The two-page board report (PDF), registered for verification."""
        return self.request("POST", "/api/executive/report", json={"days": days, "tlp": tlp, "prepared_for": prepared_for},
                            raw=True).content  # fmt: skip

    # ------------------------------------------------------------------ remediation
    def tasks(self, *, status: str = "active", assignee: str | None = None, overdue: bool = False) -> dict[str, Any]:
        """Remediation tasks (most urgent first) with metrics: MTTR, SLA compliance, overdue counts."""
        return self.get("/api/remediation", status=status, assignee=assignee, overdue="true" if overdue else None)

    def track(
        self, source: dict[str, Any], *, assignee: str | None = None, external_ref: str | None = None
    ) -> dict[str, Any]:
        """Open a task for a finding, e.g. ``{"type": "attack_path", "investigation_id": …, "path_id": …}``."""
        return self.post("/api/remediation", {"source": source, "assignee": assignee, "external_ref": external_ref})

    def update_task(self, task_id: str, **changes: Any) -> dict[str, Any]:
        """Change status, owner, due date or ticket; ``note=`` is recorded on the timeline."""
        return self.patch(f"/api/remediation/{task_id}", changes)

    # ------------------------------------------------------------------ monitoring
    def monitors(self) -> list[dict[str, Any]]:
        return self.get("/api/monitors")

    def watch(self, target: str, *, purpose: str, interval_hours: int = 24, **options: Any) -> dict[str, Any]:
        """Monitor ``target`` continuously (you confirm you are authorised to)."""
        return self.post("/api/monitors", {"target": target, "purpose": purpose, "interval_hours": interval_hours,
                                           "authorized": True, **options})  # fmt: skip

    def update_alert(self, alert_id: str, *, status: str | None = None, assignee: str | None = None,
                     note: str = "") -> dict[str, Any]:  # fmt: skip
        """Move an alert along (open, investigating, resolved, false_positive) and/or assign it ("me", "" unassigns)."""
        body: dict[str, Any] = {"note": note}
        if status is not None:
            body["status"] = status
        if assignee is not None:
            body["assignee"] = assignee
        return self.request("PATCH", f"/api/alerts/{alert_id}", json=body)

    def comment_alert(self, alert_id: str, body: str) -> dict[str, Any]:
        return self.post(f"/api/alerts/{alert_id}/comments", {"body": body})

    def alert_stats(self, *, days: int = 30) -> dict[str, Any]:
        """Open alerts by severity, unassigned, and the median hours to acknowledge and to resolve."""
        return self.get("/api/alerts/stats", days=days)

    def alerts(self, **params: Any) -> list[dict[str, Any]]:
        return self.get("/api/alerts", **params)


_SIGNATURE_TAG = '<meta name="argus-signature" content="{}">'


def _watch_path(kind: str) -> str:
    paths = {"brand": "brand-watches", "fingerprint": "fingerprint-watches"}
    if kind not in paths:
        raise ValueError("kind is 'brand' or 'fingerprint'")
    return paths[kind]


def verify_report(report: bytes | str, trusted_key: str | None = None) -> dict[str, Any]:
    """Check a signed Argus case report offline (needs the ``cryptography`` package).

    ``report`` is the file's bytes or its path. Returns ``valid`` (unaltered since it was signed by the
    key it carries), ``key_id``, and ``trusted`` (that key is ``trusted_key``, a public key or key id;
    None when no key was given).
    """
    import re

    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:  # pragma: no cover - depends on the environment
        raise ImportError("verify_report needs the 'cryptography' package: pip install cryptography") from exc
    data = report if isinstance(report, bytes) else open(report, "rb").read()  # noqa: SIM115
    html = data.decode("utf-8", errors="strict")
    signatures = re.findall(r'<meta name="argus-signature" content="([^"]*)">', html)
    keys = re.findall(r'<meta name="argus-signing-key" content="([A-Za-z0-9+/=]*)">', html)
    if len(signatures) != 1 or len(keys) != 1 or not signatures[0].startswith("ed25519:"):
        return {"valid": False, "trusted": None, "problem": "Not a signed Argus report"}
    _scheme, claimed_id, signature = signatures[0].split(":", 2)
    raw_key = base64.b64decode(keys[0])
    digest = hashlib.sha256(raw_key).hexdigest()[:16]
    key_id = "-".join(digest[i : i + 4] for i in range(0, 16, 4))
    unsigned = html.replace(_SIGNATURE_TAG.format(signatures[0]), _SIGNATURE_TAG.format(""), 1).encode()
    message = b"argus-case-report/v1\n" + hashlib.sha256(unsigned).digest()
    try:
        if claimed_id != key_id:
            raise InvalidSignature
        Ed25519PublicKey.from_public_bytes(raw_key).verify(base64.b64decode(signature), message)
    except (InvalidSignature, ValueError):
        return {"valid": False, "trusted": None, "key_id": key_id, "problem": "Changed after signing, or not signed"}
    trusted = None
    if trusted_key:
        wanted = trusted_key.strip()
        trusted = wanted == keys[0] or wanted.replace("-", "").lower() == key_id.replace("-", "")
    return {"valid": True, "trusted": trusted, "key_id": key_id, "sha256": hashlib.sha256(data).hexdigest()}


def verify_webhook(secret: str, headers: Mapping[str, str], body: bytes, *, tolerance: int = 300) -> None:
    """Check a webhook's Standard Webhooks signature. Raises :class:`WebhookVerificationError`.

    Pass the *raw* request body (before JSON parsing) and the request headers.
    """
    lowered = {k.lower(): v for k, v in headers.items()}
    try:
        msg_id, timestamp = lowered["webhook-id"], int(lowered["webhook-timestamp"])
        offered = lowered["webhook-signature"].split()
    except (KeyError, ValueError) as exc:
        raise WebhookVerificationError("missing or malformed signature headers") from exc
    if abs(time.time() - timestamp) > tolerance:
        raise WebhookVerificationError("timestamp outside the tolerance window (replayed, or clock skew)")
    key = base64.b64decode(secret.removeprefix("whsec_"))
    mac = hmac.new(key, f"{msg_id}.{timestamp}.".encode() + body, hashlib.sha256).digest()
    expected = "v1," + base64.b64encode(mac).decode()
    if not any(hmac.compare_digest(expected, signature) for signature in offered):
        raise WebhookVerificationError("no valid signature")


class WebhookVerificationError(Exception):
    pass
