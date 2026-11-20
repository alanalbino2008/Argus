"""Official Python client for the Argus API.

    from argus_client import ArgusClient

    argus = ArgusClient("https://argus.example.com", api_key="argus_…")
    scan = argus.scan("example.com", purpose="Annual external assessment, ticket SEC-42")
    investigation = argus.wait(scan["investigation_id"])
    print(argus.rating(investigation["id"])["grade"])

Rate limits are handled for you: a ``429`` or ``503`` is retried after the server's
``Retry-After`` (a few times, then :class:`RateLimited` is raised). Every other error raises an
:class:`ArgusError` subclass carrying the server's human-readable ``detail``.

Webhooks: :func:`verify_webhook` checks a delivery's Standard Webhooks signature.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import time
from collections.abc import Mapping
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
__version__ = "1.58.0"

FINISHED = {"completed", "cancelled", "failed"}
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
        return clone

    def _headers(self) -> dict[str, str]:
        headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        if self.workspace:
            headers["X-Argus-Workspace"] = self.workspace
        return headers

    def request(self, method: str, path: str, *, json: Any = None, params: Mapping[str, Any] | None = None,
                raw: bool = False) -> Any:  # fmt: skip
        """Call any endpoint. Returns parsed JSON (or the raw response with ``raw=True``)."""
        url = f"{self.base_url}{path}"
        clean = {k: v for k, v in (params or {}).items() if v is not None}
        for attempt in range(self.max_retries + 1):
            response = self._http.request(method, url, json=json, params=clean, headers=self._headers())
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
        if raw:
            return response
        if response.status_code == 204 or not response.content:
            return None
        return response.json()

    def get(self, path: str, **params: Any) -> Any:
        return self.request("GET", path, params=params)

    def post(self, path: str, body: Any = None) -> Any:
        return self.request("POST", path, json=body)

    def patch(self, path: str, body: Any) -> Any:
        return self.request("PATCH", path, json=body)

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

    def alerts(self, **params: Any) -> list[dict[str, Any]]:
        return self.get("/api/alerts", **params)


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
