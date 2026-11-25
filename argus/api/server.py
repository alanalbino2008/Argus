"""FastAPI backend: REST API, persistent investigation history and live WebSocket telemetry.

State model
-----------
* The **database** is the source of truth for every investigation, past or present.
* **Running** scans also live in ``INVESTIGATIONS`` (in memory) so their graphs can
  be served live; they are dropped once their final state is persisted.
* Each WebSocket client gets its **own bounded send queue** drained by a dedicated
  task, so a slow browser can never slow the engine down. A client that falls too
  far behind is disconnected rather than allowed to exhaust memory.
* On connect, a client receives a **snapshot** of everything found so far, then live
  events - so opening the page mid-scan (or after a restart) loses nothing.

Running as several replicas (Kubernetes) behind a load balancer
----------------------------------------------------------------
Replicas coordinate through the shared database - no sticky sessions, no extra broker:

* each scan records its **owner** replica, which refreshes a **heartbeat**; a replica that
  crashes is detected by the others (its scans are marked failed), instead of every
  restart failing every running scan;
* **cancel** works from any replica: it sets a flag the owner sees on its next heartbeat;
* a WebSocket opened on a replica that is *not* running the scan **tails the database**,
  streaming new findings as the owner checkpoints them (about once a second);
* WebSocket **tickets**, the scheduler's monitor **claims** and the **audit chain** are all
  database-backed and safe under concurrency; migrations take an advisory lock.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
import time
from collections import OrderedDict
from contextlib import asynccontextmanager
from dataclasses import asdict
from datetime import datetime, timezone
from functools import partial
from pathlib import Path
from typing import Any, Literal

import aiohttp
import anyio
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy import text

from argus import __version__
from argus.accounts import own_keys, privacy
from argus.accounts.alerts import OwnerAlerts
from argus.accounts.mailer import AccountMailer
from argus.accounts.owner import box as owner_box
from argus.accounts.personal import PersonalLicence
from argus.api import remediation_hooks
from argus.api.account_routes import router as account_router
from argus.api.analyst_routes import router as analyst_router
from argus.api.annotation_routes import router as annotation_router
from argus.api.approval_routes import router as approval_router
from argus.api.auth_routes import router as auth_router
from argus.api.backup_routes import router as backup_router
from argus.api.billing_routes import router as billing_router
from argus.api.brand_watch_routes import router as brand_watch_router
from argus.api.business_routes import router as business_router
from argus.api.campaign_routes import issue_brand_report
from argus.api.campaign_routes import router as campaign_router
from argus.api.case_report_routes import router as case_report_router
from argus.api.case_routes import router as case_router
from argus.api.compliance_routes import router as compliance_router
from argus.api.connect_routes import router as connect_router
from argus.api.deps import WorkspaceContext, audit, in_workspace, public_base_url, require_platform_admin
from argus.api.executive_routes import router as executive_router
from argus.api.executive_service import issue_board_report
from argus.api.exposure_routes import router as exposure_router
from argus.api.fingerprint_watch_routes import router as fingerprint_watch_router
from argus.api.inspect_routes import router as inspect_router
from argus.api.legal_routes import router as legal_router
from argus.api.map_routes import router as map_router
from argus.api.monitor_routes import router as monitor_router
from argus.api.network_routes import router as network_router
from argus.api.notification_routes import router as notification_router
from argus.api.onboarding_routes import router as onboarding_router
from argus.api.onboarding_routes import scope_warnings
from argus.api.openapi import build_openapi
from argus.api.opsec_routes import route_for
from argus.api.opsec_routes import router as opsec_router
from argus.api.owner_console_routes import router as owner_console_router
from argus.api.owner_routes import router as owner_router
from argus.api.people_routes import auto_import
from argus.api.people_routes import router as people_router
from argus.api.personal_routes import licence_gate
from argus.api.personal_routes import router as personal_router
from argus.api.playbook_routes import RUNS as PLAYBOOK_RUNS
from argus.api.playbook_routes import router as playbook_router
from argus.api.query_routes import router as query_router
from argus.api.rating_routes import benchmark, ensure_history, rate
from argus.api.rating_routes import router as rating_router
from argus.api.remediation_routes import router as remediation_router
from argus.api.report_routes import router as report_router
from argus.api.research_routes import router as research_router
from argus.api.scheduler import SCHEDULER, MonitorScheduler
from argus.api.security_routes import router as security_router
from argus.api.supplier_routes import router as supplier_router
from argus.api.taxii_routes import router as taxii_router
from argus.api.team_routes import router as team_router
from argus.api.vault_routes import router as vault_router
from argus.api.vault_routes import vault_gate
from argus.api.watch_routes import router as watch_router
from argus.api.workspace_routes import router as workspace_router
from argus.core import runtime_config
from argus.core.engine import ArgusEngine
from argus.core.events import Event, EventType, event_bus
from argus.core.graph import IntelligenceGraph
from argus.core.models import EntityType, Investigation, InvestigationStatus, ScanConfig
from argus.core.settings import EgressRoute, Settings, get_settings
from argus.demo import DEMO_TARGET, load_demo
from argus.intel import brand_watch as brand
from argus.intel import fingerprint_watch as fp_watch
from argus.intel import hunt as hunting
from argus.intel import internet_search
from argus.intel.account_watch import AccountWatcher
from argus.intel.account_watch import client as outbound_client
from argus.intel.attack import map_investigation, to_navigator_layer
from argus.intel.brand_watch import BrandWatcher
from argus.intel.diff import compare, headline
from argus.intel.exposure import demo_findings
from argus.intel.exposure_monitor import ExposureMonitor
from argus.intel.fingerprint_watch import FingerprintWatcher
from argus.intel.identity import resolve_people
from argus.intel.link_analysis import analyze_links
from argus.intel.paths import find_attack_paths
from argus.intel.query import EXAMPLES as QUERY_EXAMPLES
from argus.intel.query import QueryError, run_query
from argus.intel.query import syntax as query_syntax
from argus.intel.remediation_clock import RemediationClock
from argus.intel.stix import build_bundle
from argus.intel.suppliers import min_grade as supplier_min_grade
from argus.intel.suppliers import worse as grade_worse
from argus.modules import get_default_modules, get_module_catalog, plugin_report
from argus.modules.analytics.graph_analyzer import GraphIntelligenceAnalyzer
from argus.notify.dispatcher import NotificationDispatcher
from argus.observability import logs, metrics
from argus.observability.middleware import ObservabilityMiddleware
from argus.reports.data import ReportOptions
from argus.reports.scheduler import ReportScheduler
from argus.reports.service import issue_report
from argus.security import vault
from argus.security.approvals import ApprovalRepository, ApprovalRequired
from argus.security.auth import SYSTEM, Principal, Role
from argus.security.crypto import secret_box_from_settings
from argus.security.headers import SecurityHeadersMiddleware
from argus.security.network import validate_scan_target
from argus.security.oidc import OidcProvider
from argus.security.ratelimit import SlidingWindowLimiter
from argus.storage import Database, InvestigationRecorder, InvestigationRepository
from argus.storage import backup as backup_files
from argus.storage.account_mail_repo import AccountMailRepository
from argus.storage.annotation_repo import AnnotationRepository
from argus.storage.backup_service import BackupService
from argus.storage.brand_watch_repo import BrandWatchRepository
from argus.storage.case_repo import CaseRepository
from argus.storage.exposure_repo import ExposureRepository
from argus.storage.fingerprint_watch_repo import FingerprintWatchRepository
from argus.storage.migrate import upgrade_database
from argus.storage.monitor_repo import MonitorRepository
from argus.storage.notification_repo import NotificationRepository
from argus.storage.owner_repo import OwnerRepository
from argus.storage.playbook_repo import PlaybookRepository
from argus.storage.rating_repo import RatingRepository
from argus.storage.remediation_repo import RemediationRepository
from argus.storage.report_repo import ReportRepository
from argus.storage.repository import ACTIVE_STATUSES
from argus.storage.saved_query_repo import SavedQueryRepository
from argus.storage.schedule_repo import ScheduleRepository
from argus.storage.security_repo import ApiKeyRepository, AuditLog, TicketStore
from argus.storage.subscriber_repo import (
    AppStateRepository,
    CreditRepository,
    SubscriberRepository,
    TeamRepository,
)
from argus.storage.supplier_repo import SupplierRepository
from argus.storage.user_repo import UserRepository
from argus.storage.vault_store import VaultService
from argus.storage.watch_repo import AccountWatchRepository
from argus.storage.workspace_repo import WorkspaceRepository

logger = logging.getLogger("argus.api")

BASE_DIR = Path(__file__).resolve().parent.parent
WEB_DIR = BASE_DIR / "web"

# Live (running) scans only. Finished investigations are read from the database.
INVESTIGATIONS: dict[str, ArgusEngine] = {}
SCAN_TASKS: dict[str, asyncio.Task[None]] = {}


# --------------------------------------------------------------------------- WebSockets
class ClientConnection:
    """One WebSocket client with its own bounded outbound queue."""

    def __init__(self, ws: WebSocket, maxsize: int):
        self.ws = ws
        self.queue: asyncio.Queue[str] = asyncio.Queue(maxsize=maxsize)
        self.dead = asyncio.Event()

    def offer(self, message: str) -> None:
        if self.dead.is_set():
            return
        try:
            self.queue.put_nowait(message)
        except asyncio.QueueFull:
            logger.warning("WebSocket client too slow; disconnecting")
            self.dead.set()

    async def pump(self) -> None:
        try:
            while True:
                await self.ws.send_text(await self.queue.get())
        finally:
            self.dead.set()


CONNECTIONS: dict[str, set[ClientConnection]] = {}


# Per-module start/finish chatter is several times the volume of actual findings and no client
# renders it: kept on the event bus (metrics, plugins) but never sent down a WebSocket.
WS_SILENT_EVENTS = frozenset({EventType.MODULE_STARTED, EventType.MODULE_FINISHED})


async def ws_dispatcher(event: Event) -> None:
    """Fan an engine event out to every client watching that investigation (non-blocking)."""
    if event.type in WS_SILENT_EVENTS:
        return
    conns = CONNECTIONS.get(event.investigation_id)
    if not conns:
        return
    payload = json.dumps(event.model_dump(mode="json"))
    for conn in list(conns):
        conn.offer(payload)


# --------------------------------------------------------------------------- lifecycle
@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    logs.configure(settings.log_format, settings.log_level, settings.instance_id)
    metrics.init(settings.instance_id, settings.max_concurrent_scans)
    restored = backup_files.apply_pending_restore(settings)  # a restore prepared before the restart, if any
    db = Database(settings.database_url, echo=settings.db_echo)
    if settings.auto_migrate:
        await upgrade_database(db)
    repo = InvestigationRepository(db, graph_cache_size=settings.graph_cache_size)
    app.state.app_state = AppStateRepository(db)
    if settings.edition != "personal":  # the owner console's settings win over the deployment's
        runtime_config.apply(settings, await app.state.app_state.get(runtime_config.STATE_KEY), owner_box(settings))
    app.state.vault = VaultService(db, app.state.app_state)
    await app.state.vault.load()  # a vault set up here starts locked: the key is only in memory once unlocked

    async def recover_scans() -> None:
        # Scans this instance was running before it restarted, legacy rows without an owner, and
        # scans whose owner stopped sending heartbeats can never finish. Other replicas' live
        # scans are left alone.
        interrupted = await repo.mark_interrupted(owned_by=settings.instance_id,
                                                  stale_seconds=settings.scan_stale_seconds)  # fmt: skip
        if interrupted:
            metrics.SCANS_INTERRUPTED.labels("restart").inc(interrupted)
            logger.warning("Marked %d interrupted investigation(s) as failed", interrupted)

    if vault.locked():
        app.state.vault.on_unlock.append(recover_scans)  # it reads encrypted scan records
    else:
        await recover_scans()

    app.state.settings, app.state.db, app.state.repo = settings, db, repo
    from argus.storage.data_version import VersionedCache

    app.state.derived_cache = VersionedCache(maxsize=128)  # campaigns and TAXII, per data version (Phase 85)
    from argus.security import ratelimit

    if settings.shared_rate_limits:
        ratelimit.use_database(db)  # named limiters hold for the whole deployment (Phase 86)
    else:
        ratelimit.use_memory()
    app.state.keys = ApiKeyRepository(db)
    app.state.approvals = ApprovalRepository(db)
    app.state.users = UserRepository(db)
    app.state.workspaces = WorkspaceRepository(db)
    app.state.oidc = OidcProvider(settings) if settings.oidc_issuer and settings.oidc_client_id else None
    app.state.audit = AuditLog(db)
    app.state.ws_tickets = TicketStore(db, settings.ws_ticket_ttl_seconds)
    app.state.scan_limiter = SlidingWindowLimiter(settings.scans_per_minute, 60, name="scans_per_minute")
    app.state.api_limiter = (
        SlidingWindowLimiter(settings.api_requests_per_minute, 60) if settings.api_requests_per_minute else None
    )
    app.state.owner = OwnerRepository(db)
    await _bootstrap_admin_key(app)
    await _audit_plugins(app)
    app.state.monitors = MonitorRepository(db)
    app.state.reports = ReportRepository(db)
    app.state.ratings = RatingRepository(db)
    app.state.suppliers = SupplierRepository(db)
    app.state.exposure = ExposureRepository(db)
    app.state.remediation = RemediationRepository(db)
    app.state.cases = CaseRepository(db)
    app.state.account_watches = AccountWatchRepository(db)
    app.state.subscribers = SubscriberRepository(db)
    app.state.credits = CreditRepository(db)
    app.state.teams = TeamRepository(db)
    app.state.playbooks = PlaybookRepository(db)
    app.state.saved_queries = SavedQueryRepository(db)
    app.state.annotations = AnnotationRepository(db)
    app.state.fingerprint_watches = FingerprintWatchRepository(db)
    app.state.brand_watches = BrandWatchRepository(db)
    app.state.report_signer = None  # loaded on first use (settings or the sealed key in the database)
    app.state.playbook_scan = _playbook_scan
    app.state.scan_engines = lambda: list(INVESTIGATIONS.values())

    async def recover_playbooks() -> None:
        stale = await app.state.playbooks.interrupt_running(settings.instance_id)
        if stale:
            logger.warning("%d playbook run(s) were left unfinished by the last shutdown: marked interrupted", stale)

    if vault.locked():
        app.state.vault.on_unlock.append(recover_playbooks)
    else:
        await recover_playbooks()
    app.state.personal = PersonalLicence(settings, app.state.app_state)
    if settings.edition == "personal":
        await app.state.personal.load()
    app.state.remediation_clock = RemediationClock(app.state.remediation, settings)
    app.state.rescan = partial(_rescan, app)
    app.state.exposure_monitor = ExposureMonitor(
        app.state.exposure,
        settings,
        suppliers=lambda workspace_id: app.state.suppliers.list_suppliers(workspace_id=workspace_id),
        on_new=lambda workspace_id, new: remediation_hooks.after_exposure_check(app, workspace_id, new),
    )
    app.state.schedules = ScheduleRepository(db)
    app.state.secret_box = secret_box_from_settings(settings)
    app.state.backups = BackupService(settings, app.state.app_state, app.state.secret_box)
    if restored:
        await app.state.audit.record(SYSTEM, "backup.restored", None, details={"previous_data_kept_in": restored})
    backup_task = (
        asyncio.create_task(app.state.backups.run_forever(), name="backups")
        if app.state.backups.available and (settings.edition == "personal" or settings.backup_dir)
        else None
    )
    if settings.edition == "personal":
        await own_keys.load(app.state.app_state, app.state.secret_box)
    app.state.notifications = NotificationRepository(db, app.state.secret_box)
    app.state.notifier = NotificationDispatcher(
        app.state.notifications,
        settings,
        files=lambda report_id, workspace_id: app.state.reports.file(report_id, workspace_id=workspace_id),
    )
    app.state.report_scheduler = ReportScheduler(
        app.state.schedules, repo, app.state.reports, app.state.workspaces, app.state.audit, settings,
        board=partial(issue_board_report, app), brand=partial(issue_brand_report, app),
    )  # fmt: skip
    report_task = (
        asyncio.create_task(app.state.report_scheduler.run_forever(), name="report-scheduler")
        if settings.report_schedules_enabled
        else None
    )
    notifier_task = (
        asyncio.create_task(app.state.notifier.run_forever(), name="notification-dispatcher")
        if settings.notifications_enabled
        else None
    )
    app.state.scheduler = MonitorScheduler(
        app.state.monitors,
        app.state.audit,
        settings,
        launch=lambda config, by, purpose, monitor_id, workspace_id: _launch_for_scheduler(
            app, config, by, purpose, monitor_id, workspace_id
        ),
        running_scans=lambda: cluster_running_scans(app),
    )
    exposure_task = (
        asyncio.create_task(app.state.exposure_monitor.run_forever(), name="exposure-monitor")
        if settings.exposure_monitoring_enabled
        else None
    )
    remediation_task = (
        asyncio.create_task(app.state.remediation_clock.run_forever(), name="remediation-clock")
        if settings.monitors_enabled
        else None
    )
    app.state.fingerprint_watcher = FingerprintWatcher(
        app.state.fingerprint_watches, settings, raise_alert=partial(_fingerprint_alert, app)
    )
    fingerprint_task = (
        asyncio.create_task(app.state.fingerprint_watcher.run_forever(), name="fingerprint-watcher")
        if settings.fingerprint_watch_enabled and settings.monitors_enabled
        else None
    )
    app.state.brand_watcher = BrandWatcher(app.state.brand_watches, settings, raise_alert=partial(_brand_alert, app))
    app.state.brand_watcher.health_alert = app.state.fingerprint_watcher.health_alert = partial(
        _watch_health_alert, app
    )
    brand_task = (
        asyncio.create_task(app.state.brand_watcher.run_forever(), name="brand-watcher")
        if settings.brand_watch_enabled and settings.monitors_enabled
        else None
    )
    app.state.account_watcher = AccountWatcher(app.state.account_watches, app.state.cases, settings, app.state.audit)
    watch_task = (
        asyncio.create_task(app.state.account_watcher.run_forever(), name="account-watcher")
        if settings.account_watch_enabled and settings.monitors_enabled
        else None
    )
    app.state.account_mail = AccountMailRepository(db)
    app.state.mailer = AccountMailer(app.state.account_mail, app.state.subscribers, settings)
    mailer_task = (  # runs whenever this is an account service: email can be switched on from the owner console
        asyncio.create_task(app.state.mailer.run_forever(), name="account-emails")
        if settings.account_service_enabled
        else None
    )
    privacy_task = (
        asyncio.create_task(privacy.run_forever(app), name="privacy-retention")
        if settings.account_service_enabled
        else None
    )
    app.state.owner_alerts = OwnerAlerts(app)
    alerts_task = (
        asyncio.create_task(app.state.owner_alerts.run_forever(), name="owner-alerts")
        if settings.edition != "personal"
        else None
    )
    from argus.security import key_expiry

    key_expiry_task = (
        asyncio.create_task(key_expiry.run_forever(app), name="key-expiry") if settings.monitors_enabled else None
    )
    config_task = (
        asyncio.create_task(_config_sync(app), name="owner-config-sync") if settings.edition != "personal" else None
    )
    licence_task = (
        asyncio.create_task(app.state.personal.run_forever(), name="licence-renewal")
        if settings.edition == "personal"
        else None
    )
    janitor_task = asyncio.create_task(_janitor(app), name="crashed-scan-janitor")
    vault_task = asyncio.create_task(_vault_idle_lock(app), name="vault-idle-lock")
    scheduler_task = (
        asyncio.create_task(app.state.scheduler.run_forever(), name="monitor-scheduler")
        if settings.monitors_enabled
        else None
    )
    event_bus.subscribe_all(ws_dispatcher)
    try:
        yield
    finally:
        ratelimit.use_memory()  # the database is closed below
        background = [
            t
            for t in (
                scheduler_task,
                janitor_task,
                notifier_task,
                report_task,
                exposure_task,
                remediation_task,
                watch_task,
                fingerprint_task,
                brand_task,
                licence_task,
                mailer_task,
                config_task,
                vault_task,
                backup_task,
                alerts_task,
                privacy_task,
                key_expiry_task,
            )
            if t
        ]
        for task in background:
            task.cancel()
        await asyncio.gather(*background, return_exceptions=True)
        if exposure_task is None:
            await app.state.exposure_monitor.sources.close()
        event_bus.unsubscribe_all(ws_dispatcher)
        runs = [t for t in PLAYBOOK_RUNS.values() if not t.done()]
        for task in runs:
            task.cancel()  # each saves itself as interrupted
        await asyncio.gather(*runs, return_exceptions=True)
        for engine in INVESTIGATIONS.values():
            engine.cancel()
        pending = [t for t in SCAN_TASKS.values() if not t.done()]
        if pending:
            await asyncio.wait(pending, timeout=15)  # let recorders persist final state
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        await db.dispose()


MIN_BOOTSTRAP_KEY_LENGTH = 32


async def _audit_plugins(app: FastAPI) -> None:
    """Third-party code runs with server privileges: record exactly what was loaded."""
    report = plugin_report()
    for name, source in report.loaded.items():
        await app.state.audit.record(SYSTEM, "plugin.loaded", name, details={"source": source})
    for name, reason in report.errors.items():
        await app.state.audit.record(SYSTEM, "plugin.rejected", name, outcome="failure", details={"reason": reason})


BOOTSTRAP_LOCK = 0x4152_4755_5342_4F4F  # "ARGUSBOO": replicas starting together bootstrap once


async def _config_sync(app: FastAPI, every: float = 30.0) -> None:
    """Pick up owner console changes made on another server of this deployment."""
    while True:
        await asyncio.sleep(every)
        try:
            stored = await app.state.app_state.get(runtime_config.STATE_KEY)
            if str((stored or {}).get("version") or "") != runtime_config.version():
                runtime_config.apply(app.state.settings, stored, owner_box(app.state.settings))
        except Exception:
            logger.exception("Could not refresh the owner console's settings")


async def _bootstrap_admin_key(app: FastAPI) -> None:
    """Guarantee an administrator can always get in - without shipping a default password."""
    settings = app.state.settings
    if not settings.auth_enabled:
        logger.warning("AUTHENTICATION IS DISABLED (ARGUS_AUTH_ENABLED=false). Never expose this instance.")
        return
    # Several replicas start at once: without the lock each sees "no admin yet" and creates one.
    async with app.state.db.cluster_lock(BOOTSTRAP_LOCK):
        await _install_bootstrap_key(app, settings)


async def _install_bootstrap_key(app: FastAPI, settings: Settings) -> None:
    keys: ApiKeyRepository = app.state.keys
    if await keys.count_active(Role.ADMIN) > 0:
        return
    if await app.state.owner.get() is not None:  # the owner signs in to the owner console: no key is recreated
        logger.info("No admin API key, and the owner console is set up: not creating one")
        return
    supplied = (settings.bootstrap_admin_key.get_secret_value() if settings.bootstrap_admin_key else "").strip() or None
    if supplied is not None and len(supplied) < MIN_BOOTSTRAP_KEY_LENGTH:
        # Fail closed: never install a guessable admin credential.
        raise RuntimeError(
            f"ARGUS_BOOTSTRAP_ADMIN_KEY must be at least {MIN_BOOTSTRAP_KEY_LENGTH} characters "
            "(generate one with: python -c \"import secrets; print('argus_' + secrets.token_urlsafe(32))\")"
        )
    record, key = await keys.create("bootstrap-admin", Role.ADMIN, created_by="system", plaintext=supplied)
    await app.state.audit.record(
        SYSTEM, "key.bootstrap", record["id"], details={"source": "env" if supplied else "generated"}
    )
    if not supplied and settings.edition == "personal":
        logger.info("Created this installation's admin API key (not shown: Argus Personal signs in with an account)")
    elif not supplied:
        banner = "=" * 72
        logger.warning(
            "\n%s\n No admin API key existed, so one was generated. It will NOT be shown again:\n\n"
            "   %s\n\n Use it to sign in to the web UI, then create personal keys and revoke this one.\n%s",
            banner,
            key,
            banner,
        )


API_DESCRIPTION = """
Everything the Argus web app does is available through this API: launch investigations, read
graphs and attack paths, watch targets, rate security posture, manage suppliers and reports,
and connect alerts to Slack, Teams, email, webhooks, Jira, ServiceNow, Splunk or Microsoft Sentinel.

**Authentication.** Send an API key as `Authorization: Bearer <key>` (or `X-API-Key: <key>`).
Keys are created by an admin under Settings → API keys and carry a role: *viewer* (read),
*analyst* (scan and edit) or *admin* (manage the workspace).

**Workspaces.** Data lives in workspaces. Requests act in your default workspace unless you
send `X-Argus-Workspace: <slug or id>`. Anything in a workspace you are not a member of
answers **404**, exactly as if it did not exist.

**Rate limits.** Each API key may make 600 requests a minute by default (and launch 10 scans a
minute). Every response carries `RateLimit-Limit`, `RateLimit-Remaining` and `RateLimit-Reset`;
a `429` also carries `Retry-After`.

**Errors** are JSON: `{"detail": "a message you can show to a person"}`; validation errors
(`422`) list each problem in `detail`.

**Webhooks** are signed with the Standard Webhooks scheme (`webhook-id`, `webhook-timestamp`,
`webhook-signature`). The guide in `docs/API.md` shows how to verify them, and the official
Python client (`clients/python`) does it for you.
"""

API_TAGS = [
    {"name": "investigations", "description": "Launch scans; read graphs, attack paths, people and exports."},
    {"name": "query", "description": "Argus Query Language: saved queries, hunts across investigations, query alerts."},
    {"name": "ratings", "description": "A-F security ratings with factor breakdowns, benchmarks and history."},
    {"name": "supplier risk", "description": "The supplier register, passive assessments and the risk matrix."},
    {
        "name": "exposure",
        "description": "Breached staff accounts, infostealer infections and ransomware leak-site posts.",
    },
    {"name": "monitoring", "description": "Continuous monitoring of targets and the alerts it raises."},
    {"name": "notifications", "description": "Alert destinations and integrations, and the delivery log."},
    {
        "name": "threat intelligence",
        "description": "A read-only TAXII 2.1 server: tagged entities, lookalike domains and fingerprint-watch servers as STIX indicators, per workspace.",
    },
    {"name": "reports", "description": "Signed PDF reports, verification and schedules."},
    {"name": "workspaces", "description": "Team workspaces and their members."},
    {"name": "security", "description": "API keys, users and the audit log."},
    {"name": "single sign-on", "description": "OpenID Connect sign-in for the web app."},
    {"name": "getting started", "description": "The guided first scan."},
    {"name": "platform", "description": "Health, modules and plugins."},
]


def _operation_id(route: Any) -> str:
    return str(route.name)


app = FastAPI(
    title="Argus API",
    summary="Outside-in attack surface intelligence: reconnaissance, ratings, supplier risk and alerts.",
    description=API_DESCRIPTION,
    version=__version__,
    lifespan=lifespan,
    openapi_tags=API_TAGS,
    generate_unique_id_function=_operation_id,
    license_info={"name": "Proprietary"},
)
app.openapi = partial(build_openapi, app)  # type: ignore[method-assign]

if get_settings().compress_responses:
    # Innermost, so security headers and metrics see the final response. Auth is by header, never a
    # cookie, so a cross-site page cannot make credentialed requests to mount a BREACH-style attack.
    app.add_middleware(GZipMiddleware, minimum_size=1024, compresslevel=5)
app.middleware("http")(licence_gate)  # personal edition: the subscription decides what is allowed
app.middleware("http")(vault_gate)  # a locked case vault: nothing but unlocking until it is open
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(ObservabilityMiddleware)  # outermost: times and labels everything, incl. errors
# Same-origin by default. The UI is served by this app, so CORS is only needed for
# separate front-ends, which must be listed explicitly (never "*").
_cors_origins = get_settings().cors_origins
if _cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins,
        allow_credentials=False,  # auth is via header, not cookies
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["Authorization", "X-API-Key", "Content-Type"],
    )
app.include_router(security_router)
app.include_router(auth_router)
app.include_router(workspace_router)
app.include_router(monitor_router)
app.include_router(notification_router)
app.include_router(report_router)
app.include_router(onboarding_router)
app.include_router(rating_router)
app.include_router(supplier_router)
app.include_router(exposure_router)
app.include_router(remediation_router)
app.include_router(executive_router)
app.include_router(compliance_router)
app.include_router(case_router)
app.include_router(opsec_router)
app.include_router(watch_router)
app.include_router(inspect_router)
app.include_router(map_router)
app.include_router(account_router)
app.include_router(billing_router)
app.include_router(business_router)
app.include_router(team_router)
app.include_router(research_router)
app.include_router(owner_router)
app.include_router(owner_console_router)
app.include_router(connect_router)
app.include_router(personal_router)
app.include_router(analyst_router)
app.include_router(query_router)
app.include_router(annotation_router)
app.include_router(fingerprint_watch_router)
app.include_router(brand_watch_router)
app.include_router(taxii_router)
app.include_router(campaign_router)
app.include_router(approval_router)


@app.exception_handler(ApprovalRequired)
async def _approval_required(request: Request, exc: ApprovalRequired) -> JSONResponse:
    """A protected action without an approval: 202 with the request a second administrator must approve."""
    return JSONResponse({"approval_required": True, "detail": exc.message, "approval": exc.approval},
                        status_code=202, headers={"X-Argus-Approval-Request": exc.approval["id"]})  # fmt: skip


app.include_router(case_report_router)
app.include_router(playbook_router)
app.include_router(vault_router)
app.include_router(backup_router)
app.include_router(legal_router)
app.include_router(network_router)
app.include_router(people_router)

# Tenant-scoped endpoints receive a WorkspaceContext: the caller, the workspace and their role there.
VIEWER = Depends(in_workspace(Role.VIEWER))
ANALYST = Depends(in_workspace(Role.ANALYST))
ADMIN = Depends(in_workspace(Role.ADMIN))
PLATFORM_ADMIN = Depends(require_platform_admin)


def get_repo(request: Request) -> InvestigationRepository:
    return request.app.state.repo


# --------------------------------------------------------------------------- helpers
class StartScanRequest(BaseModel):
    target: str = Field(min_length=1, max_length=253)
    target_type: EntityType | None = None
    max_depth: int = Field(default=2, ge=0, le=4)
    passive_only: bool = Field(default=False, description="Skip modules that contact the target's own systems")
    enabled_modules: list[str] | None = None
    concurrency_limit: int = Field(default=15, ge=1, le=50)
    purpose: str = Field(
        min_length=5,
        max_length=500,
        description="Why this target is being investigated, e.g. 'HackerOne program X, ticket #123' or 'CTF'",
    )
    authorized: bool = Field(description="Confirms you are authorised to investigate this target")
    egress: str | None = Field(
        default=None, description="Egress route (see /api/opsec/routes) every request leaves through; 'direct': none"
    )
    case_id: str | None = Field(
        default=None, description="Case the scan belongs to: it uses the case's route and is linked to the case"
    )
    handle_variants: bool = Field(
        default=False, description="Username targets: also search likely variants (jane.roe, jane_roe, janeroe...)"
    )


def _live_investigation(engine: ArgusEngine) -> Investigation:
    """The engine's Investigation with live counters/stats filled in."""
    inv = engine.investigation
    if engine.is_running:
        inv = inv.model_copy(
            update={
                "node_count": engine.graph.node_count,
                "edge_count": engine.graph.edge_count,
                "truncated": engine.truncated,
                "module_stats": {n: s.as_dict() for n, s in engine.module_stats.items()},
                "http_stats": engine.http.stats.as_dict() if engine.http else {},
            }
        )
    return inv


def _investigation_payload(inv: Investigation) -> dict[str, Any]:
    return {
        "id": inv.id,
        "name": inv.name,
        "status": inv.status.value,
        "target": inv.config.target,
        "target_type": inv.config.target_type.value,
        "max_depth": inv.config.max_depth,
        "node_count": inv.node_count,
        "edge_count": inv.edge_count,
        "truncated": inv.truncated,
        "errors": inv.errors,
        "warnings": inv.warnings,
        "module_stats": inv.module_stats,
        "http_stats": inv.http_stats,
        "created_at": inv.created_at.isoformat(),
        "completed_at": inv.completed_at.isoformat() if inv.completed_at else None,
        "created_by": inv.created_by,
        "purpose": inv.purpose,
    }


def _not_found() -> HTTPException:
    return HTTPException(status_code=404, detail="Investigation not found")


async def _resolve(inv_id: str, repo: InvestigationRepository, workspace_id: str) -> Investigation:
    """THE tenant boundary for investigations: anything outside ``workspace_id`` is "not found"."""
    engine = INVESTIGATIONS.get(inv_id)
    if engine:
        if engine.investigation.workspace_id != workspace_id:
            raise _not_found()
        return _live_investigation(engine)
    inv = await repo.get_investigation(inv_id)
    if inv is None or inv.workspace_id != workspace_id:
        raise _not_found()
    return inv


async def _resolve_graph(inv_id: str, repo: InvestigationRepository, workspace_id: str) -> IntelligenceGraph:
    engine = INVESTIGATIONS.get(inv_id)
    if engine:
        if engine.investigation.workspace_id != workspace_id:
            raise _not_found()
        return engine.graph
    await _resolve(inv_id, repo, workspace_id)  # ownership first, then the (larger) graph
    graph = await repo.load_graph(inv_id, shared=True)  # read-only: every caller only reads it
    if graph is None:
        raise _not_found()
    return graph


async def _run_scan(engine: ArgusEngine, recorder: InvestigationRecorder) -> None:
    inv_id = engine.investigation_id
    try:
        await recorder.start()
        await engine.start()
    finally:
        try:
            await asyncio.shield(recorder.finish())
        except Exception:
            logger.exception("Failed to persist final state of %s", inv_id)
        INVESTIGATIONS.pop(inv_id, None)
        SCAN_TASKS.pop(inv_id, None)


BACKGROUND_TASKS: set[asyncio.Task[Any]] = set()


def _spawn(coro: Any, name: str) -> None:
    task = asyncio.create_task(coro, name=name)
    BACKGROUND_TASKS.add(task)  # strong reference until done
    task.add_done_callback(BACKGROUND_TASKS.discard)


def _running_scans() -> int:
    """Scans running in this process."""
    return sum(1 for e in INVESTIGATIONS.values() if e.is_running or e.investigation.status.value == "initializing")


async def cluster_running_scans(app: FastAPI) -> int:
    """Scans running on any replica (live heartbeat), so the concurrency cap is cluster-wide."""
    try:
        remote = len(await app.state.repo.active_scans(app.state.settings.scan_stale_seconds))
        metrics.CLUSTER_SCANS_RUNNING.set(remote)
    except Exception:
        logger.warning("Could not count cluster-wide scans; using this replica's count", exc_info=True)
        remote = 0
    return max(_running_scans(), remote)


async def _janitor(app: FastAPI) -> None:
    """Periodically fail scans whose owning replica died (no heartbeat), so they don't stay 'running'."""
    settings: Settings = app.state.settings
    while True:
        await asyncio.sleep(max(15.0, settings.scan_stale_seconds / 4))
        if not vault.ready():
            continue  # scan records are encrypted and the vault is locked
        try:
            count = await app.state.repo.mark_interrupted(
                stale_seconds=settings.scan_stale_seconds,
                exclude=list(INVESTIGATIONS),
                reason="Interrupted: the replica running this scan stopped responding.",
            )
            if count:
                metrics.SCANS_INTERRUPTED.labels("replica_unresponsive").inc(count)
                logger.warning("Marked %d scan(s) of unresponsive replicas as failed", count)
            await cluster_running_scans(app)  # refreshes argus_cluster_scans_running
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Janitor pass failed")


VAULT_TIMER = Principal(key_id="vault-timer", name="vault timer", role=Role.VIEWER)


async def _vault_idle_lock(app: FastAPI) -> None:
    """Lock an unlocked vault after a quiet spell, unless work in progress still needs the key."""
    from argus.api.playbook_routes import RUNS

    while True:
        await asyncio.sleep(30)
        minutes = app.state.settings.vault_idle_minutes
        if not minutes or not vault.STATE.enabled or vault.locked():
            continue
        if time.monotonic() - vault.STATE.last_activity < minutes * 60:
            continue
        if any(e.is_running for e in INVESTIGATIONS.values()) or any(not t.done() for t in RUNS.values()):
            continue
        try:
            await app.state.audit.record(VAULT_TIMER, "vault.lock", None, "success", None,
                                         {"by": f"no activity for {minutes} minutes"}, None)  # fmt: skip
        except Exception:
            logger.exception("Could not record the vault locking")
        app.state.vault.lock()
        logger.info("Case vault locked after %d minutes without activity", minutes)


async def launch_scan(
    app: FastAPI,
    config: ScanConfig,
    *,
    created_by: str,
    purpose: str,
    workspace_id: str,
    monitor_id: str | None = None,
    egress: EgressRoute | None = None,
) -> ArgusEngine:
    """Single code path for every scan (manual or scheduled): record, register, run in background."""
    repo: InvestigationRepository = app.state.repo
    engine = ArgusEngine(config, egress=egress)
    engine.investigation.workspace_id = workspace_id
    engine.investigation.created_by = created_by
    engine.investigation.purpose = purpose
    engine.investigation.monitor_id = monitor_id
    await repo.save_investigation(engine.investigation)  # fail before running if it cannot be recorded

    recorder = InvestigationRecorder(
        repo, engine, flush_interval=app.state.settings.persist_flush_interval, owner=app.state.settings.instance_id
    )
    INVESTIGATIONS[engine.investigation_id] = engine
    # Keep a strong reference to the task (asyncio only holds weak refs) and log failures.
    task = asyncio.create_task(_run_scan(engine, recorder), name=f"scan-{engine.investigation_id}")
    task.add_done_callback(_on_scan_done)
    task.add_done_callback(
        lambda _t: _spawn(_after_scan_remediation(app, engine), f"remediation-{engine.investigation_id}")
    )
    if monitor_id:
        task.add_done_callback(lambda _t: _spawn(_evaluate_drift(app, engine), f"drift-{engine.investigation_id}"))
    task.add_done_callback(
        lambda _t: _spawn(_evaluate_saved_queries(app, engine), f"saved-queries-{engine.investigation_id}")
    )
    SCAN_TASKS[engine.investigation_id] = task
    metrics.SCANS_STARTED.labels("monitor" if monitor_id else "manual").inc()
    return engine


async def _rescan(app: FastAPI, config: ScanConfig, principal: Principal, purpose: str, workspace_id: str) -> str:
    """Rescan a target with a previous scan's exact configuration (to verify a remediation)."""
    settings = app.state.settings
    if not settings.allow_private_targets:
        try:
            validate_scan_target(config.target, config.target_type)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
    if await cluster_running_scans(app) >= settings.max_concurrent_scans:
        metrics.RATE_LIMITED.labels("concurrent_scans").inc()
        raise HTTPException(
            status_code=429, detail=f"Server is at its limit of {settings.max_concurrent_scans} concurrent scans"
        )
    limiter: SlidingWindowLimiter = app.state.scan_limiter
    if not await limiter.allow(principal.key_id):
        metrics.RATE_LIMITED.labels("scans_per_minute").inc()
        raise HTTPException(status_code=429, detail="Scan rate limit exceeded",
                            headers={"Retry-After": str(limiter.retry_after(principal.key_id))})  # fmt: skip
    fresh = config.model_copy(update={"allow_private_targets": settings.allow_private_targets})
    engine = await launch_scan(app, fresh, created_by=principal.name, purpose=purpose, workspace_id=workspace_id)
    return engine.investigation_id


async def _playbook_scan(app: FastAPI, config: ScanConfig, *, by: str, purpose: str, workspace_id: str,
                         egress: EgressRoute | None) -> tuple[str, IntelligenceGraph]:  # fmt: skip
    """A playbook's scan: wait for a free slot (the cluster-wide cap), run it, and wait for it to finish."""
    settings = app.state.settings
    for _ in range(120):  # up to ten minutes
        if await cluster_running_scans(app) < settings.max_concurrent_scans:
            break
        await asyncio.sleep(5)
    else:
        raise RuntimeError(f"The server stayed at its limit of {settings.max_concurrent_scans} concurrent scans")
    engine = await launch_scan(app, config, created_by=by, purpose=purpose, workspace_id=workspace_id, egress=egress)
    task = SCAN_TASKS.get(engine.investigation_id)
    if task is not None:
        await asyncio.wait({task})
    return engine.investigation_id, engine.graph


async def _after_scan_remediation(app: FastAPI, engine: ArgusEngine) -> None:
    """Every finished scan is evidence for or against the remediation tasks of its target."""
    await remediation_hooks.after_scan(app, engine.investigation, engine.graph, truncated=bool(engine.truncated))


async def _launch_for_scheduler(
    app: FastAPI, config: ScanConfig, by: str, purpose: str, monitor_id: str, workspace_id: str
) -> str:
    engine = await launch_scan(
        app, config, created_by=by, purpose=purpose, monitor_id=monitor_id, workspace_id=workspace_id
    )
    return engine.investigation_id


SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


async def _evaluate_supplier(app: FastAPI, inv: Investigation, graph: IntelligenceGraph) -> bool:
    """For a supplier's assessment: record the new grade; alert if it dropped or fell below policy.

    Returns True when the scan belonged to a supplier (its drift alerts are then skipped: for a third
    party, what matters to the buyer is the grade, not every change in its attack surface).
    """
    supplier = await app.state.suppliers.by_monitor(inv.monitor_id) if inv.monitor_id else None
    if supplier is None:
        return False
    rating = await rate(app, inv, graph)
    grade, previous = rating.get("grade"), supplier["last_grade"]
    if not grade:
        return True
    await app.state.suppliers.record_assessment(
        supplier["id"], grade=grade, score=rating["score"], investigation_id=inv.id,
        assessed_at=inv.completed_at or inv.created_at,
    )  # fmt: skip
    floor = supplier_min_grade(supplier["tier"], supplier["min_grade_override"])
    below = floor is not None and grade_worse(grade, floor)
    await remediation_hooks.after_supplier_assessment(app, inv.workspace_id, supplier, grade=grade, floor=floor,
                                                      below=below)  # fmt: skip
    dropped = previous is not None and grade_worse(grade, previous)
    if not (dropped or (below and previous is None)):
        return True  # unchanged or better (or still below, already alerted)
    severity = ("critical" if supplier["tier"] == "critical" else "high") if below else "medium"
    change = f"dropped from {previous} to {grade}" if dropped else f"was rated {grade}"
    headline_text = f"Supplier {supplier['name']} ({supplier['domain']}) {change}" + (
        f", below the {floor} required for {supplier['tier']} suppliers" if below else ""
    )
    alert = await app.state.monitors.create_alert(
        monitor_id=inv.monitor_id,
        investigation_id=inv.id,
        previous_investigation_id=supplier["last_investigation_id"] or inv.id,
        target=inv.config.target,
        severity=severity,
        headline=headline_text,
        summary={
            "supplier": {
                "id": supplier["id"],
                "name": supplier["name"],
                "tier": supplier["tier"],
                "previous_grade": previous,
                "grade": grade,
                "score": rating["score"],
                "min_grade": floor,
                "below_minimum": below,
            }
        },
        workspace_id=inv.workspace_id,
        public_url=app.state.settings.public_url,
    )
    metrics.ALERTS_RAISED.labels(severity).inc()
    await app.state.audit.record(
        SCHEDULER, "supplier.alert", alert["id"],
        details={"supplier": supplier["name"], "previous_grade": previous, "grade": grade, "below_minimum": below},
        workspace_id=inv.workspace_id,
    )  # fmt: skip
    return True


async def _evaluate_saved_queries(app: FastAPI, engine: ArgusEngine) -> None:
    """After any completed scan: the workspace's alerting saved queries, alerting on new matches."""
    inv = engine.investigation

    async def raise_alert(saved: dict[str, Any], new: dict[str, str], total: int, previous_id: str | None):
        alert = await app.state.monitors.create_alert(
            monitor_id=inv.monitor_id,
            investigation_id=inv.id,
            previous_investigation_id=previous_id or inv.id,
            target=inv.config.target,
            severity=saved["severity"],
            headline=hunting.alert_headline(saved, len(new), inv.config.target),
            summary=hunting.alert_summary(saved, new, total),
            workspace_id=inv.workspace_id,
            public_url=app.state.settings.public_url,
        )
        metrics.ALERTS_RAISED.labels(saved["severity"]).inc()
        await app.state.audit.record(
            SCHEDULER, "saved_query.alert", alert["id"],
            details={"saved_query": saved["id"], "new_matches": len(new)}, workspace_id=inv.workspace_id,
        )  # fmt: skip
        return alert

    await hunting.check_after_scan(
        investigation=inv, graph=engine.graph, repo=app.state.repo, saved_queries=app.state.saved_queries,
        raise_alert=raise_alert, annotations=await app.state.annotations.all(inv.workspace_id),
    )  # fmt: skip


async def _fingerprint_alert(
    app: FastAPI, watch: dict[str, Any], new: list[dict[str, Any]], total: int
) -> dict[str, Any] | None:
    """New servers share a watched fingerprint: one alert, linked to the investigation it was watched from."""
    alert = await app.state.monitors.create_alert(
        monitor_id=None,
        investigation_id=watch["investigation_id"],
        previous_investigation_id=watch["investigation_id"],
        target=watch["label"],
        severity=watch["severity"],
        headline=fp_watch.alert_headline(watch, len(new)),
        summary=fp_watch.alert_summary(watch, new, total),
        workspace_id=watch["workspace_id"],
        public_url=app.state.settings.public_url,
    )
    metrics.ALERTS_RAISED.labels(watch["severity"]).inc()
    await app.state.audit.record(
        SCHEDULER, "fingerprint_watch.alert", alert["id"],
        details={"watch": watch["id"], "new_servers": len(new)}, workspace_id=watch["workspace_id"],
    )  # fmt: skip
    return alert


async def _watch_health_alert(
    app: FastAPI, kind: str, watch: dict[str, Any], event: str, message: str
) -> dict[str, Any]:
    """A watch keeps failing, was paused, or works again: tell its workspace, with what to do about it."""
    from argus.intel import watch_health

    name = watch.get("domain") or watch.get("label") or watch["id"]
    severity = {"paused": "high", "failing": "medium"}.get(event, "low")
    state = await (app.state.brand_watches if kind == "brand" else app.state.fingerprint_watches).get(
        watch["id"], watch["workspace_id"]
    )
    failures = int((state or {}).get("failures") or watch_health.ALERT_AFTER)
    alert = await app.state.monitors.create_alert(
        monitor_id=None,
        investigation_id=watch.get("investigation_id") or "",
        previous_investigation_id=watch.get("investigation_id") or "",
        target=str(name),
        severity=severity,
        headline=watch_health.headline(kind, str(name), event, failures),
        summary={"watch_health": {
            "kind": kind, "watch_id": watch["id"], "name": name, "event": event, "failures": failures,
            "failing_since": (state or {}).get("failing_since"), "error": message[:300],
            "advice": "" if event == "recovered" else watch_health.advice(message),
        }},
        workspace_id=watch["workspace_id"],
        public_url=app.state.settings.public_url,
    )  # fmt: skip
    metrics.ALERTS_RAISED.labels(severity).inc()
    await app.state.audit.record(
        SCHEDULER, f"{kind}_watch.health", alert["id"],
        details={"watch": watch["id"], "event": event}, workspace_id=watch["workspace_id"],
    )  # fmt: skip
    return alert


async def _brand_alert(app: FastAPI, watch: dict[str, Any], news: list[Any], baseline: bool) -> dict[str, Any] | None:
    """New lookalike domains of a watched brand got certificates: one alert per run."""
    severity = brand.worst(news)
    alert = await app.state.monitors.create_alert(
        monitor_id=None,
        investigation_id="",
        previous_investigation_id="",
        target=watch["domain"],
        severity=severity,
        headline=brand.alert_headline(watch, news),
        summary=brand.alert_summary(watch, news, baseline),
        workspace_id=watch["workspace_id"],
        public_url=app.state.settings.public_url,
    )
    metrics.ALERTS_RAISED.labels(severity).inc()
    await app.state.audit.record(
        SCHEDULER, "brand_watch.alert", alert["id"],
        details={"watch": watch["id"], "lookalikes": len(news)}, workspace_id=watch["workspace_id"],
    )  # fmt: skip
    return alert


async def _evaluate_drift(app: FastAPI, engine: ArgusEngine) -> None:
    """After a monitored scan: compare with the previous scan and raise an alert if anything material changed."""
    inv = engine.investigation
    if inv.status != InvestigationStatus.COMPLETED:
        return
    if await _evaluate_supplier(app, inv, engine.graph):
        return
    repo: InvestigationRepository = app.state.repo
    previous = await repo.find_previous(inv)
    if previous is None:
        return  # first scan is the baseline
    old_graph = await repo.load_graph(previous.id)
    if old_graph is None:
        return
    diff = compare(old_graph, engine.graph)
    if not diff["summary"]["material"]:
        return
    worst = max(
        (p["severity"] for p in diff["new_paths"] + diff["escalated_paths"]),
        key=lambda s: SEVERITY_RANK.get(s, 0),
        default="low",
    )
    alert = await app.state.monitors.create_alert(
        monitor_id=inv.monitor_id,
        investigation_id=inv.id,
        previous_investigation_id=previous.id,
        target=inv.config.target,
        severity=worst,
        headline=headline(diff, inv.config.target),
        summary={k: diff[k] for k in ("summary", "new_paths", "escalated_paths", "resolved_paths")},
        workspace_id=inv.workspace_id,
        public_url=app.state.settings.public_url,
    )
    metrics.ALERTS_RAISED.labels(worst).inc()
    await app.state.audit.record(
        SCHEDULER,
        "alert.raised",
        alert["id"],
        details={"severity": worst, "target": inv.config.target, "notifications": alert.get("notifications_queued", 0)},
        workspace_id=inv.workspace_id,
    )


def _on_scan_done(task: asyncio.Task[None]) -> None:
    """Consume the task result so failures are logged instead of silently lost."""
    if not task.cancelled() and task.exception() is not None:
        logger.error("Scan task %s failed: %r", task.get_name(), task.exception())


# --------------------------------------------------------------------------- REST
@app.get("/metrics", include_in_schema=False)
async def prometheus_metrics(request: Request):
    """Prometheus scrape endpoint (one per replica). Optionally protected by ARGUS_METRICS_TOKEN."""
    settings: Settings = request.app.state.settings
    if not settings.metrics_enabled:
        raise HTTPException(status_code=404, detail="Not found")
    if settings.metrics_token is not None:
        expected = f"Bearer {settings.metrics_token.get_secret_value()}"
        if not hmac.compare_digest(request.headers.get("authorization", ""), expected):
            metrics.AUTH_FAILURES.labels("metrics_token").inc()
            raise HTTPException(
                status_code=401, detail="Metrics token required", headers={"WWW-Authenticate": "Bearer"}
            )
    body, content_type = metrics.render()
    return Response(body, media_type=content_type)


@app.get("/api/live")
async def live():
    """Liveness probe: the process is up and serving. Deliberately ignores the database, so a
    database outage makes pods *unready* (taken out of the load balancer) rather than restarted."""
    return {"status": "alive"}


@app.get("/api/health")
async def health(request: Request):
    """Liveness/readiness probe for Docker, Kubernetes and load balancers."""
    db: Database = request.app.state.db
    try:
        async with db.engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        db_ok = True
        metrics.DATABASE_UP.set(1)
    except Exception:
        logger.warning("Health check: database unreachable", exc_info=True)
        db_ok = False
        metrics.DATABASE_UP.set(0)
    body = {
        "status": "ok" if db_ok else "degraded",
        "database": {"backend": db.dialect, "reachable": db_ok},
        "active_scans": len(INVESTIGATIONS),
        "instance": request.app.state.settings.instance_id,
        "version": app.version,
    }
    if not db_ok:
        return Response(json.dumps(body), status_code=503, media_type="application/json")
    return body


@app.get("/api/modules")
async def list_modules(ws: WorkspaceContext = VIEWER):
    """Return list of available OSINT reconnaissance modules."""
    return [
        {
            "name": m.name,
            "description": m.description,
            "supported_types": [t.value for t in m.supported_entity_types],
            "attack_techniques": list(m.attack_techniques),
            "active": m.active,
            "requires": list(m.requires_settings),
            "configured": m.is_configured(),
            "origin": m.origin,
        }
        for m in get_module_catalog().values()
    ]


@app.get("/api/plugins")
async def list_plugins(_: Principal = PLATFORM_ADMIN):
    """Plugin status: allowlisted, loaded, rejected (with reasons) and installed-but-inactive."""
    return asdict(plugin_report())


async def _seed_exposure_demo(app: FastAPI, workspace_id: str, by: str) -> None:
    """Fictional exposure for the demo organisation (never checked against live sources)."""
    repo: ExposureRepository = app.state.exposure
    watch = await repo.create_watch(
        workspace_id=workspace_id, scope="domain", domain=DEMO_TARGET, organisation="Acme Corp", by=by,
        basis="Demonstration data (fictional)", demo=True,
    )  # fmt: skip
    if watch is None:  # already loaded
        return
    findings = demo_findings(DEMO_TARGET, datetime.now(timezone.utc))
    sources = {"breach_catalogue": {"status": "ok", "found": 3}, "domain_search": {"status": "ok", "found": 5},
               "stealer_logs": {"status": "ok", "found": 1}, "ransomware": {"status": "ok", "found": 1}}  # fmt: skip
    await repo.record_check(watch, findings, status="ok", message="Demonstration data (fictional)", sources=sources,
                            subject_names={DEMO_TARGET: "Acme Corp"})  # fmt: skip


@app.post("/api/demo")
async def load_demo_investigation(request: Request, ws: WorkspaceContext = ADMIN):
    """Load the built-in fictional demo investigation (reserved .example domains, TEST-NET IPs)."""
    principal = ws.principal
    inv_id = await load_demo(get_repo(request), ws.id)
    await _seed_exposure_demo(request.app, ws.id, principal.name)
    await audit(request, principal, "demo.load", inv_id)
    return {"investigation_id": inv_id}


@app.get("/api/investigations")
async def list_investigations(
    request: Request,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    status: InvestigationStatus | None = None,
    target: str | None = Query(None, max_length=253),
    ws: WorkspaceContext = VIEWER,
):
    """Investigation history (newest first), with live counters for running scans."""
    rows = await get_repo(request).list_investigations(
        workspace_id=ws.id, limit=limit, offset=offset, status=status.value if status else None, target=target
    )
    for row in rows:
        engine = INVESTIGATIONS.get(row["id"])
        if engine:
            row["status"] = engine.investigation.status.value
            row["nodes_count"] = engine.graph.node_count
            row["edges_count"] = engine.graph.edge_count
    return rows


@app.post("/api/scan")
async def start_scan(req: StartScanRequest, request: Request, ws: WorkspaceContext = ANALYST):
    """Initiate a new reconnaissance scan in the background."""
    principal = ws.principal
    from argus.cli.console import detect_target_type

    settings = request.app.state.settings
    target = req.target.strip()
    if not target:
        raise HTTPException(status_code=422, detail="Target must not be blank")
    if not req.authorized:
        await audit(request, principal, "scan.start", target, "denied", {"reason": "authorisation not confirmed"})
        raise HTTPException(status_code=422, detail="You must confirm you are authorised to investigate this target")
    if req.enabled_modules:
        catalog = get_module_catalog()
        unknown = set(req.enabled_modules) - set(catalog)
        if unknown:
            raise HTTPException(status_code=422, detail=f"Unknown modules: {sorted(unknown)}")
        unconfigured = sorted(n for n in req.enabled_modules if not catalog[n].is_configured())
        if unconfigured:
            raise HTTPException(status_code=422, detail=f"Modules need an API key first: {unconfigured}")

    case = None
    if req.case_id:
        case = await request.app.state.cases.get(req.case_id, workspace_id=ws.id, who=principal.name)
        if case is None:
            raise HTTPException(status_code=404, detail="Case not found")
    route = route_for(settings, case, req.egress)
    anonymous = bool(case and case["opsec_mode"] == "anonymous")
    passive_only = req.passive_only or anonymous  # an anonymous case never touches its subjects' own systems

    ttype = req.target_type or detect_target_type(target)
    if ttype == EntityType.CRYPTO_WALLET:
        from argus.intel.crypto import classify

        if classify(target) is None:
            raise HTTPException(status_code=422, detail="That is not a valid wallet address: its checksum does not "
                                                        "match, so it was probably mistyped")  # fmt: skip
    if not settings.allow_private_targets:
        try:
            validate_scan_target(target, ttype)
        except ValueError as exc:
            await audit(request, principal, "scan.start", target, "denied", {"reason": str(exc)})
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    if await cluster_running_scans(request.app) >= settings.max_concurrent_scans:
        metrics.RATE_LIMITED.labels("concurrent_scans").inc()
        raise HTTPException(
            status_code=429, detail=f"Server is at its limit of {settings.max_concurrent_scans} concurrent scans"
        )
    limiter: SlidingWindowLimiter = request.app.state.scan_limiter
    if not await limiter.allow(principal.key_id):
        metrics.RATE_LIMITED.labels("scans_per_minute").inc()
        raise HTTPException(
            status_code=429,
            detail="Scan rate limit exceeded",
            headers={"Retry-After": str(limiter.retry_after(principal.key_id))},
        )

    try:
        config = ScanConfig(
            target=target,
            target_type=ttype,
            max_depth=req.max_depth,
            passive_only=passive_only,
            handle_variants=req.handle_variants and ttype == EntityType.USERNAME,
            enabled_modules=req.enabled_modules,
            concurrency_limit=req.concurrency_limit,
            allow_private_targets=settings.allow_private_targets,
        )
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=exc.errors(include_url=False)) from exc

    try:  # fail fast (503) if we cannot record the scan, rather than run it unsaved
        engine = await launch_scan(
            request.app, config, created_by=principal.name, purpose=req.purpose, workspace_id=ws.id, egress=route
        )
    except Exception as exc:
        logger.exception("Database unavailable")
        raise HTTPException(status_code=503, detail="Database unavailable") from exc
    await audit(
        request,
        principal,
        "scan.start",
        engine.investigation_id,
        details={
            "target": target,
            "target_type": ttype.value,
            "max_depth": req.max_depth,
            "passive_only": passive_only,
            "purpose": req.purpose,
            "route": route.name if route else "direct",
            "case": req.case_id,
            "authorized_confirmed": True,
            # What the person was warned about (computed here, not trusted from the client).
            "scope_warnings": [w["code"] for w in scope_warnings(target, ttype, req.passive_only)],
        },
    )

    if case is not None:
        await request.app.state.cases.add_item(
            case["id"], by=principal.name, kind="scan", title=target, body="",
            data={"investigation_id": engine.investigation_id, "target": target}, occurred_at=None,
        )  # fmt: skip
        task = SCAN_TASKS.get(engine.investigation_id)
        if task is not None:  # when it finishes, the people it is sure of join the case
            app_ref, case_id, inv_id, workspace_id = request.app, case["id"], engine.investigation_id, ws.id
            task.add_done_callback(lambda _t: _spawn(auto_import(app_ref, case_id, inv_id, principal, workspace_id),
                                                     f"case-people-{inv_id}"))  # fmt: skip
    return {
        "status": "launched",
        "route": route.name if route else "direct",
        "passive_only": passive_only,
        "skipped_for_route": getattr(engine, "skipped_for_route", []),
        "investigation_id": engine.investigation_id,
        "target": target,
        "target_type": ttype.value,
    }


@app.get("/api/investigation/{inv_id}")
async def get_investigation(inv_id: str, request: Request, ws: WorkspaceContext = VIEWER):
    """Status, summary metrics and execution telemetry of an investigation."""
    return _investigation_payload(await _resolve(inv_id, get_repo(request), ws.id))


@app.post("/api/investigation/{inv_id}/cancel")
async def cancel_investigation(inv_id: str, request: Request, ws: WorkspaceContext = ANALYST):
    """Request cooperative cancellation of a running investigation."""
    principal = ws.principal
    inv = await _resolve(inv_id, get_repo(request), ws.id)  # tenant check first: 404 outside this workspace
    engine = INVESTIGATIONS.get(inv_id)
    if engine is not None and engine.is_running:
        engine.cancel()
        await audit(request, principal, "scan.cancel", inv_id)
        return {"status": "cancelling", "investigation_id": inv_id}
    if engine is None and await get_repo(request).request_cancel(inv_id):
        # Running on another replica: it sees the request on its next heartbeat (~1 s).
        await audit(request, principal, "scan.cancel", inv_id, details={"via": "cluster"})
        return {"status": "cancelling", "investigation_id": inv_id}
    raise HTTPException(status_code=409, detail=f"Investigation is {inv.status.value}")


@app.delete("/api/investigation/{inv_id}", status_code=204)
async def delete_investigation(inv_id: str, request: Request, ws: WorkspaceContext = ADMIN):
    """Permanently delete an investigation and all of its findings."""
    principal = ws.principal
    stored = await _resolve(inv_id, get_repo(request), ws.id)  # tenant check first: 404 outside this workspace
    if inv_id in INVESTIGATIONS or stored.status.value in ACTIVE_STATUSES:
        raise HTTPException(status_code=409, detail="Investigation is running; cancel it first")
    if not await get_repo(request).delete_investigation(inv_id):
        raise HTTPException(status_code=404, detail="Investigation not found")
    await audit(request, principal, "investigation.delete", inv_id)
    return Response(status_code=204)


@app.get("/api/investigation/{inv_id}/graph")
async def get_investigation_graph(inv_id: str, request: Request, ws: WorkspaceContext = VIEWER):
    """Retrieve full Cytoscape-formatted graph elements."""
    graph = await _resolve_graph(inv_id, get_repo(request), ws.id)
    return {
        "investigation_id": inv_id,
        "elements": graph.to_cytoscape_elements(),
        "analytics": GraphIntelligenceAnalyzer.analyze(graph),
    }


@app.get("/api/investigation/{inv_id}/export/json")
async def export_graph_json(inv_id: str, request: Request, ws: WorkspaceContext = VIEWER):
    """Export complete graph as JSON."""
    principal = ws.principal
    graph = await _resolve_graph(inv_id, get_repo(request), ws.id)
    await audit(request, principal, "investigation.export", inv_id, details={"format": "json"})
    return graph.to_dict()


@app.get("/api/investigation/{inv_id}/export/csv")
async def export_graph_csv(inv_id: str, request: Request, ws: WorkspaceContext = VIEWER):
    """Export relationships in Maltego-compatible CSV format."""
    principal = ws.principal
    graph = await _resolve_graph(inv_id, get_repo(request), ws.id)
    await audit(request, principal, "investigation.export", inv_id, details={"format": "csv"})
    return PlainTextResponse(
        graph.to_maltego_csv(),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=argus_{inv_id}_maltego.csv"},
    )


def _modules_for(inv_id: str) -> dict[str, Any]:
    engine = INVESTIGATIONS.get(inv_id)
    return engine.modules if engine else get_default_modules()


@app.get("/api/investigation/{inv_id}/attack")
async def get_attack_mapping(inv_id: str, request: Request, ws: WorkspaceContext = VIEWER):
    """Findings classified by MITRE ATT&CK reconnaissance technique, with defensive guidance."""
    graph = await _resolve_graph(inv_id, get_repo(request), ws.id)
    return map_investigation(graph, _modules_for(inv_id))


@app.get("/api/investigation/{inv_id}/paths")
async def get_attack_paths(inv_id: str, request: Request, ws: WorkspaceContext = VIEWER):
    """Attack Path Engine: findings chained into ranked, explained attack scenarios."""
    return find_attack_paths(await _resolve_graph(inv_id, get_repo(request), ws.id))


class InternetSearchRequest(BaseModel):
    entity_id: str = Field(min_length=1, max_length=64, description="A fingerprint or certificate entity in the graph")
    engine: Literal["shodan", "censys"] = Field(default="shodan", description="Which internet-scan search to ask")
    mode: Literal["count", "search"] = Field(
        default="count", description="count: how common, with top organisations and countries; search: lists hosts"
    )


_internet_search_limiter = SlidingWindowLimiter(limit=10, window=60, name="internet_search")
ENGINE_NAMES = {"shodan": "Shodan", "censys": "Censys"}


def _secret(value: Any) -> str:
    return value.get_secret_value().strip() if value else ""


def _shodan_key(settings: Settings) -> str:
    return _secret(settings.shodan_api_key)


def _engine_keys(settings: Settings) -> dict[str, str]:
    return {"shodan": _shodan_key(settings), "censys": _secret(settings.censys_api_token)}


@app.get("/api/internet-search")
async def internet_search_status(request: Request, ws: WorkspaceContext = VIEWER):
    """Which internet-wide searches this server can run for fingerprint pivots."""
    return {engine: bool(key) for engine, key in _engine_keys(request.app.state.settings).items()}


@app.post("/api/investigation/{inv_id}/internet-search")
async def internet_search_pivot(
    inv_id: str, request: Request, req: InternetSearchRequest | None = None, ws: WorkspaceContext = ANALYST
):
    """Who else on the internet shares this entity's fingerprint, according to Shodan or Censys (on demand).

    Shodan: ``count`` is free and says how common the fingerprint is; ``search`` lists up to 100 servers
    and spends one query credit. Censys: the same, through its Platform API (credit use depends on the
    account's plan). The search is the entity's own, never free text.
    """
    graph = await _resolve_graph(inv_id, get_repo(request), ws.id)  # tenant check before anything else
    if req is None:
        raise HTTPException(status_code=422, detail="Say which entity to search for")
    entity = graph.get_entity(req.entity_id)
    if entity is None:
        raise HTTPException(status_code=404, detail="Entity not found in this investigation")
    name = ENGINE_NAMES[req.engine]
    query = str((entity.metadata.get("search_queries") or {}).get(req.engine) or "")
    if not query:
        raise HTTPException(status_code=422, detail=f"This entity has no {name} search")
    settings = request.app.state.settings
    key = _engine_keys(settings)[req.engine]
    if not key:
        setting = "ARGUS_SHODAN_API_KEY" if req.engine == "shodan" else "ARGUS_CENSYS_API_TOKEN"
        raise HTTPException(status_code=409, detail=f"Internet search needs a {name} key ({setting})")
    if not await _internet_search_limiter.allow(f"{ws.id}:{ws.principal.key_id}"):
        raise HTTPException(status_code=429, detail="Too many internet searches: try again in a minute")
    try:
        async with outbound_client(settings, None) as http:
            if req.engine == "shodan":
                result = await internet_search.shodan(http, key, query, mode=req.mode)
            else:
                result = await internet_search.censys(
                    http, key, query, mode=req.mode, organization=settings.censys_organization_id
                )
    except internet_search.SearchError as exc:
        raise HTTPException(status_code=exc.status, detail=exc.detail) from exc
    except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
        raise HTTPException(status_code=502, detail=f"{name} could not be reached; try again later") from exc
    await audit(
        request, ws.principal, "investigation.internet_search", inv_id,
        details={"engine": req.engine, "mode": req.mode, "entity_type": entity.type.value, "total": result["total"]},
    )  # fmt: skip
    return {**result, "entity_id": entity.id}


class GraphQueryRequest(BaseModel):
    query: str = Field(min_length=1, max_length=2000, description="An Argus Query Language (AQL) query")


@app.get("/api/query/help")
async def query_help(ws: WorkspaceContext = VIEWER):
    """Argus Query Language: syntax summary and example queries."""
    return {"syntax": query_syntax(), "examples": QUERY_EXAMPLES}


@app.post("/api/investigation/{inv_id}/query")
async def query_graph(
    inv_id: str, request: Request, req: GraphQueryRequest | None = None, ws: WorkspaceContext = VIEWER
):
    """Run an Argus Query Language query: filters, relation patterns, shortest paths, sort/limit/group.

    Read-only and bounded. Returns matching rows, the node and edge ids to highlight, and paths.
    """
    graph = await _resolve_graph(inv_id, get_repo(request), ws.id)  # tenant check before anything else
    if req is None:
        raise HTTPException(status_code=422, detail={"message": "a query is required", "position": 0})
    try:
        annotations = await request.app.state.annotations.all(ws.id)
        return await _graph_work(inv_id, graph, partial(run_query, annotations=annotations), graph, req.query)
    except QueryError as exc:
        raise HTTPException(status_code=400, detail={"message": str(exc), "position": exc.position}) from exc


@app.get("/api/investigation/{inv_id}/links")
async def link_analysis(inv_id: str, request: Request, ws: WorkspaceContext = VIEWER):
    """Link analysis: key entities, brokers, single points of failure and communities."""
    graph = await _resolve_graph(inv_id, get_repo(request), ws.id)
    result = await _graph_work(inv_id, graph, analyze_links, graph)
    return {
        **{k: v for k, v in result.items() if k != "scores"},
        "community_of": {nid: score["community"] for nid, score in result["scores"].items()},
    }


async def _graph_work(inv_id: str, graph: IntelligenceGraph, fn: Any, *args: Any) -> Any:
    """CPU-bound graph work, always off the event loop. A running scan's graph is still being
    written by the engine, so the worker thread gets a snapshot taken here, on the loop."""
    if inv_id in INVESTIGATIONS:
        snapshot = graph.snapshot()
        args = tuple(snapshot if a is graph else a for a in args)
    return await anyio.to_thread.run_sync(fn, *args)


@app.get("/api/investigation/{inv_id}/people")
async def get_people(inv_id: str, request: Request, ws: WorkspaceContext = VIEWER):
    """Identity resolution: linked identifiers grouped into personas, each with a dossier.

    Dossiers aggregate personal data, so every access is recorded in the audit log.
    """
    principal = ws.principal
    graph = await _resolve_graph(inv_id, get_repo(request), ws.id)
    await audit(request, principal, "investigation.people", inv_id)
    return resolve_people(graph, find_attack_paths(graph)["paths"])


@app.get("/api/investigation/{inv_id}/diff")
async def diff_investigation(
    inv_id: str, request: Request, against: str | None = Query(None, max_length=64), ws: WorkspaceContext = VIEWER
):
    """What changed since an earlier scan of the same target (default: the previous completed one)."""
    repo = get_repo(request)
    inv = await _resolve(inv_id, repo, ws.id)
    previous = await _resolve(against, repo, ws.id) if against else await repo.find_previous(inv)
    if previous is None:
        raise HTTPException(status_code=404, detail="No earlier completed investigation of this target to compare with")
    if previous.config.target.lower() != inv.config.target.lower():
        raise HTTPException(status_code=422, detail="Investigations are of different targets")
    diff = compare(await _resolve_graph(previous.id, repo, ws.id), await _resolve_graph(inv_id, repo, ws.id))
    return {
        "investigation_id": inv_id,
        "previous_investigation_id": previous.id,
        "previous_completed_at": previous.completed_at.isoformat() if previous.completed_at else None,
        "headline": headline(diff, inv.config.target),
        **diff,
    }


@app.get("/api/investigation/{inv_id}/export/navigator")
async def export_attack_navigator(inv_id: str, request: Request, ws: WorkspaceContext = VIEWER):
    """ATT&CK Navigator layer (open at https://mitre-attack.github.io/attack-navigator/)."""
    principal = ws.principal
    repo = get_repo(request)
    inv, graph = await _resolve(inv_id, repo, ws.id), await _resolve_graph(inv_id, repo, ws.id)
    layer = to_navigator_layer(map_investigation(graph), f"Argus: {inv.config.target}", f"Investigation {inv_id}")
    await audit(request, principal, "investigation.export", inv_id, details={"format": "attack-navigator"})
    return JSONResponse(
        layer, headers={"Content-Disposition": f"attachment; filename=argus_{inv_id}_attack_layer.json"}
    )


@app.get("/api/investigation/{inv_id}/export/stix")
async def export_stix(inv_id: str, request: Request, ws: WorkspaceContext = VIEWER):
    """STIX 2.1 bundle for threat-intelligence platforms (OpenCTI, MISP...). Marked TLP:AMBER."""
    principal = ws.principal
    repo = get_repo(request)
    inv, graph = await _resolve(inv_id, repo, ws.id), await _resolve_graph(inv_id, repo, ws.id)
    bundle = build_bundle(inv, graph)
    await audit(request, principal, "investigation.export", inv_id, details={"format": "stix-2.1"})
    return Response(
        bundle.serialize(pretty=True),
        media_type="application/stix+json;version=2.1",
        headers={"Content-Disposition": f"attachment; filename=argus_{inv_id}_stix.json"},
    )


@app.get("/api/investigation/{inv_id}/rating")
async def get_rating(inv_id: str, request: Request, ws: WorkspaceContext = VIEWER):
    """Security rating (A-F) with its factor breakdown, improvement plan, trend and benchmark."""
    repo = get_repo(request)
    inv = await _resolve(inv_id, repo, ws.id)
    graph = await _resolve_graph(inv_id, repo, ws.id)
    rating = await rate(request.app, inv, graph)
    await ensure_history(request.app, ws.id, inv.config.target)  # the trend needs earlier scans rated too
    history = await request.app.state.ratings.history(inv.config.target, workspace_id=ws.id)
    return {
        **rating,
        "target": inv.config.target,
        "investigation_id": inv_id,
        "live": inv.status.value in ACTIVE_STATUSES,
        "history": history,
        "benchmark": await benchmark(request.app, ws.id, inv.config.target, rating.get("score", 0)),
    }


class ReportRequest(BaseModel):
    prepared_for: str = Field(default="", max_length=200, description="Client or recipient shown on the cover")
    tlp: Literal["CLEAR", "GREEN", "AMBER", "AMBER+STRICT", "RED"] = "AMBER"
    include_inventory: bool = True
    compare_previous: bool = True
    include_personal_details: bool = Field(
        default=False, description="Name the people in attack paths instead of pseudonymising them (audited)"
    )


_report_limiter = SlidingWindowLimiter(limit=10, window=60, name="report")  # per principal: PDF rendering costs CPU


@app.post("/api/investigation/{inv_id}/report")
async def generate_report(
    inv_id: str, request: Request, body: ReportRequest | None = None, ws: WorkspaceContext = ANALYST
):
    """Client-ready PDF report. Each file's SHA-256 is registered so recipients can verify it."""
    principal = ws.principal
    options = body or ReportRequest()
    repo = get_repo(request)
    inv = await _resolve(inv_id, repo, ws.id)
    if inv.status.value in ACTIVE_STATUSES:
        raise HTTPException(status_code=409, detail="The scan is still running; generate the report when it finishes")
    if not await _report_limiter.allow(principal.key_id):
        metrics.RATE_LIMITED.labels("report").inc()
        raise HTTPException(status_code=429, detail="Too many reports; try again in a minute")
    graph = await _resolve_graph(inv_id, repo, ws.id)
    report_options = ReportOptions(
        prepared_for=options.prepared_for.strip(),
        tlp=options.tlp,
        include_inventory=options.include_inventory,
        compare_previous=options.compare_previous,
        include_personal_details=options.include_personal_details,
    )
    issued = await issue_report(
        investigations=repo,
        reports=request.app.state.reports,
        investigation=inv,
        graph=graph,
        options=report_options,
        workspace=ws.workspace,
        issued_by=principal.name,
        base_url=public_base_url(request),
    )
    data, pdf, digest, filename = issued.data, issued.pdf, issued.sha256, issued.filename
    await audit(
        request,
        principal,
        "report.generate",
        inv_id,
        details={
            "report_id": data.report_id,
            "sha256": digest,
            "tlp": options.tlp,
            "prepared_for": options.prepared_for,
            "personal_details": options.include_personal_details,
        },
    )
    return Response(
        pdf,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
            "X-Argus-Report-Id": data.report_id,
            "X-Argus-Report-Sha256": digest,
        },
    )


@app.get("/api/entities/search")
async def search_entities(
    request: Request,
    q: str = Query(min_length=2, max_length=253, description="Substring of the entity value"),
    type: EntityType | None = None,
    limit: int = Query(50, ge=1, le=500),
    ws: WorkspaceContext = VIEWER,
):
    """Cross-investigation pivot: every investigation *of this workspace* in which a value has been seen."""
    return await get_repo(request).search_entities(
        q, workspace_id=ws.id, entity_type=type.value if type else None, limit=limit
    )


# --------------------------------------------------------------------------- WebSocket
@app.websocket("/ws/stream/{inv_id}")
async def websocket_stream(websocket: WebSocket, inv_id: str):
    """Snapshot of everything found so far, followed by live events.

    Authenticate with ``?ticket=`` from ``POST /api/ws-ticket`` (single use, short-lived).
    """
    if vault.locked():
        await websocket.close(code=4423)  # the case vault is locked
        return
    ticket = websocket.query_params.get("ticket")
    auth_enabled = websocket.app.state.settings.auth_enabled
    redeemed = await websocket.app.state.ws_tickets.redeem_for_workspace(ticket) if auth_enabled else None
    if auth_enabled and redeemed is None:
        metrics.AUTH_FAILURES.labels("websocket_ticket").inc()
        await websocket.close(code=4401)
        return
    repo: InvestigationRepository = websocket.app.state.repo
    engine = INVESTIGATIONS.get(inv_id)
    stored = None if engine else await repo.get_investigation(inv_id)
    owner_ws = engine.investigation.workspace_id if engine else stored.workspace_id if stored else None
    # The ticket was issued for one workspace: anything else is "not found", exactly like the REST API.
    if owner_ws is None or (redeemed is not None and redeemed[1] != owner_ws):
        await websocket.close(code=4404)
        return
    await websocket.accept()

    conn = ClientConnection(websocket, websocket.app.state.settings.ws_queue_size)
    tail_graph: IntelligenceGraph | None = None
    engine = INVESTIGATIONS.get(inv_id)  # re-check: the scan may have finished meanwhile
    if engine is not None:
        # No await between snapshot and registration: no event can slip between them.
        snapshot = _snapshot_message(_live_investigation(engine), engine.graph)
        conn.offer(snapshot)
        CONNECTIONS.setdefault(inv_id, set()).add(conn)
    else:
        # Read-only: a finished scan's graph comes from the cache, and so does its serialised snapshot.
        inv, graph = await repo.get_investigation(inv_id), await repo.load_graph(inv_id, shared=True)
        if inv is None or graph is None:
            await websocket.close(code=4404)
            return
        conn.offer(await _stored_snapshot(inv, graph))
        if inv.status.value in ACTIVE_STATUSES:
            tail_graph = graph  # running on another replica: follow it through the database

    client_gone = False

    async def tail_database(start: IntelligenceGraph) -> None:
        """Stream a scan owned by another replica by following its database checkpoints."""
        sent_entities = {e.id for e in start.get_all_entities()}
        sent_relations = {r.id for r in start.get_all_relations()}
        counts = (start.node_count, start.edge_count)
        interval = max(0.5, websocket.app.state.settings.persist_flush_interval)
        while True:
            await anyio.sleep(interval)
            progress = await repo.progress(inv_id)
            if progress is None:
                return  # deleted
            status, nodes, edges = progress
            finished = status not in ACTIVE_STATUSES
            if (nodes, edges) != counts or finished:
                counts = (nodes, edges)
                graph = await repo.load_graph(inv_id)
                if graph is None:
                    return
                for e in graph.get_all_entities():
                    if e.id not in sent_entities:
                        sent_entities.add(e.id)
                        conn.offer(_event_json("entity_discovered", inv_id, {"entity": e.model_dump(mode="json")}))
                for r in graph.get_all_relations():
                    if r.id not in sent_relations:
                        sent_relations.add(r.id)
                        conn.offer(_event_json("relation_discovered", inv_id, {"relation": r.model_dump(mode="json")}))
                if finished:
                    final = await repo.get_investigation(inv_id)
                    data: dict[str, Any] = {"analytics": GraphIntelligenceAnalyzer.analyze(graph)}
                    if final is not None and final.errors:
                        data["error"] = final.errors[-1]
                    kind = {"completed": "scan_completed", "cancelled": "scan_cancelled"}.get(status, "scan_failed")
                    conn.offer(_event_json(kind, inv_id, data))
                    await anyio.sleep_forever()  # keep the socket open, as for local scans

    async def drain_client() -> None:
        nonlocal client_gone
        try:
            while True:
                await websocket.receive_text()
        except WebSocketDisconnect:
            client_gone = True

    ws_mode = "tail" if tail_graph is not None else "live" if engine is not None else "replay"
    metrics.WS_CONNECTIONS.labels(ws_mode).inc()
    try:
        # Structured concurrency (anyio, which Starlette itself uses): whichever of
        # sender / receiver / overflow-watch finishes first cancels the other two,
        # and cancellation from the server propagates through cleanly.
        async with anyio.create_task_group() as tg:

            async def first_to_finish_wins(fn) -> None:
                try:
                    await fn()
                except Exception as exc:  # noqa: BLE001 - e.g. send on a broken socket ends this client only
                    logger.debug("WebSocket task ended: %r", exc)
                finally:
                    tg.cancel_scope.cancel()

            tg.start_soon(first_to_finish_wins, conn.pump)
            tg.start_soon(first_to_finish_wins, drain_client)
            tg.start_soon(first_to_finish_wins, conn.dead.wait)
            if tail_graph is not None:
                start_graph = tail_graph
                tg.start_soon(first_to_finish_wins, lambda: tail_database(start_graph))
    finally:
        metrics.WS_CONNECTIONS.labels(ws_mode).dec()
        conns = CONNECTIONS.get(inv_id)
        if conns is not None:
            conns.discard(conn)
            if not conns:
                CONNECTIONS.pop(inv_id, None)

    if not client_gone:  # server-side ending (e.g. slow client): tell the browser
        if conn.dead.is_set():
            metrics.WS_SLOW_CLIENTS.inc()
        try:
            await websocket.close(code=1013)
        except Exception as exc:  # noqa: BLE001 - best-effort notice to a client that may already be gone
            logger.debug("Could not close WebSocket cleanly: %r", exc)


def _event_json(kind: str, inv_id: str, data: dict[str, Any]) -> str:
    """Same wire format as engine events relayed by :func:`ws_dispatcher`."""
    return json.dumps(
        {"type": kind, "investigation_id": inv_id, "data": data, "timestamp": datetime.now(timezone.utc).isoformat()}
    )


_SNAPSHOT_CACHE: OrderedDict[str, tuple[tuple[Any, ...], str]] = OrderedDict()
SNAPSHOT_CACHE_SIZE = 8


async def _stored_snapshot(inv: Investigation, graph: IntelligenceGraph) -> str:
    """The snapshot of a stored investigation, serialised in a worker thread (tens of MB for big
    graphs) and kept for finished investigations, whose snapshot only changes with a new version."""
    version = (inv.status.value, inv.node_count, inv.edge_count, inv.completed_at, id(graph))
    cached = _SNAPSHOT_CACHE.get(inv.id)
    if cached is not None and cached[0] == version:
        _SNAPSHOT_CACHE.move_to_end(inv.id)
        return cached[1]
    text = await anyio.to_thread.run_sync(_snapshot_message, inv, graph)
    if inv.status.value not in ACTIVE_STATUSES:
        _SNAPSHOT_CACHE[inv.id] = (version, text)
        while len(_SNAPSHOT_CACHE) > SNAPSHOT_CACHE_SIZE:
            _SNAPSHOT_CACHE.popitem(last=False)
    return text


def _snapshot_message(inv: Investigation, graph: IntelligenceGraph) -> str:
    return json.dumps(
        {
            "type": "snapshot",
            "investigation_id": inv.id,
            "data": {
                "investigation": _investigation_payload(inv),
                "analytics": inv.analytics,
                "entities": [e.model_dump(mode="json") for e in graph.get_all_entities()],
                "relations": [r.model_dump(mode="json") for r in graph.get_all_relations()],
            },
        }
    )


# --------------------------------------------------------------------------- static UI
if WEB_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(WEB_DIR)), name="static")

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    async def serve_index():
        index_file = WEB_DIR / "index.html"
        if index_file.exists():
            return HTMLResponse(content=index_file.read_text(encoding="utf-8"))
        return HTMLResponse("<h3>Argus Web UI Loading...</h3>")

    @app.get("/admin", response_class=HTMLResponse, include_in_schema=False)
    async def serve_owner_console(request: Request):
        """The owner console (not on Argus Personal)."""
        if request.app.state.settings.edition == "personal":
            raise HTTPException(status_code=404, detail="Not found")
        return HTMLResponse(content=(WEB_DIR / "admin.html").read_text(encoding="utf-8"),
                            headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer",
                                     "X-Robots-Tag": "noindex, nofollow"})  # fmt: skip

    @app.get("/join-team", response_class=HTMLResponse, include_in_schema=False)
    async def serve_join_team(request: Request):
        """The account service's "join a team" page (the link in team invitations)."""
        if not request.app.state.settings.account_service_enabled:
            raise HTTPException(status_code=404, detail="Not found")
        return HTMLResponse(content=(WEB_DIR / "join.html").read_text(encoding="utf-8"),
                            headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"})  # fmt: skip

    @app.get("/reset-password", response_class=HTMLResponse, include_in_schema=False)
    async def serve_password_reset(request: Request):
        """The account service's "forgot password" page (the link in reset emails)."""
        if not request.app.state.settings.account_service_enabled:
            raise HTTPException(status_code=404, detail="Not found")
        return HTMLResponse(content=(WEB_DIR / "reset.html").read_text(encoding="utf-8"),
                            headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"})  # fmt: skip
