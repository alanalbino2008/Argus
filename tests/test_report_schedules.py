"""Scheduled reports: time-zone-correct schedules, the run pipeline, delivery and isolation."""

from __future__ import annotations

import asyncio
import hashlib
import io
from datetime import datetime, timedelta, timezone

import pytest
from pypdf import PdfReader

from argus.demo import DEMO_TARGET
from argus.reports.schedule import ScheduleError, describe, next_run, validate
from argus.storage.db import ReportFileRow, ReportScheduleRow
from tests.test_reports import _text

UTC = timezone.utc


def u(*args: int) -> datetime:
    return datetime(*args, tzinfo=UTC)


# ---------------------------------------------------------------------------- schedule arithmetic
def test_weekly_schedules_keep_local_time_across_daylight_saving():
    # Monday 08:00 London: GMT (UTC+0) in winter, BST (UTC+1) after 29 March 2026.
    assert next_run("weekly", 0, None, 8, 0, "Europe/London", u(2026, 3, 20, 12)) == u(2026, 3, 23, 8)
    assert next_run("weekly", 0, None, 8, 0, "Europe/London", u(2026, 3, 27, 12)) == u(2026, 3, 30, 7)
    assert next_run("weekly", 0, None, 8, 0, "Europe/London", u(2026, 10, 23, 12)) == u(2026, 10, 26, 8)


def test_next_run_is_strictly_after_and_handles_month_ends_and_gaps():
    assert next_run("weekly", 0, None, 8, 0, "Europe/London", u(2026, 3, 23, 8)) == u(2026, 3, 30, 7)
    assert next_run("monthly", None, 1, 9, 30, "America/New_York", u(2026, 12, 15)) == u(2027, 1, 1, 14, 30)
    assert next_run("monthly", None, 28, 0, 0, "UTC", u(2027, 2, 28, 0, 1)) == u(2027, 3, 28)
    # 01:30 on 29 March 2026 does not exist in London: it runs an hour later (02:30 BST = 01:30 UTC).
    assert next_run("weekly", 6, None, 1, 30, "Europe/London", u(2026, 3, 28, 12)) == u(2026, 3, 29, 1, 30)
    # 01:30 on 25 October 2026 happens twice in London: the first occurrence (BST) is used, once.
    first = next_run("weekly", 6, None, 1, 30, "Europe/London", u(2026, 10, 24, 12))
    assert first == u(2026, 10, 25, 0, 30)
    assert next_run("weekly", 6, None, 1, 30, "Europe/London", first) == u(2026, 11, 1, 1, 30)


def test_schedule_validation_and_wording():
    validate("weekly", 4, None, 17, 45, "Asia/Kolkata")
    for bad in [("weekly", None, None, 8, 0, "UTC"), ("monthly", None, 31, 8, 0, "UTC"),
                ("weekly", 0, None, 8, 0, "Mars/Olympus"), ("daily", 0, None, 8, 0, "UTC")]:  # fmt: skip
        with pytest.raises(ScheduleError):
            validate(*bad)
    assert describe("weekly", 0, None, 8, 0, "Europe/London") == "Every Monday at 08:00 Europe/London"
    assert describe("monthly", None, 3, 9, 5, "UTC") == "Monthly on the 3rd at 09:05 UTC"
    assert describe("monthly", None, 11, 9, 5, "UTC") == "Monthly on the 11th at 09:05 UTC"


# ---------------------------------------------------------------------------- the pipeline, end to end
ENV = {
    "monitors_enabled": "false",
    "notifications_enabled": "false",
    "report_schedules_enabled": "false",
    "encryption_key": "k" * 40,
    "smtp_host": "smtp.example.com",
    "smtp_from": "argus@acme.com",
    "public_url": "https://argus.example.com",
}


@pytest.fixture
def setup(make_client):
    client = make_client(**ENV)
    mail = client.post(
        "/api/notifications/channels",
        json={"name": "SOC mailbox", "type": "email", "destination": {"recipients": ["soc@acme.com"]}},
    ).json()
    slack = client.post(
        "/api/notifications/channels",
        json={"name": "#soc", "type": "slack", "destination": {"url": "https://hooks.slack.com/services/T/B/x"}},
    ).json()
    return client, mail, slack


def _schedule(client, channels, **extra):
    body = {"name": "Weekly exposure", "target": DEMO_TARGET, "weekday": 0, "hour": 8, "timezone": "Europe/London",
            "channel_ids": [c["id"] for c in channels], "options": {"prepared_for": "Acme Corporation"}, **extra}  # fmt: skip
    response = client.post("/api/reports/schedules", json=body)
    assert response.status_code == 201, response.text
    return response.json()


def _tick(client):
    return client.portal.call(client.app.state.report_scheduler.tick)


def _send(client, monkeypatch):
    """Run the notification dispatcher once, capturing emails and HTTP posts instead of sending them."""
    sent: dict[str, list] = {"email": [], "http": []}
    transport = client.app.state.notifier.transport
    monkeypatch.setattr(transport, "_send_mail", lambda message: sent["email"].append(message))

    async def post(url, body, headers):
        sent["http"].append((url, body))
        from argus.notify.transport import Result

        return Result(True, status_code=200)

    monkeypatch.setattr(transport, "post", post)
    client.portal.call(client.app.state.notifier.tick)
    return sent


def test_a_scheduled_report_is_generated_registered_and_delivered(setup, monkeypatch):
    client, mail, slack = setup
    schedule = _schedule(client, [mail, slack])
    assert schedule["description"] == "Every Monday at 08:00 Europe/London" and schedule["has_scan"] is False

    client.post(f"/api/reports/schedules/{schedule['id']}/run")
    assert _tick(client) == ["no_scan"]  # nothing to report on yet: nothing is sent
    assert client.get("/api/notifications/deliveries").json() == []

    client.post("/api/demo")
    client.post(f"/api/reports/schedules/{schedule['id']}/run")
    assert _tick(client) == ["sent"]
    [record] = client.get("/api/reports").json()
    assert record["created_by"] == "schedule: Weekly exposure" and record["file_available"]
    assert record["prepared_for"] == "Acme Corporation"
    state = client.get("/api/reports/schedules").json()[0]
    assert state["last_status"] == "sent" and state["last_report_id"] == record["id"]
    assert datetime.fromisoformat(state["next_run_at"]) > datetime.now(UTC)  # back on its normal slot

    sent = _send(client, monkeypatch)
    [message] = sent["email"]
    assert message["Subject"] == f"[Argus] Weekly exposure: {DEMO_TARGET} (CRITICAL)"
    [attachment] = list(message.iter_attachments())
    pdf = attachment.get_content()
    assert (
        attachment.get_filename()
        == f"argus-report-acme-corp-example-{record['created_at'][:10].replace('-', '')}-{record['id']}.pdf"
    )
    assert hashlib.sha256(pdf).hexdigest() == record["sha256"]  # the emailed file is the registered one
    body = message.get_body(("plain",)).get_content()
    assert record["sha256"] in body and f"https://argus.example.com/api/reports/verify/{record['sha256']}" in body
    [(url, payload)] = sent["http"]
    assert url == "https://hooks.slack.com/services/T/B/x" and record["sha256"].encode() in payload
    assert b"Open in Argus" in payload
    statuses = {d["channel_name"]: d["status"] for d in client.get("/api/notifications/deliveries").json()}
    assert statuses == {"SOC mailbox": "delivered", "#soc": "delivered"}
    actions = [e["action"] for e in client.get("/api/audit?limit=40").json()]
    assert "report.scheduled" in actions and "report.schedule_create" in actions


def test_unchanged_targets_are_skipped_unless_asked(setup):
    client, mail, _ = setup
    client.post("/api/demo")
    quiet = _schedule(client, [mail])
    noisy = _schedule(client, [mail], name="Always", skip_unchanged=False)
    for _ in range(2):
        for s in (quiet, noisy):
            client.post(f"/api/reports/schedules/{s['id']}/run")
        outcomes = _tick(client)
    assert sorted(outcomes) == ["sent", "skipped_unchanged"]
    assert len(client.get("/api/reports").json()) == 3


def test_unattended_reports_never_name_people(setup, monkeypatch):
    client, mail, _ = setup
    client.post("/api/demo")
    schedule = _schedule(client, [mail], options={"include_personal_details": True})  # ignored: not a schedule option
    client.post(f"/api/reports/schedules/{schedule['id']}/run")
    _tick(client)
    [message] = _send(client, monkeypatch)["email"]
    text = _text(next(message.iter_attachments()).get_content())
    assert "Dana Whitfield" not in text and "d•••@acme-corp.example" in text


def test_expired_files_fail_the_email_clearly(setup, monkeypatch):
    client, mail, _ = setup
    client.post("/api/demo")
    schedule = _schedule(client, [mail])
    client.post(f"/api/reports/schedules/{schedule['id']}/run")
    _tick(client)

    async def expire():
        async with client.app.state.db.session() as s, s.begin():
            await s.execute(ReportFileRow.__table__.update().values(expires_at=datetime.now(UTC) - timedelta(days=1)))

    client.portal.call(expire)
    assert _send(client, monkeypatch)["email"] == []
    [delivery] = client.get("/api/notifications/deliveries").json()
    assert delivery["status"] == "failed" and "expired" in delivery["last_error"]
    assert client.portal.call(client.app.state.reports.purge_files) == 1


def test_schedule_validation_through_the_api(setup, make_client):
    client, mail, _ = setup
    base = {"name": "x", "target": DEMO_TARGET, "channel_ids": [mail["id"]]}
    assert client.post("/api/reports/schedules", json={**base, "timezone": "Nowhere/Land"}).status_code == 422
    assert client.post("/api/reports/schedules", json={**base, "frequency": "monthly"}).status_code == 422
    assert client.post("/api/reports/schedules", json={**base, "channel_ids": ["chan_nope"]}).status_code == 422
    assert client.post("/api/reports/schedules", json={**base, "channel_ids": []}).status_code == 422
    monthly = client.post("/api/reports/schedules", json={**base, "frequency": "monthly", "day_of_month": 1}).json()
    assert monthly["weekday"] is None and monthly["description"].startswith("Monthly on the 1st")
    moved = client.patch(
        f"/api/reports/schedules/{monthly['id']}", json={"frequency": "weekly", "weekday": 4, "hour": 17}
    )
    assert moved.status_code == 200 and moved.json()["description"] == "Every Friday at 17:00 UTC"
    assert moved.json()["day_of_month"] is None
    assert client.patch(f"/api/reports/schedules/{monthly['id']}", json={"timezone": "Bad/Zone"}).status_code == 422
    assert client.delete(f"/api/reports/schedules/{monthly['id']}").status_code == 204


def test_schedules_and_stored_files_are_workspace_scoped(setup):
    client, mail, _ = setup
    client.post("/api/demo")
    schedule = _schedule(client, [mail])
    client.post(f"/api/reports/schedules/{schedule['id']}/run")
    _tick(client)
    [record] = client.get("/api/reports").json()
    assert client.get(f"/api/reports/{record['id']}/file").status_code == 200

    client.post("/api/workspaces", json={"name": "Red Team"})
    red = {"X-Argus-Workspace": "red-team"}
    assert client.get("/api/reports/schedules", headers=red).json() == []
    for method, path in [("PATCH", f"/api/reports/schedules/{schedule['id']}"),
                         ("DELETE", f"/api/reports/schedules/{schedule['id']}"),
                         ("POST", f"/api/reports/schedules/{schedule['id']}/run"),
                         ("GET", f"/api/reports/{record['id']}/file")]:  # fmt: skip
        kwargs = {"json": {"name": "hijack"}} if method == "PATCH" else {}
        assert client.request(method, path, headers=red, **kwargs).status_code == 404, path
    # A schedule in Red Team cannot send to Default's destinations.
    stolen = client.post(
        "/api/reports/schedules",
        json={"name": "x", "target": DEMO_TARGET, "channel_ids": [mail["id"]]},
        headers=red,
    )
    assert stolen.status_code == 422
    viewer = client.post("/api/keys", json={"name": "v", "role": "viewer"}).json()["key"]
    headers = {"Authorization": f"Bearer {viewer}"}
    assert client.get(f"/api/reports/{record['id']}/file", headers=headers).status_code == 200
    assert client.get("/api/reports/schedules", headers=headers).status_code == 403
    assert PdfReader(io.BytesIO(client.get(f"/api/reports/{record['id']}/file").content)).pages


async def test_two_replicas_send_a_due_schedule_once(tmp_path):
    from argus.core.settings import Settings
    from argus.demo import load_demo
    from argus.reports.scheduler import ReportScheduler
    from argus.storage.db import Database
    from argus.storage.migrate import upgrade_database
    from argus.storage.report_repo import ReportRepository
    from argus.storage.repository import InvestigationRepository
    from argus.storage.schedule_repo import ScheduleRepository
    from argus.storage.security_repo import AuditLog
    from argus.storage.workspace_repo import WorkspaceRepository
    from tests.conftest import database_url

    url = database_url(tmp_path, "sched.db")
    dbs = [Database(url), Database(url)]
    await upgrade_database(dbs[0])
    await load_demo(InvestigationRepository(dbs[0]), "ws_default")
    await ScheduleRepository(dbs[0]).create(
        workspace_id="ws_default", by="t", name="Weekly", target=DEMO_TARGET, frequency="weekly", weekday=0,
        day_of_month=None, hour=8, minute=0, timezone="UTC", options={}, channel_ids=[], skip_unchanged=True,
        enabled=True,
    )  # fmt: skip
    async with dbs[0].session() as s, s.begin():  # make it due
        await s.execute(
            ReportScheduleRow.__table__.update().values(next_run_at=datetime.now(UTC) - timedelta(minutes=1))
        )
    schedulers = [
        ReportScheduler(ScheduleRepository(db), InvestigationRepository(db), ReportRepository(db),
                        WorkspaceRepository(db), AuditLog(db), Settings(instance_id=f"r{i}"))
        for i, db in enumerate(dbs)
    ]  # fmt: skip
    outcomes = await asyncio.gather(*(s.tick() for s in schedulers))
    assert sorted(o for result in outcomes for o in result) == ["sent"]
    assert len(await ReportRepository(dbs[0]).list_reports(workspace_id="ws_default")) == 1
    for db in dbs:
        await db.dispose()
