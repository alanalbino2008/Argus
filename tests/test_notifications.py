"""Outbound notifications: encryption at rest, signing, SSRF guards, escaping, the outbox."""

from __future__ import annotations

import json
import os
import stat
from datetime import datetime, timedelta, timezone

import pytest
from aiohttp import web
from sqlalchemy import select, text

from argus.core.settings import Settings
from argus.notify import render, signing
from argus.notify.channels import ChannelConfigError, validate
from argus.notify.dispatcher import BACKOFF_SECONDS, NotificationDispatcher, backoff
from argus.notify.transport import Result, Transport
from argus.security.crypto import SecretBox, SecretBoxError, secret_box_from_settings
from argus.storage.db import Database, NotificationChannelRow, NotificationDeliveryRow
from argus.storage.migrate import upgrade_database
from argus.storage.monitor_repo import MonitorRepository
from argus.storage.notification_repo import NotificationRepository
from tests.conftest import database_url

KEY = "k" * 40
WS = "ws_default"
SLACK = "https://hooks.slack.com/services/T000/B000/abcdefghijklmnop"


# ---------------------------------------------------------------------------- encryption at rest
def test_secret_box_round_trip_is_bound_to_its_row_and_detects_tampering():
    box = SecretBox(KEY)
    sealed = box.seal({"url": SLACK}, "notification-channel:ws_a:chan_1")
    assert SLACK not in sealed and sealed.startswith(f"v1:{box.key_id}:")
    assert box.open(sealed, "notification-channel:ws_a:chan_1") == {"url": SLACK}
    with pytest.raises(SecretBoxError):  # copied into another workspace's row
        box.open(sealed, "notification-channel:ws_b:chan_1")
    version, kid, blob = sealed.split(":", 2)
    flipped = blob[:-2] + ("A" if blob[-2] != "A" else "B") + blob[-1]
    with pytest.raises(SecretBoxError):
        box.open(f"{version}:{kid}:{flipped}", "notification-channel:ws_a:chan_1")
    with pytest.raises(SecretBoxError):
        SecretBox("x" * 40).open(sealed, "notification-channel:ws_a:chan_1")  # wrong key
    with pytest.raises(SecretBoxError):
        SecretBox(None).seal({"a": 1}, "c")


def test_key_rotation_keeps_old_values_readable():
    old = SecretBox("old-" + KEY)
    sealed = old.seal({"v": 1}, "ctx")
    rotated = SecretBox("new-" + KEY, previous=["old-" + KEY])
    assert rotated.open(sealed, "ctx") == {"v": 1}
    assert rotated.needs_rotation(sealed) and not rotated.needs_rotation(rotated.seal({"v": 1}, "ctx"))


def test_key_file_is_created_owner_only(tmp_path):
    path = tmp_path / "keys" / "argus.key"
    box = secret_box_from_settings(Settings(encryption_key_file=str(path)))
    assert box.available and stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert secret_box_from_settings(Settings(encryption_key_file=str(path))).key_id == box.key_id  # stable


# ---------------------------------------------------------------------------- signatures
def test_webhook_signatures_follow_standard_webhooks():
    secret = signing.new_secret()
    body = b'{"type":"alert.raised"}'
    headers = signing.sign_headers([secret], "dlv_1", body, timestamp=1_700_000_000)
    signing.verify(secret, headers, body, now=1_700_000_010)
    with pytest.raises(signing.SignatureError):
        signing.verify(secret, headers, body + b" ", now=1_700_000_010)  # tampered body
    with pytest.raises(signing.SignatureError):
        signing.verify(secret, headers, body, now=1_700_000_000 + 3600)  # replayed an hour later
    with pytest.raises(signing.SignatureError):
        signing.verify(signing.new_secret(), headers, body, now=1_700_000_010)  # wrong secret
    # During rotation both secrets sign, so receivers using either one keep working.
    new = signing.new_secret()
    both = signing.sign_headers([new, secret], "dlv_2", body, timestamp=1_700_000_000)
    signing.verify(secret, both, body, now=1_700_000_000)
    signing.verify(new, both, body, now=1_700_000_000)


def test_known_answer_signature():
    """Pin the algorithm: id.timestamp.body, HMAC-SHA256, base64, v1 prefix."""
    secret = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"
    headers = signing.sign_headers([secret], "msg_p5jXN8AQM9LWM0D4loKWxJek", b'{"test": 2432232314}', 1614265330)
    assert headers["webhook-signature"] == "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE="


# ---------------------------------------------------------------------------- destinations (SSRF)
@pytest.mark.parametrize(
    "kind, url",
    [
        ("slack", "https://evil.example/services/x"),  # Slack type cannot reach other hosts
        ("slack", "https://hooks.slack.com/other"),
        ("teams", "https://teams.evil.example/hook"),
        ("webhook", "http://receiver.example.com/hook"),  # plain HTTP
        ("webhook", "https://169.254.169.254/latest/meta-data"),  # cloud metadata
        ("webhook", "https://10.0.0.5/hook"),
        ("webhook", "https://localhost/hook"),
        ("webhook", "https://db.internal/hook"),
        ("webhook", "https://[::ffff:127.0.0.1]/hook"),
        ("webhook", "https://user:pass@receiver.example.com/hook"),
    ],
)
def test_unsafe_destinations_are_refused(kind, url):
    with pytest.raises(ChannelConfigError):
        validate(kind, {"url": url}, allow_private=False)


def test_valid_destinations_and_masking():
    public, secret = validate("slack", {"url": SLACK}, allow_private=False)
    assert secret == {"url": SLACK} and public["destination"] == "https://hooks.slack.com/…mnop"
    assert SLACK not in json.dumps(public)
    validate("teams", {"url": "https://prod-01.westeurope.logic.azure.com:443/workflows/abc"}, allow_private=False)
    validate("webhook", {"url": "https://siem.example.com/argus"}, allow_private=False)
    public, secret = validate("email", {"recipients": "SOC@acme.com, soc@acme.com; ir@acme.com"}, allow_private=False)
    assert public == {"recipients": ["ir@acme.com", "soc@acme.com"]} and secret == {}
    for bad in ("not-an-email", "a@b.c\r\nBcc: victim@x.com"):
        with pytest.raises(ChannelConfigError):
            validate("email", {"recipients": [bad]}, allow_private=False)


# ---------------------------------------------------------------------------- escaping untrusted text
def _event(headline="acme.com: 1 new attack path", title="Exposed admin panel on dev.acme.com"):
    alert = {
        "id": "alert_1",
        "workspace_id": WS,
        "severity": "high",
        "target": "acme.com",
        "headline": headline,
        "investigation_id": "inv_2",
        "previous_investigation_id": "inv_1",
        "monitor_id": "mon_1",
        "created_at": "2026-11-14T10:00:00+00:00",
        "summary": {"summary": {"new_paths": 1, "risk_delta": 12}, "new_paths": [{"title": title, "severity": "high"}]},
    }
    return render.alert_event(alert, {"id": WS, "name": "Default"}, "https://argus.example.com")


def test_untrusted_text_cannot_inject_into_messages():
    event = _event(headline="x <!channel> <https://evil.example|click>", title="[pwn](https://evil.example) *b*")
    slack = json.dumps(render.slack(event))
    assert "<!channel>" not in slack and "<https://evil" not in slack and "&lt;!channel&gt;" in slack
    teams = json.dumps(render.teams(event))
    assert "[pwn](https" not in teams and "\\\\[pwn\\\\]" in teams
    mail = render.email(
        _event(headline="a\r\nBcc: victim@example.com", title="<script>x</script>"), "a@b.c", ["s@x.io"]
    )
    assert "\n" not in mail["Subject"] and "Bcc" not in mail
    body = mail.get_body(("html",)).get_content()
    assert "<script>" not in body and "&lt;script&gt;" in body
    assert event["alert"]["url"] == "https://argus.example.com/?ws=ws_default&inv=inv_2"


# ---------------------------------------------------------------------------- repository and dispatcher
@pytest.fixture
async def repo(tmp_path):
    db = Database(database_url(tmp_path, "n.db"))
    await upgrade_database(db)
    yield NotificationRepository(db, SecretBox(KEY))
    await db.dispose()


async def _channel(repo, kind="webhook", url="https://receiver.example.com/hook", min_severity="medium", ws=WS):
    public, secret = validate(kind, {"url": url}, allow_private=True)
    channel, signing_secret = await repo.create_channel(
        workspace_id=ws, name=f"{kind} channel", channel_type=kind, min_severity=min_severity,
        enabled=True, public=public, secret_values=secret, by="tester",
    )  # fmt: skip
    return channel, signing_secret


class FakeTransport(Transport):
    def __init__(self, results):
        super().__init__(Settings(instance_id="test"))
        self.results, self.calls = list(results), []

    async def post(self, url, body, headers):
        self.calls.append((url, body, headers))
        return self.results.pop(0) if self.results else Result(True, status_code=200)


async def test_the_url_is_encrypted_in_the_database(repo):
    channel, secret = await _channel(repo, "slack", SLACK)
    assert secret is None and "url" not in channel and channel["destination"].endswith("mnop")
    async with repo.db.session() as s:
        stored = (await s.execute(text("SELECT config, sealed FROM notification_channels"))).one()
    assert SLACK not in str(stored.config) and SLACK not in stored.sealed and "B000" not in stored.sealed


async def test_alerts_queue_notifications_in_the_same_transaction_by_severity(repo):
    await _channel(repo, min_severity="high")
    await _channel(repo, "slack", SLACK, min_severity="critical")
    monitors = MonitorRepository(repo.db)
    kwargs = {
        "monitor_id": "mon_1", "investigation_id": "inv_2", "previous_investigation_id": "inv_1", "target": "acme.com",
        "headline": "acme.com: change", "summary": {"summary": {}}, "workspace_id": WS,
    }  # fmt: skip
    assert (await monitors.create_alert(severity="high", **kwargs))["notifications_queued"] == 1
    assert (await monitors.create_alert(severity="critical", **kwargs))["notifications_queued"] == 2
    assert (await monitors.create_alert(severity="low", **kwargs))["notifications_queued"] == 0
    other = await _channel(repo, ws="ws_default")
    await repo.update_channel(other[0]["id"], workspace_id=WS, enabled=False)
    assert (await monitors.create_alert(severity="critical", **kwargs))[
        "notifications_queued"
    ] == 2  # disabled: skipped
    assert len(await repo.deliveries(workspace_id=WS)) == 5


async def _queue(repo, channel, event_id="evt_1"):
    event = {**_event(), "id": event_id}
    return await repo.enqueue_test(channel["id"], workspace_id=channel["workspace_id"], event=event)


async def test_delivery_is_signed_and_recorded(repo):
    channel, secret = await _channel(repo)
    delivery = await _queue(repo, channel)
    transport = FakeTransport([])
    dispatcher = NotificationDispatcher(repo, Settings(instance_id="a"), transport)
    assert await dispatcher.tick() == 1
    url, body, headers = transport.calls[0]
    assert url == "https://receiver.example.com/hook" and headers["webhook-id"] == delivery["id"]
    signing.verify(secret, headers, body)
    assert json.loads(body)["alert"]["severity"] == "high"
    [row] = await repo.deliveries(workspace_id=WS)
    assert row["status"] == "delivered" and row["attempts"] == 1
    assert (await repo.get_channel(channel["id"], workspace_id=WS))["health"] == "ok"
    assert await dispatcher.tick() == 0  # nothing is sent twice


async def test_transient_failures_back_off_then_give_up(repo):
    channel, _ = await _channel(repo)
    await _queue(repo, channel)
    settings = Settings(instance_id="a", notify_max_attempts=3)
    transport = FakeTransport([Result(False, True, 503, "busy")] * 3)
    dispatcher = NotificationDispatcher(repo, settings, transport)
    for attempt in (1, 2, 3):
        assert await dispatcher.tick() == 1
        [row] = await repo.deliveries(workspace_id=WS)
        assert row["attempts"] == attempt
        if attempt < 3:
            assert row["status"] == "pending"
            due = datetime.fromisoformat(row["next_attempt_at"]) - datetime.now(timezone.utc)
            assert timedelta(seconds=BACKOFF_SECONDS[attempt - 1] * 0.75) < due  # backed off
            async with repo.db.session() as s, s.begin():  # time passes
                await s.get(NotificationDeliveryRow, row["id"])
                await s.execute(
                    NotificationDeliveryRow.__table__.update().values(next_attempt_at=datetime.now(timezone.utc))
                )
    assert row["status"] == "failed" and row["last_status_code"] == 503
    health = await repo.get_channel(channel["id"], workspace_id=WS)
    assert health["health"] == "failing" and health["consecutive_failures"] == 3
    # An administrator fixes the receiver and retries it.
    await repo.retry(row["id"], workspace_id=WS)
    assert await dispatcher.tick() == 1
    assert (await repo.deliveries(workspace_id=WS))[0]["status"] == "delivered"


async def test_permanent_errors_are_not_retried_and_retry_after_is_honoured(repo):
    channel, _ = await _channel(repo)
    await _queue(repo, channel, "evt_a")
    dispatcher = NotificationDispatcher(
        repo, Settings(instance_id="a"), FakeTransport([Result(False, False, 410, "gone")])
    )
    await dispatcher.tick()
    assert (await repo.deliveries(workspace_id=WS))[0]["status"] == "failed"
    await _queue(repo, channel, "evt_b")
    dispatcher.transport = FakeTransport([Result(False, True, 429, "slow down", retry_after=900)])
    await dispatcher.tick()
    row = next(d for d in await repo.deliveries(workspace_id=WS) if d["event_id"] == "evt_b")
    due = datetime.fromisoformat(row["next_attempt_at"]) - datetime.now(timezone.utc)
    assert timedelta(seconds=880) < due < timedelta(seconds=901)


def test_backoff_schedule_grows_and_is_capped():
    assert 24 <= backoff(1) <= 36 and 96 <= backoff(2) <= 144
    assert backoff(50) <= BACKOFF_SECONDS[-1] * 1.2


async def test_two_replicas_never_send_the_same_delivery(tmp_path):
    url = database_url(tmp_path, "cluster.db")
    a_db, b_db = Database(url), Database(url)
    await upgrade_database(a_db)
    a, b = NotificationRepository(a_db, SecretBox(KEY)), NotificationRepository(b_db, SecretBox(KEY))
    channel, _ = await _channel(a)
    for i in range(10):
        await _queue(a, channel, f"evt_{i}")
    ta, tb = FakeTransport([]), FakeTransport([])
    import asyncio

    await asyncio.gather(
        NotificationDispatcher(a, Settings(instance_id="a"), ta).tick(),
        NotificationDispatcher(b, Settings(instance_id="b"), tb).tick(),
    )
    sent = [h["webhook-id"] for _, _, h in ta.calls + tb.calls]
    assert len(sent) == len(set(sent)) == 10
    await a_db.dispose()
    await b_db.dispose()


async def test_an_expired_lease_is_taken_over_and_the_old_owner_is_fenced(repo):
    channel, _ = await _channel(repo)
    delivery = await _queue(repo, channel)
    [first] = await repo.claim_due("frozen-pod", lease_seconds=-1)  # claims, then "freezes"
    [second] = await repo.claim_due("healthy-pod", lease_seconds=60)  # lease expired: taken over
    assert first["delivery"]["id"] == second["delivery"]["id"] == delivery["id"]
    assert not await repo.record_delivered(delivery["id"], channel["id"], "frozen-pod", 200)  # fenced
    assert await repo.record_delivered(delivery["id"], channel["id"], "healthy-pod", 200)


async def test_disabled_channels_cancel_queued_alerts_but_tests_still_go(repo):
    channel, _ = await _channel(repo)
    monitors = MonitorRepository(repo.db)
    await monitors.create_alert(
        monitor_id=None, investigation_id="i2", previous_investigation_id="i1", target="acme.com", severity="high",
        headline="h", summary={}, workspace_id=WS,
    )  # fmt: skip
    await repo.update_channel(channel["id"], workspace_id=WS, enabled=False)
    probe = render.probe_event({"id": WS, "name": "Default"}, "SIEM", "tester")
    await repo.enqueue_test(channel["id"], workspace_id=WS, event=probe)
    transport = FakeTransport([])
    await NotificationDispatcher(repo, Settings(instance_id="a"), transport).tick()
    statuses = {d["event_type"]: d["status"] for d in await repo.deliveries(workspace_id=WS)}
    assert statuses == {"alert.raised": "cancelled", "notification.test": "delivered"}


async def test_rotation_signs_with_both_secrets_for_a_day(repo):
    channel, old = await _channel(repo)
    new = await repo.rotate_secret(channel["id"], workspace_id=WS)
    await _queue(repo, channel)
    transport = FakeTransport([])
    await NotificationDispatcher(repo, Settings(instance_id="a"), transport).tick()
    _, body, headers = transport.calls[0]
    assert len(headers["webhook-signature"].split()) == 2
    signing.verify(old, headers, body)
    signing.verify(new, headers, body)


async def test_a_changed_destination_keeps_the_signing_secret(repo):
    channel, secret = await _channel(repo)
    public, values = validate("webhook", {"url": "https://other.example.com/x"}, allow_private=False)
    await repo.update_channel(channel["id"], workspace_id=WS, public=public, secret_values=values)
    async with repo.db.session() as s:
        row = await s.get(NotificationChannelRow, channel["id"])
        opened = repo.open_secrets(row)
    assert opened == {"url": "https://other.example.com/x", "signing_secret": secret}


async def test_lost_encryption_key_fails_the_delivery_clearly(repo):
    channel, _ = await _channel(repo)
    await _queue(repo, channel)
    other = NotificationRepository(repo.db, SecretBox("a-completely-different-key-" + KEY))
    await NotificationDispatcher(other, Settings(instance_id="a"), FakeTransport([])).tick()
    [row] = await repo.deliveries(workspace_id=WS)
    assert row["status"] == "failed" and "decrypt" in row["last_error"]


# ---------------------------------------------------------------------------- the real transport
@pytest.fixture
async def receiver():
    """A local HTTP receiver whose answers each test scripts."""
    received: list[tuple[dict[str, str], bytes]] = []
    answers: list[web.Response] = []

    async def hook(request: web.Request) -> web.StreamResponse:
        received.append((dict(request.headers), await request.read()))
        return answers.pop(0) if answers else web.Response(status=204)

    app = web.Application()
    app.router.add_post("/hook", hook)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]  # type: ignore[union-attr]
    yield f"http://127.0.0.1:{port}/hook", received, answers
    await runner.cleanup()


async def test_transport_classifies_answers(receiver):
    url, received, answers = receiver
    transport = Transport(Settings(allow_private_targets=True, notify_timeout_seconds=5))
    try:
        assert (await transport.post(url, b"{}", {})).ok
        answers.append(web.Response(status=503, headers={"Retry-After": "120"}))
        result = await transport.post(url, b"{}", {})
        assert result.retryable and result.retry_after == 120 and result.status_code == 503
        answers.append(web.Response(status=404, text="secret page content"))
        result = await transport.post(url, b"{}", {})
        assert not result.retryable and "revoked" in result.error and "secret page" not in result.error
        answers.append(web.Response(status=302, headers={"Location": "http://169.254.169.254/"}))
        result = await transport.post(url, b"{}", {})
        assert not result.ok and not result.retryable and len(received) == 4  # redirect not followed
        assert "/hook" not in result.error  # only the host is ever reported
    finally:
        await transport.close()


async def test_transport_blocks_private_destinations_at_send_time(receiver):
    url, received, _ = receiver
    transport = Transport(Settings(allow_private_targets=False))
    try:
        result = await transport.post(url, b"{}", {})
    finally:
        await transport.close()
    assert not result.ok and not result.retryable and "not a public" in result.error and received == []


# ---------------------------------------------------------------------------- the API
NOTIFY_ENV = {"monitors_enabled": "false", "notifications_enabled": "false", "encryption_key": KEY}


def test_api_channel_lifecycle_and_end_to_end_delivery(make_client):
    client = make_client(allow_private_targets="true", **NOTIFY_ENV)
    loop_state: dict = {}

    async def start():
        received: list = []

        async def hook(request):
            received.append((dict(request.headers), await request.read()))
            return web.Response(status=200)

        app = web.Application()
        app.router.add_post("/hook", hook)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        loop_state.update(runner=runner, received=received, port=site._server.sockets[0].getsockname()[1])

    client.portal.call(start)
    url = f"http://127.0.0.1:{loop_state['port']}/hook"
    caps = client.get("/api/notifications/capabilities").json()
    assert caps["encryption"] and "webhook" in caps["types"] and not caps["email"]

    created = client.post(
        "/api/notifications/channels",
        json={"name": "SIEM", "type": "webhook", "min_severity": "high", "destination": {"url": url}},
    )
    assert created.status_code == 201, created.text
    channel = created.json()
    secret = channel["signing_secret"]
    listed = client.get("/api/notifications/channels").json()
    assert "signing_secret" not in json.dumps(listed) and url not in json.dumps(listed)

    test = client.post(f"/api/notifications/channels/{channel['id']}/test")
    assert test.status_code == 202
    assert client.portal.call(client.app.state.notifier.tick) == 1
    headers, body = loop_state["received"][0]
    signing.verify(secret, headers, body)
    assert json.loads(body)["type"] == "notification.test"
    [delivery] = client.get("/api/notifications/deliveries").json()
    assert delivery["status"] == "delivered" and delivery["channel_name"] == "SIEM"

    assert (
        client.patch(f"/api/notifications/channels/{channel['id']}", json={"min_severity": "critical"}).json()[
            "min_severity"
        ]
        == "critical"
    )
    rotated = client.post(f"/api/notifications/channels/{channel['id']}/rotate-secret").json()
    assert rotated["signing_secret"] != secret
    actions = {e["action"] for e in client.get("/api/audit?limit=20").json()}
    assert {"notification.channel_create", "notification.channel_test", "notification.secret_rotate"} <= actions
    assert client.delete(f"/api/notifications/channels/{channel['id']}").status_code == 204
    assert client.get("/api/notifications/deliveries").json() == []
    client.portal.call(loop_state["runner"].cleanup)


def test_api_refuses_unsafe_or_unavailable_channels(make_client):
    client = make_client(**NOTIFY_ENV)
    bad = client.post(
        "/api/notifications/channels",
        json={"name": "x", "type": "webhook", "destination": {"url": "https://169.254.169.254/x"}},
    )
    assert bad.status_code == 422 and "public" in bad.json()["detail"]
    email = client.post(
        "/api/notifications/channels", json={"name": "x", "type": "email", "destination": {"recipients": ["a@b.co"]}}
    )
    assert email.status_code == 409 and "SMTP" in email.json()["detail"]


def test_api_without_an_encryption_key_explains_what_to_do(make_client):
    client = make_client(monitors_enabled="false", notifications_enabled="false")
    assert client.get("/api/notifications/capabilities").json()["types"] == []
    response = client.post(
        "/api/notifications/channels", json={"name": "x", "type": "slack", "destination": {"url": SLACK}}
    )
    assert response.status_code == 409 and "ARGUS_ENCRYPTION_KEY" in response.json()["detail"]


def test_channels_are_invisible_to_other_workspaces_and_need_admin(make_client):
    client = make_client(**NOTIFY_ENV)
    client.post("/api/workspaces", json={"name": "Red Team"})
    channel = client.post(
        "/api/notifications/channels", json={"name": "Slack", "type": "slack", "destination": {"url": SLACK}}
    ).json()
    client.post(f"/api/notifications/channels/{channel['id']}/test")
    [delivery] = client.get("/api/notifications/deliveries").json()
    red_key = client.post("/api/keys", json={"name": "r", "role": "admin"}, headers={"X-Argus-Workspace": "red-team"})
    red = {"Authorization": f"Bearer {red_key.json()['key']}"}
    assert client.get("/api/notifications/channels", headers=red).json() == []
    assert client.get("/api/notifications/deliveries", headers=red).json() == []
    cid = channel["id"]
    for method, path in [
        ("PATCH", f"/api/notifications/channels/{cid}"),
        ("DELETE", f"/api/notifications/channels/{cid}"),
        ("POST", f"/api/notifications/channels/{cid}/test"),
        ("POST", f"/api/notifications/channels/{cid}/rotate-secret"),
        ("POST", f"/api/notifications/deliveries/{delivery['id']}/retry"),
    ]:
        kwargs = {"json": {"enabled": False}} if method == "PATCH" else {}
        assert client.request(method, path, headers=red, **kwargs).status_code == 404, path
    analyst = client.post("/api/keys", json={"name": "a", "role": "analyst"}).json()["key"]
    assert client.get("/api/notifications/channels", headers={"Authorization": f"Bearer {analyst}"}).status_code == 403
    assert client.get("/api/notifications/channels").json()[0]["enabled"] is True  # untouched at home


async def test_email_rendering_and_smtp_outcomes(repo, monkeypatch):
    public, _ = validate("email", {"recipients": ["soc@acme.com"]}, allow_private=False)
    channel, _ = await repo.create_channel(
        workspace_id=WS, name="SOC", channel_type="email", min_severity="low", enabled=True, public=public,
        secret_values={}, by="t",
    )  # fmt: skip
    sent = []
    settings = Settings(instance_id="a", smtp_host="smtp.example.com", smtp_from="argus@acme.com")
    transport = Transport(settings)
    monkeypatch.setattr(transport, "_send_mail", lambda message: sent.append(message))
    await _queue(repo, channel)
    await NotificationDispatcher(repo, settings, transport).tick()
    assert sent[0]["To"] == "soc@acme.com" and sent[0]["Subject"] == "[Argus] HIGH drift on acme.com"
    assert (await repo.deliveries(workspace_id=WS))[0]["status"] == "delivered"

    import smtplib

    def refuse(message):
        raise smtplib.SMTPRecipientsRefused({"soc@acme.com": (550, b"no such user")})

    monkeypatch.setattr(transport, "_send_mail", refuse)
    assert not (await transport.send_email(sent[0])).retryable
    monkeypatch.setattr(transport, "_send_mail", lambda m: (_ for _ in ()).throw(ConnectionRefusedError()))
    assert (await transport.send_email(sent[0])).retryable


async def test_old_deliveries_are_purged(repo):
    channel, _ = await _channel(repo)
    await _queue(repo, channel)
    await NotificationDispatcher(repo, Settings(instance_id="a"), FakeTransport([])).tick()
    async with repo.db.session() as s, s.begin():
        await s.execute(
            NotificationDeliveryRow.__table__.update().values(
                created_at=datetime.now(timezone.utc) - timedelta(days=31)
            )
        )
    assert await repo.purge() == 1
    async with repo.db.session() as s:
        assert (await s.scalars(select(NotificationDeliveryRow))).all() == []


def test_the_receiver_example_in_the_docs_verifies_real_signatures():
    import re
    from pathlib import Path

    doc = Path("docs/explained/15-outbound-alerts.md").read_text()
    snippet = re.search(r"```python\n(.*?)```", doc, re.S).group(1)
    namespace: dict = {}
    exec(snippet, namespace)  # noqa: S102 - our own documentation
    secret, body = signing.new_secret(), b'{"type":"alert.raised"}'
    headers = signing.sign_headers([signing.new_secret(), secret], "dlv_1", body)
    namespace["verify"](secret, headers, body)
    with pytest.raises(ValueError, match="signature"):
        namespace["verify"](secret, headers, body + b"x")


@pytest.fixture
async def smtp_server():
    """A minimal SMTP server (no TLS): enough to prove a real email leaves Argus correctly."""
    import asyncio

    messages: list[dict] = []

    async def session(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        envelope: dict = {"rcpt": []}

        async def say(line: str) -> None:
            writer.write(f"{line}\r\n".encode())
            await writer.drain()

        await say("220 test ESMTP")
        while line := (await reader.readline()).decode().rstrip("\r\n"):
            verb = line.split(" ", 1)[0].upper()
            if verb in ("EHLO", "HELO"):
                await say("250 test")
            elif verb == "MAIL":
                envelope["from"] = line
                await say("250 OK")
            elif verb == "RCPT":
                envelope["rcpt"].append(line)
                await say("550 no such user" if "nobody@" in line else "250 OK")
            elif verb == "DATA":
                await say("354 go ahead")
                data = []
                while (chunk := (await reader.readline()).decode()) not in (".\r\n", ""):
                    data.append(chunk)
                messages.append({**envelope, "data": "".join(data)})
                await say("250 queued")
            elif verb == "QUIT":
                await say("221 bye")
                break
            else:
                await say("250 OK")
        writer.close()

    server = await asyncio.start_server(session, "127.0.0.1", 0)
    yield server.sockets[0].getsockname()[1], messages
    server.close()
    await server.wait_closed()


async def test_a_real_email_is_sent_over_smtp(smtp_server):
    port, messages = smtp_server
    settings = Settings(smtp_host="127.0.0.1", smtp_port=port, smtp_security="none", smtp_from="argus@acme.com")
    transport = Transport(settings)
    assert (await transport.send_email(render.email(_event(), settings.smtp_from, ["soc@acme.com"]))).ok
    [mail] = messages
    assert "soc@acme.com" in mail["rcpt"][0] and "Subject: [Argus] HIGH drift on acme.com" in mail["data"]
    assert "Open in Argus: https://argus.example.com/?ws=ws_default&inv=inv_2" in mail["data"]
    refused = await transport.send_email(render.email(_event(), settings.smtp_from, ["nobody@acme.com"]))
    assert not refused.ok and not refused.retryable
    down = Transport(Settings(smtp_host="127.0.0.1", smtp_port=1, smtp_security="none", notify_timeout_seconds=2))
    assert (await down.send_email(render.email(_event(), "a@b.co", ["x@y.co"]))).retryable
