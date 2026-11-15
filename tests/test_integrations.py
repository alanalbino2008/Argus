"""Integrations (Jira, ServiceNow, Splunk, Sentinel), the OpenAPI document, rate limits and the Python client."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest
from aiohttp import web
from sqlalchemy import update

from argus.core.settings import Settings
from argus.notify import integrations, render, signing
from argus.notify.channels import ChannelConfigError, validate
from argus.notify.transport import Reply, Result, Transport
from argus.security.network import BlockedDestinationError, GuardedResolver, assert_allowed_host
from argus.storage.db import NotificationDeliveryRow

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "clients" / "python"))
from argus_client import (
    ArgusClient,
    NotFound,
    PermissionDenied,
    RateLimited,
    WebhookVerificationError,
    verify_webhook,
)

KEY = "k" * 40
TOKEN = "atlassian-token-0123456789"
JIRA = {"url": "https://acme.atlassian.net/", "project_key": "sec", "email": "bot@acme.com", "api_token": TOKEN}
DCR = "dcr-" + "0" * 31 + "a"
GUID = "11111111-2222-3333-4444-555555555555"
SENTINEL = {"dce_url": "https://argus-dce.westeurope-1.ingest.monitor.azure.com", "dcr_id": DCR, "tenant_id": GUID,
            "client_id": GUID, "client_secret": "client-secret-value"}  # fmt: skip


def alert_event(alert_id="alt_1", severity="critical"):
    alert = {"id": alert_id, "severity": severity, "target": "acme.com", "investigation_id": "inv_2",
             "previous_investigation_id": "inv_1", "monitor_id": "mon_1", "created_at": "2026-11-15T10:00:00+00:00",
             "headline": "acme.com: 2 new attack paths {noformat}[click|https://evil.example]",
             "summary": {"summary": {"new_paths": 2}, "new_paths": [{"title": "Exposed admin panel", "severity": "high"}]}}  # fmt: skip
    return render.alert_event(alert, {"id": "ws_default", "name": "Default"}, "https://argus.example")


# ---------------------------------------------------------------------------- validation
def test_integrations_are_validated_and_credentials_kept_secret():
    public, secrets = validate("jira", JIRA, allow_private=False)
    assert public == {"destination": "https://acme.atlassian.net", "host": "acme.atlassian.net", "project_key": "SEC",
                      "issue_type": "Task", "auth": "API token of bot@acme.com", "cloud": True}  # fmt: skip
    assert TOKEN not in json.dumps(public) and secrets["api_token"] == TOKEN and secrets["url"] == public["destination"]

    sn_public, sn_secrets = validate("servicenow", {"url": "https://acme.service-now.com", "username": "argus",
                                                    "password": "s3cret-pass"}, allow_private=False)  # fmt: skip
    assert "password" not in sn_public and sn_secrets["password"] == "s3cret-pass"

    sp_public, _ = validate("splunk", {"url": "https://splunk.acme.com:8088/services/collector/event",
                                       "token": "0000-hec-token", "index": "security"}, allow_private=False)  # fmt: skip
    assert sp_public["destination"] == "https://splunk.acme.com:8088" and sp_public["sourcetype"] == "argus:event"

    se_public, se_secrets = validate("sentinel", SENTINEL, allow_private=False)
    assert se_public["stream"] == "Custom-ArgusEvents_CL" and "client_secret" not in se_public
    assert se_secrets["authority"] == "login.microsoftonline.com"
    gov = validate("sentinel", {**SENTINEL, "dce_url": "https://dce.usgovvirginia-1.ingest.monitor.azure.us"},
                   allow_private=False)[1]  # fmt: skip
    assert gov["authority"] == "login.microsoftonline.us" and gov["scope"] == "https://monitor.azure.us//.default"

    bad = [
        ("jira", {**JIRA, "project_key": "not a key"}, "project key"),
        ("jira", {**JIRA, "api_token": ""}, "Enter the API token"),
        ("jira", {**JIRA, "api_token": "has spaces in it"}, "doesn't look right"),
        ("jira", {**JIRA, "url": "http://acme.atlassian.net"}, "https://"),
        ("jira", {**JIRA, "url": "https://10.0.0.5"}, "public internet"),
        ("jira", {**JIRA, "url": "https://jira.acme.com/?x=1"}, "without ?query"),
        ("servicenow", {"url": "https://acme.service-now.com", "password": "s3cret-pass"}, "user's name"),
        ("splunk", {"url": "https://splunk.acme.com", "token": "0000-hec-token", "index": "Bad Index"}, "index"),
        ("sentinel", {**SENTINEL, "dce_url": "https://evil.example.com"}, "Logs Ingestion URL"),
        ("sentinel", {**SENTINEL, "dcr_id": "dcr-123"}, "immutable ID"),
        ("sentinel", {**SENTINEL, "client_id": "not-a-guid"}, "client) ID"),
        ("sentinel", {**SENTINEL, "stream": "ArgusEvents"}, "stream name"),
    ]
    for kind, config, message in bad:
        with pytest.raises(ChannelConfigError, match=message.replace("?", r"\?").replace(")", r"\)")):
            validate(kind, config, allow_private=False)


def test_credentials_are_kept_on_edit_only_while_the_host_is_unchanged():
    _, saved = validate("jira", JIRA, allow_private=False)
    _, kept = validate("jira", {**JIRA, "api_token": "", "project_key": "OPS"}, allow_private=False, current=saved)
    assert kept["api_token"] == TOKEN and kept["project_key"] == "OPS"
    # An admin who never saw the token must not be able to send it to a server they control.
    with pytest.raises(ChannelConfigError, match="Re-enter the API token"):
        validate("jira", {**JIRA, "url": "https://attacker.example", "api_token": ""}, allow_private=False,
                 current=saved)  # fmt: skip
    with pytest.raises(ChannelConfigError, match="Re-enter"):  # same host, another port: another server
        validate("jira", {**JIRA, "url": "https://acme.atlassian.net:8443", "api_token": ""}, allow_private=False,
                 current=saved)  # fmt: skip


def test_private_integration_hosts_need_the_operator_allowlist():
    splunk = {"url": "https://splunk.corp.internal:8088", "token": "0000-hec-token"}
    with pytest.raises(ChannelConfigError, match="ARGUS_INTEGRATION_ALLOWED_HOSTS"):
        validate("splunk", splunk, allow_private=False)
    assert validate("splunk", splunk, allow_private=False, private_ok=["splunk.corp.internal"])[0]["host"]
    assert validate("webhook", {"url": "https://10.1.2.3/hook"}, allow_private=False, private_ok=["10.1.2.3"])
    # Even an allowlisted host never reaches the cloud metadata service.
    with pytest.raises(BlockedDestinationError):
        assert_allowed_host("169.254.169.254", ["169.254.169.254"])
    with pytest.raises(BlockedDestinationError):
        assert_allowed_host("fd00:ec2::254", ["fd00:ec2::254"])
    assert Settings(integration_allowed_hosts=["Splunk.Corp.Internal."]).integration_allowed_hosts == [
        "splunk.corp.internal"
    ]
    with pytest.raises(ValueError, match="exact host names"):
        Settings(integration_allowed_hosts=["*.corp.internal"])


async def test_the_resolver_lets_allowlisted_hosts_resolve_privately_but_never_to_metadata():
    class Inner:
        def __init__(self, ips):
            self.ips = ips

        async def resolve(self, host, port=0, family=0):
            return [{"host": ip, "port": port} for ip in self.ips]

        async def close(self):
            pass

    private = GuardedResolver(Inner(["10.0.0.7"]), private_ok_hosts=["splunk.corp.internal"])
    assert (await private.resolve("splunk.corp.internal", 443))[0]["host"] == "10.0.0.7"
    with pytest.raises(BlockedDestinationError):
        await private.resolve("other.corp.internal", 443)  # not listed: private answers are dropped
    rebinding = GuardedResolver(Inner(["169.254.169.254"]), private_ok_hosts=["splunk.corp.internal"])
    with pytest.raises(BlockedDestinationError):
        await rebinding.resolve("splunk.corp.internal", 443)


# ---------------------------------------------------------------------------- senders
class ScriptedTransport(Transport):
    """Answers requests from a script of (method, path fragment) -> Reply, recording every call."""

    def __init__(self, script):
        super().__init__(Settings(instance_id="test"))
        self.script, self.calls = list(script), []

    async def request(self, method, url, *, body=None, headers=None, content_type="application/json", read=False):
        self.calls.append({"method": method, "url": url, "body": body, "headers": headers or {}})
        expected_method, fragment, reply = self.script.pop(0)
        assert method == expected_method and fragment in url, (method, url)
        return reply


def jira_secrets(**extra):
    return {**validate("jira", JIRA, allow_private=False)[1], **extra}


async def test_jira_creates_one_issue_per_alert_with_untrusted_text_neutralised():
    transport = ScriptedTransport([
        ("GET", "/rest/api/3/search/jql?", Reply(200, data={"issues": []})),
        ("POST", "/rest/api/2/issue", Reply(201, data={"key": "SEC-12"})),
    ])  # fmt: skip
    result = await integrations.jira(transport, jira_secrets(), alert_event())
    assert result.ok and result.reference == "SEC-12"
    search, create = transport.calls
    assert parse_qs(urlsplit(search["url"]).query)["jql"] == ['labels = "argus-alt_1"']
    assert search["headers"]["Authorization"].startswith("Basic ")
    fields = json.loads(create["body"])["fields"]
    assert fields["project"] == {"key": "SEC"} and fields["labels"] == [
        "argus",
        "argus-alt_1",
        "argus-severity-critical",
    ]
    assert fields["summary"].startswith("[Argus] CRITICAL: acme.com: 2 new attack paths")
    description = fields["description"]
    assert description.startswith("{noformat}\n") and description.count("{noformat}") == 2  # cannot be closed early
    assert "[Open in Argus|https://argus.example/?ws=ws_default&inv=inv_2]" in description


async def test_a_retried_jira_delivery_finds_the_issue_instead_of_duplicating_it():
    transport = ScriptedTransport([("GET", "/search/jql?", Reply(200, data={"issues": [{"key": "SEC-12"}]}))])
    result = await integrations.jira(transport, jira_secrets(), alert_event())
    assert result.ok and result.reference == "SEC-12 (already existed)" and len(transport.calls) == 1


async def test_jira_data_center_uses_v2_search_and_a_bearer_token():
    secrets = validate("jira", {**JIRA, "url": "https://jira.acme.com/jira", "email": ""}, allow_private=False)[1]
    transport = ScriptedTransport([
        ("GET", "https://jira.acme.com/jira/rest/api/2/search?", Reply(200, data={"issues": []})),
        ("POST", "/rest/api/2/issue", Reply(400, data={"errors": {"priority": "Field 'priority' cannot be set"}})),
    ])  # fmt: skip
    result = await integrations.jira(transport, secrets, alert_event())
    assert transport.calls[0]["headers"]["Authorization"] == f"Bearer {TOKEN}"
    assert not result.ok and not result.retryable and "priority: Field 'priority' cannot be set" in result.error


async def test_jira_test_checks_the_project_and_issue_type_without_creating_anything():
    probe = render.probe_event({"id": "ws_default", "name": "Default"}, "Jira", "admin")
    project = Reply(200, data={"issueTypes": [{"name": "Bug"}, {"name": "Task"}]})
    ok = await integrations.jira(
        ScriptedTransport([("GET", "/rest/api/2/project/SEC", project)]), jira_secrets(), probe
    )
    assert ok.ok and ok.reference == "Connected to project SEC"
    wrong = await integrations.jira(ScriptedTransport([("GET", "/project/SEC", project)]),
                                    jira_secrets(issue_type="Incident"), probe)  # fmt: skip
    assert not wrong.ok and "has no issue type “Incident” (it has: Bug, Task)" in wrong.error
    denied = await integrations.jira(ScriptedTransport([("GET", "/project/SEC", Reply(401))]), jira_secrets(), probe)
    assert not denied.ok and "check the email address and API token" in denied.error
    report = {"type": "report.scheduled", "id": "evt_r", "workspace": {}, "report": {}}
    assert "alerts only" in (await integrations.jira(ScriptedTransport([]), jira_secrets(), report)).error


async def test_servicenow_correlates_incidents_and_maps_severity():
    secrets = validate("servicenow", {"url": "https://acme.service-now.com", "username": "argus",
                                      "password": "s3cret-pass", "assignment_group": "SOC"}, allow_private=False)[1]  # fmt: skip
    transport = ScriptedTransport([
        ("GET", "/api/now/table/incident?", Reply(200, data={"result": []})),
        ("POST", "/api/now/table/incident", Reply(201, data={"result": {"number": "INC0010001"}})),
    ])  # fmt: skip
    result = await integrations.servicenow(transport, secrets, alert_event(severity="high"))
    assert result.ok and result.reference == "INC0010001"
    assert parse_qs(urlsplit(transport.calls[0]["url"]).query)["sysparm_query"] == ["correlation_id=argus-alt_1"]
    record = json.loads(transport.calls[1]["body"])
    assert (record["impact"], record["urgency"], record["correlation_id"]) == ("1", "2", "argus-alt_1")
    assert record["assignment_group"] == "SOC" and len(record["short_description"]) <= 160
    again = ScriptedTransport([("GET", "incident?", Reply(200, data={"result": [{"number": "INC0010001"}]}))])
    assert (await integrations.servicenow(again, secrets, alert_event())).reference == "INC0010001 (already existed)"
    refused = ScriptedTransport([("GET", "incident?", Reply(403, data={"error": {"message": "User Not Authorized"}}))])
    assert "User Not Authorized" in (await integrations.servicenow(refused, secrets, alert_event())).error


async def test_splunk_receives_the_event_through_hec():
    secrets = validate("splunk", {"url": "https://splunk.acme.com:8088", "token": "0000-hec-token", "index": "sec"},
                       allow_private=False)[1]  # fmt: skip
    transport = ScriptedTransport([("POST", "https://splunk.acme.com:8088/services/collector/event",
                                    Reply(200, data={"text": "Success", "code": 0}))])  # fmt: skip
    assert (await integrations.splunk(transport, secrets, alert_event())).ok
    call = transport.calls[0]
    payload = json.loads(call["body"])
    assert call["headers"]["Authorization"] == "Splunk 0000-hec-token"
    assert (
        payload["index"] == "sec"
        and payload["sourcetype"] == "argus:event"
        and payload["event"]["type"] == "alert.raised"
    )
    assert payload["time"] == 1794736800.0
    bad = ScriptedTransport([("POST", "/collector/event", Reply(400, data={"text": "Incorrect index", "code": 7}))])
    result = await integrations.splunk(bad, secrets, alert_event())
    assert not result.retryable and "Incorrect index (code 7)" in result.error
    busy = ScriptedTransport(
        [("POST", "/collector/event", Reply(503, retry_after=5, data={"text": "busy", "code": 9}))]
    )
    result = await integrations.splunk(busy, secrets, alert_event())
    assert result.retryable and result.retry_after == 5


async def test_sentinel_signs_in_once_and_sends_flat_records():
    secrets = validate("sentinel", SENTINEL, allow_private=False)[1]
    token = Reply(200, data={"access_token": "aad-token", "expires_in": 3599})
    transport = ScriptedTransport([
        ("POST", f"https://login.microsoftonline.com/{GUID}/oauth2/v2.0/token", token),
        ("POST", f"/dataCollectionRules/{DCR}/streams/Custom-ArgusEvents_CL?api-version=2023-01-01", Reply(204)),
        ("POST", "/dataCollectionRules/", Reply(204)),  # the cached token is reused
    ])  # fmt: skip
    assert (await integrations.sentinel(transport, secrets, alert_event())).ok
    assert (await integrations.sentinel(transport, secrets, alert_event("alt_2"))).ok
    sign_in, ingest, _ = transport.calls
    assert parse_qs(sign_in["body"].decode())["scope"] == ["https://monitor.azure.com//.default"]
    assert ingest["headers"]["Authorization"] == "Bearer aad-token"
    [record] = json.loads(ingest["body"])
    assert {k: record[k] for k in ("EventType", "Severity", "Target", "WorkspaceName")} == {
        "EventType": "alert.raised", "Severity": "critical", "Target": "acme.com", "WorkspaceName": "Default"}  # fmt: skip
    assert record["TimeGenerated"] == "2026-11-15T10:00:00+00:00" and record["Details"]["alert"]["id"] == "alt_1"

    expired = ScriptedTransport([("POST", "/dataCollectionRules/", Reply(401))])
    expired.tokens = transport.tokens
    result = await integrations.sentinel(expired, secrets, alert_event())
    assert result.retryable and not expired.tokens  # signs in again on the retry
    failing = ScriptedTransport([("POST", "/oauth2/v2.0/token", Reply(401, data={
        "error": "invalid_client", "error_description": "AADSTS7000215: Invalid client secret provided. Trace ID: x"}))])  # fmt: skip
    result = await integrations.sentinel(failing, secrets, alert_event())
    assert (
        not result.ok
        and "Microsoft sign-in failed" in result.error
        and "invalid_client (AADSTS7000215)" in result.error
    )
    assert "Trace ID" not in result.error
    forbidden = ScriptedTransport([("POST", "/token", token), ("POST", "/dataCollectionRules/", Reply(403))])
    assert "Monitoring Metrics Publisher" in (await integrations.sentinel(forbidden, secrets, alert_event())).error


async def test_transport_failures_pass_through_unchanged():
    timeout = Result(False, True, error="Timed out after 10s waiting for acme.atlassian.net")
    result = await integrations.jira(ScriptedTransport([("GET", "/search", timeout)]), jira_secrets(), alert_event())
    assert result is timeout


# ---------------------------------------------------------------------------- the API, end to end
ENV = {"monitors_enabled": "false", "notifications_enabled": "false", "encryption_key": KEY,
       "report_schedules_enabled": "false"}  # fmt: skip


def fake_jira(client, state):
    """A tiny Jira on localhost that remembers issues by label."""

    async def start():
        issues: dict[str, str] = {}

        async def search(request):
            label = request.query["jql"].split('"')[1]
            state["auth"] = request.headers.get("Authorization")
            return web.json_response({"issues": [{"key": issues[label]}] if label in issues else []})

        async def create(request):
            fields = (await request.json())["fields"]
            key = f"{fields['project']['key']}-{len(issues) + 1}"
            issues[fields["labels"][1]] = key
            state["created"] = state.get("created", 0) + 1
            if state.get("lose_response"):  # created, but the answer never arrives
                return web.json_response({"errorMessages": ["gateway timeout"]}, status=504)
            return web.json_response({"key": key}, status=201)

        app = web.Application()
        app.router.add_get("/rest/api/2/search", search)
        app.router.add_post("/rest/api/2/issue", create)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        state.update(runner=runner, port=site._server.sockets[0].getsockname()[1])

    client.portal.call(start)


def test_jira_channel_end_to_end_with_retries_never_duplicating(make_client):
    client = make_client(allow_private_targets="true", **ENV)
    state: dict = {}
    fake_jira(client, state)
    caps = client.get("/api/notifications/capabilities").json()
    assert {"jira", "servicenow", "splunk", "sentinel"} <= set(caps["types"]) and caps["ticketing"] == [
        "jira",
        "servicenow",
    ]

    destination = {"url": f"http://127.0.0.1:{state['port']}", "project_key": "SEC", "email": "bot@acme.com",
                   "api_token": TOKEN}  # fmt: skip
    created = client.post("/api/notifications/channels",
                          json={"name": "SOC Jira", "type": "jira", "destination": destination})  # fmt: skip
    assert created.status_code == 201, created.text
    channel = created.json()
    assert channel["integration"] and channel["project_key"] == "SEC" and "signing_secret" not in channel
    assert TOKEN not in json.dumps(client.get("/api/notifications/channels").json())

    async def queue_alert():
        await client.app.state.monitors.create_alert(
            monitor_id="mon_1", investigation_id="inv_2", previous_investigation_id="inv_1", target="acme.com",
            severity="critical", headline="acme.com: new attack path", summary={"summary": {}},
            workspace_id="ws_default")  # fmt: skip

    state["lose_response"] = True
    client.portal.call(queue_alert)
    assert client.portal.call(client.app.state.notifier.tick) == 1
    [delivery] = client.get("/api/notifications/deliveries").json()
    assert delivery["status"] == "pending" and delivery["attempts"] == 1 and "HTTP 504" in delivery["last_error"]

    async def due_now():
        async with client.app.state.db.session() as s, s.begin():
            await s.execute(update(NotificationDeliveryRow).values(
                next_attempt_at=datetime.now(timezone.utc) - timedelta(seconds=1)))  # fmt: skip

    client.portal.call(due_now)
    assert client.portal.call(client.app.state.notifier.tick) == 1  # the retry finds the issue, creates nothing
    [delivery] = client.get("/api/notifications/deliveries").json()
    assert delivery["status"] == "delivered" and delivery["reference"] == "SEC-1 (already existed)"
    assert state["created"] == 1

    # Edit without re-typing the token: kept (same host). Point it elsewhere: must re-enter it.
    patch = client.patch(f"/api/notifications/channels/{channel['id']}",
                         json={"destination": {**destination, "api_token": "", "project_key": "OPS"}})  # fmt: skip
    assert patch.status_code == 200 and patch.json()["project_key"] == "OPS"
    moved = client.patch(f"/api/notifications/channels/{channel['id']}",
                         json={"destination": {**destination, "url": "http://127.0.0.2:1", "api_token": ""}})  # fmt: skip
    assert moved.status_code == 422 and "Re-enter the API token" in moved.json()["detail"]

    # Ticketing channels cannot receive scheduled reports.
    client.post("/api/demo")
    inv = client.get("/api/investigations").json()[0]
    schedule = client.post("/api/reports/schedules", json={
        "name": "Weekly", "target": inv["target"], "frequency": "weekly", "weekday": 0, "hour": 8,
        "channel_ids": [channel["id"]]})  # fmt: skip
    assert schedule.status_code == 422 and "creates tickets" in schedule.json()["detail"]
    client.portal.call(state["runner"].cleanup)


def test_private_integration_hosts_are_refused_by_the_api_unless_allowlisted(make_client):
    body = {"name": "Splunk", "type": "splunk",
            "destination": {"url": "https://splunk.corp.internal:8088", "token": "0000-hec-token"}}  # fmt: skip
    client = make_client(**ENV)
    refused = client.post("/api/notifications/channels", json=body)
    assert refused.status_code == 422 and "ARGUS_INTEGRATION_ALLOWED_HOSTS" in refused.json()["detail"]
    allowed = make_client(integration_allowed_hosts='["splunk.corp.internal"]', **ENV)
    assert allowed.post("/api/notifications/channels", json=body).status_code == 201
    assert allowed.get("/api/notifications/capabilities").json()["private_hosts_allowed"] == 1


# ---------------------------------------------------------------------------- OpenAPI and rate limits
def test_the_openapi_document_describes_authentication_and_workspaces(client):
    doc = client.get("/openapi.json").json()
    assert doc["info"]["title"] == "Argus API" and set(doc["components"]["securitySchemes"]) == {
        "ApiKeyBearer", "ApiKeyHeader"}  # fmt: skip
    ops = {(path, method): op for path, item in doc["paths"].items() for method, op in item.items()}
    assert len({op["operationId"] for op in ops.values()}) == len(ops)  # stable, unique names for generators
    assert all(op.get("tags") for op in ops.values())
    public = {k for k, op in ops.items() if op["security"] == []}
    assert {("/api/health", "get"), ("/api/live", "get"), ("/api/reports/verify/{sha256}", "get")} <= public
    assert ("/api/scan", "post") not in public
    scan = ops[("/api/scan", "post")]
    assert scan["operationId"] == "start_scan" and scan["x-argus-role"] == "analyst"
    assert "X-Argus-Workspace" in [p["name"] for p in scan["parameters"]] and "403" in scan["responses"]
    assert ops[("/api/notifications/channels", "post")]["x-argus-role"] == "admin"
    assert "X-Argus-Workspace" not in [p["name"] for p in ops[("/api/me", "get")].get("parameters", [])]
    assert "text/html" not in json.dumps(doc["paths"].get("/", {}))


def test_api_keys_are_rate_limited_with_standard_headers(make_client):
    client = make_client(api_requests_per_minute="3", monitors_enabled="false")
    first = client.get("/api/me")
    assert first.headers["RateLimit-Limit"] == "3" and first.headers["RateLimit-Remaining"] == "2"
    client.get("/api/me")
    client.get("/api/me")
    limited = client.get("/api/me")
    assert limited.status_code == 429 and int(limited.headers["Retry-After"]) >= 1
    assert limited.headers["RateLimit-Remaining"] == "0" and "3 requests per minute" in limited.json()["detail"]
    assert client.get("/api/health").status_code == 200  # public endpoints are not counted
    assert "RateLimit-Limit" not in client.get("/api/live").headers


# ---------------------------------------------------------------------------- the Python client
def test_the_python_client_against_the_real_api(make_client):
    client = make_client(monitors_enabled="false")
    argus = ArgusClient(api_key=None, http=client)  # the TestClient already carries the admin key
    assert argus.me()["role"] == "admin"
    client.post("/api/demo")
    inv = argus.investigations()[0]
    assert argus.wait(inv["id"], timeout=1)["status"] == "completed"
    assert argus.rating(inv["id"])["grade"] in "ABCDF"
    assert argus.graph(inv["id"])["elements"] and argus.stix(inv["id"])["type"] == "bundle"
    assert argus.report_pdf(inv["id"], tlp="GREEN").startswith(b"%PDF")
    supplier = argus.add_supplier("Acme", inv["target"], basis="Contracted payroll provider", tier="critical")
    assert supplier["status"] == "below_minimum" and argus.suppliers()["summary"]["total"] == 1
    with pytest.raises(NotFound) as missing:
        argus.investigation("inv_doesnotexist")
    assert missing.value.status_code == 404 and "not found" in str(missing.value.detail).lower()
    client.post("/api/workspaces", json={"name": "Red Team"})
    assert argus.in_workspace("red-team").investigations() == []

    viewer_key = client.post("/api/keys", json={"name": "ro", "role": "viewer"}).json()["key"]
    from fastapi.testclient import TestClient

    with TestClient(client.app) as anonymous:
        viewer = ArgusClient(api_key=viewer_key, http=anonymous)
        assert viewer.ratings() is not None
        with pytest.raises(PermissionDenied):
            viewer.scan("example.com", purpose="should not be allowed")


def test_the_client_waits_out_rate_limits_then_gives_up(make_client):
    client = make_client(api_requests_per_minute="1", monitors_enabled="false")
    del client.headers["Authorization"]
    sleeps: list[float] = []
    argus = ArgusClient(api_key="argus_test-admin-key-0123456789abcdefghijklmnopqrstu", http=client, max_retries=2)
    import argus_client

    original = argus_client.time.sleep
    argus_client.time.sleep = sleeps.append
    try:
        argus.me()
        with pytest.raises(RateLimited) as limited:
            argus.me()
    finally:
        argus_client.time.sleep = original
    assert len(sleeps) == 2 and all(1 <= s <= 61 for s in sleeps) and limited.value.retry_after >= 1


def test_webhook_verification_helper_matches_the_server():
    secret = signing.new_secret()
    body = b'{"type":"alert.raised"}'
    headers = signing.sign_headers([secret], "dlv_1", body)
    verify_webhook(secret, headers, body)
    with pytest.raises(WebhookVerificationError):
        verify_webhook(secret, headers, body + b"x")
    with pytest.raises(WebhookVerificationError):
        verify_webhook(secret, {**headers, "webhook-timestamp": "1"}, body)
