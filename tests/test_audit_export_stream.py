"""Phase 92: audit log exports checkable offline, and the audit log streamed to a SIEM from a checkpoint."""

from __future__ import annotations

import json

import pytest

from argus.cli.console import verify_audit_cli
from argus.notify.transport import Result, Transport
from argus.security.audit_export import VerificationError, verify


class FakeTransport(Transport):
    def __init__(self, settings, results=()):
        super().__init__(settings)
        self.results, self.calls = list(results), []

    async def post(self, url, body, headers):
        self.calls.append((url, json.loads(body), headers))
        return self.results.pop(0) if self.results else Result(True, status_code=200)


@pytest.fixture
def c(make_client):
    client = make_client(encryption_key="k" * 40, notifications_enabled="false", monitors_enabled="false")
    for name in ("-SUM A1", "siem reader"):  # a few audit entries, one that looks like a spreadsheet formula
        client.post("/api/keys", json={"name": name, "role": "viewer"})
    return client


def _export(c, **params):
    r = c.get("/api/audit/export", params=params)
    assert r.status_code == 200, r.text
    return r


def test_a_platform_export_verifies_and_tampering_is_caught(c, tmp_path):
    data = _export(c, scope="all").content
    result = verify(data)
    assert result["valid"] and result["complete_chain"] and result["entries"] >= 3 and result["first_id"] == 1
    assert result["exported_by"] == "bootstrap-admin" and result["head"]["id"] >= result["last_id"]

    lines = data.splitlines(keepends=True)
    entry = json.loads(lines[1])
    entry["actor_name"] = "someone else"
    forged = lines[0] + json.dumps(entry).encode() + b"\n" + b"".join(lines[2:])
    with pytest.raises(VerificationError, match="do not match the manifest"):
        verify(forged)
    with pytest.raises(VerificationError, match="do not match the manifest"):
        verify(lines[0] + b"".join(lines[2:]))  # an entry removed
    manifest = json.loads(lines[-1])
    manifest["manifest"]["exported_by"] = "auditor"
    with pytest.raises(VerificationError, match="signature"):
        verify(b"".join(lines[:-1]) + json.dumps(manifest).encode() + b"\n")
    with pytest.raises(VerificationError, match="different key"):
        verify(data, trusted_key="AAAA")
    key = c.get("/api/report-signing-key").json()["public_key"]
    assert verify(data, trusted_key=key)["trusted_key_checked"]

    good, bad = tmp_path / "audit.jsonl", tmp_path / "forged.jsonl"
    good.write_bytes(data)
    bad.write_bytes(forged)
    assert verify_audit_cli(str(good), key) == 0 and verify_audit_cli(str(bad), None) == 1


def test_filtered_exports_report_gaps_and_csv_is_safe(c):
    data = _export(c, action="key.create").content
    result = verify(data)
    assert result["entries"] >= 2 and result["filters"]["action"] == "key.create"
    assert all(json.loads(line)["action"] == "key.create" for line in data.splitlines()[:-1])
    assert _export(c, since="2999-01-01").content.count(b"\n") == 1  # just the manifest
    assert c.get("/api/audit/export", params={"since": "yesterday"}).status_code == 422

    formula = c.post("/api/keys", json={"name": "-SUM A1", "role": "analyst"}).json()["key"]
    c.post(
        "/api/cases",
        json={"title": "x", "purpose": "CSV injection check case", "confirmed": True},
        headers={"Authorization": f"Bearer {formula}"},
    )  # its name now starts the actor_name cell
    sheet = _export(c, format="csv").text
    assert sheet.splitlines()[0].startswith("id,ts,workspace_id,actor_id")
    assert "'-SUM A1" in sheet and ",-SUM A1" not in sheet  # a formula is neutralised
    assert "audit.export" in {e["action"] for e in c.get("/api/audit?limit=200").json()}


def _stream(c, start="beginning"):
    channel = c.post("/api/notifications/channels", json={
        "name": "SIEM", "type": "webhook", "destination": {"url": "https://siem.example.com/argus"}}).json()  # fmt: skip
    created = c.post("/api/audit/streams", json={"channel_id": channel["id"], "start": start})
    assert created.status_code == 201, created.text
    return created.json()


def test_the_stream_delivers_in_order_and_resumes_from_its_checkpoint(c):
    _stream(c)
    streams = c.app.state.audit_streams
    c.app.state.notifier.transport = fake = FakeTransport(c.app.state.settings)
    sent = c.portal.call(streams.tick)
    assert sent >= 3 and len(fake.calls) == sent
    ids = [body["audit"]["id"] for _, body, _ in fake.calls]
    assert ids == sorted(ids) and all(body["type"] == "audit.event" for _, body, _ in fake.calls)
    first = fake.calls[0][1]
    assert (
        first["id"] == f"audit-{ids[0]}"
        and len(first["audit"]["hash"]) == 64
        and "webhook-signature" in fake.calls[0][2]
    )
    (listed,) = c.get("/api/audit/streams").json()
    assert listed["last_id"] == ids[-1] and listed["sent"] == sent and listed["last_error"] is None

    # The SIEM goes down: nothing advances, nothing is lost.
    c.post("/api/keys", json={"name": "during outage", "role": "viewer"})
    fake.results = [Result(False, True, 503, "SIEM is down")]
    assert c.portal.call(streams.tick) == 0
    (listed,) = c.get("/api/audit/streams").json()
    assert listed["last_id"] == ids[-1] and "SIEM is down" in listed["last_error"] and listed["failing_since"]
    assert listed["behind"] >= 1
    # Back up: it catches up from the checkpoint.
    assert c.portal.call(streams.tick) >= 1
    actions = [body["audit"]["action"] for _, body, _ in fake.calls[sent + 1 :]]
    assert "key.create" in actions
    (listed,) = c.get("/api/audit/streams").json()
    assert listed["last_error"] is None and listed["failing_since"] is None


def test_streams_from_now_destination_types_and_approval_to_stop(c):
    stream = _stream(c, start="now")
    c.app.state.notifier.transport = fake = FakeTransport(c.app.state.settings)
    assert c.portal.call(c.app.state.audit_streams.tick) <= 2  # only what came after it was created
    assert all(body["audit"]["id"] > 3 for _, body, _ in fake.calls)
    slack = c.post("/api/notifications/channels", json={
        "name": "chat", "type": "slack", "destination": {"url": "https://hooks.slack.com/services/T0/B0/x"}}).json()  # fmt: skip
    assert c.post("/api/audit/streams", json={"channel_id": slack["id"]}).status_code == 422
    assert c.post("/api/audit/streams", json={"channel_id": "nope"}).status_code == 404

    bob = c.post("/api/keys", json={"name": "bob", "role": "admin"}).json()["key"]
    c.put("/api/approval-policy", json={"actions": ["audit.stream_stop"]})
    asked = c.delete(f"/api/audit/streams/{stream['id']}")
    assert asked.status_code == 202  # stopping the SIEM feed needs someone else's agreement
    c.post(
        f"/api/approvals/{asked.json()['approval']['id']}/approve", json={}, headers={"Authorization": f"Bearer {bob}"}
    )
    done = c.delete(f"/api/audit/streams/{stream['id']}", headers={"X-Argus-Approval": asked.json()["approval"]["id"]})
    assert done.status_code == 204 and c.get("/api/audit/streams").json() == []
