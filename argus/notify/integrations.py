"""Integrations: alerts become Jira issues or ServiceNow incidents; events flow into Splunk or Sentinel.

Each sender returns a :class:`~argus.notify.transport.Result`, so integrations get the outbox's
retries, backoff and delivery log for free.

**Exactly one ticket per alert.** Deliveries are at-least-once: if Jira creates the issue but
the response is lost (timeout), the delivery is retried. So before creating, the sender looks
for a ticket already carrying the alert's correlation key - a Jira label ``argus-<alert id>``
or a ServiceNow ``correlation_id`` - and reports that one instead of creating a duplicate.

**Untrusted text.** Alert text contains names found on the internet. Jira descriptions put it
in a ``{noformat}`` block (no links, mentions or macros can be injected); ServiceNow fields are
plain text; SIEMs receive JSON. Error messages quote only short, specific fields of the
receiver's error response, never the response itself.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote, urlencode

from argus.notify.channels import SPLUNK_PATH
from argus.notify.transport import Reply, Result, Transport, classify

SN_PRIORITY = {"critical": ("1", "1"), "high": ("1", "2"), "medium": ("2", "2"), "low": ("3", "3")}  # impact, urgency
TOKEN_MARGIN = 300.0


def _clean(text: Any, limit: int) -> str:
    return re.sub(r"\s+", " ", str(text)).strip()[:limit]


def correlation_key(event: dict[str, Any]) -> str:
    return "argus-" + re.sub(r"[^A-Za-z0-9_-]", "", str(event["alert"]["id"]))[:60]


def ticket(event: dict[str, Any]) -> dict[str, Any]:
    """The summary and plain-text body of a ticket for an ``alert.raised`` event."""
    alert = event["alert"]
    counts = alert.get("counts") or {}
    lines = [alert["headline"], "", f"Severity: {alert['severity']}", f"Target: {alert['target']}",
             f"Workspace: {event['workspace'].get('name')}"]  # fmt: skip
    if counts:
        lines.append("Changes: " + ", ".join(f"{k.replace('_', ' ')} {v}" for k, v in counts.items() if v is not None))
    if alert.get("new_paths"):
        lines += ["", "New attack paths:", *(f"- {p['title']} ({p['severity']})" for p in alert["new_paths"])]
    lines += ["", f"Argus alert {alert['id']} · investigation {alert['investigation_id']}"]
    return {
        "summary": _clean(f"[Argus] {alert['severity'].upper()}: {alert['headline']}", 240),
        "text": "\n".join(str(x) for x in lines)[:20000],
        "url": alert.get("url"),
    }


def _error_detail(data: Any) -> str:
    """A short, specific message from a receiver's JSON error (never the raw body)."""
    if not isinstance(data, dict):
        return ""
    parts: list[str] = []
    if isinstance(data.get("errorMessages"), list):  # Jira
        parts += [str(m) for m in data["errorMessages"][:2]]
    if isinstance(data.get("errors"), dict):
        parts += [f"{k}: {v}" for k, v in list(data["errors"].items())[:3]]
    error = data.get("error")
    if isinstance(error, dict):  # ServiceNow
        parts.append(str(error.get("message") or ""))
    elif isinstance(error, str):  # OAuth
        description = str(data.get("error_description") or "")
        code = re.match(r"(AADSTS\d+)", description)
        parts.append(f"{error}{f' ({code.group(1)})' if code else ''}")
    if "text" in data and "code" in data:  # Splunk HEC
        parts.append(f"{data['text']} (code {data['code']})")
    return _clean("; ".join(p for p in parts if p), 200)


def _outcome(host: str, reply: Reply | Result, hints: dict[int, str] | None = None) -> Result:
    if isinstance(reply, Result):
        return reply
    detail = _error_detail(reply.data) if not 200 <= reply.status < 300 else ""
    if not detail and hints:
        detail = hints.get(reply.status, "")
    return classify(host, reply, detail)


def _basic(user: str, password: str) -> str:
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


def _body(value: Any) -> bytes:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()


# ---------------------------------------------------------------------------- Jira
def _jira_text(text: str) -> str:
    # Inside {noformat} nothing is interpreted; only the closing tag itself must not appear.
    return re.sub(r"\{noformat\}", "{ noformat }", text, flags=re.IGNORECASE)


async def jira(transport: Transport, secrets: dict[str, Any], event: dict[str, Any]) -> Result:
    base, host = secrets["url"], secrets["host"]
    auth = _basic(secrets["email"], secrets["api_token"]) if secrets.get("email") else f"Bearer {secrets['api_token']}"
    headers = {"Authorization": auth, "Accept": "application/json"}
    hints = {401: "check the email address and API token", 403: "the account cannot use this project",
             404: f"project {secrets['project_key']} was not found or is not visible to this account"}  # fmt: skip

    if event["type"] == "notification.test":
        reply = await transport.request(
            "GET", f"{base}/rest/api/2/project/{quote(secrets['project_key'])}", headers=headers, read=True
        )
        result = _outcome(host, reply, hints)
        if not result.ok or not isinstance(reply, Reply):
            return result
        names = [str(t.get("name")) for t in (reply.data or {}).get("issueTypes", []) if isinstance(t, dict)]
        if names and secrets["issue_type"] not in names:
            return Result(False, False, reply.status, f"Project {secrets['project_key']} has no issue type "
                          f"“{secrets['issue_type']}” (it has: {', '.join(names[:8])})")  # fmt: skip
        return Result(True, status_code=reply.status, reference=f"Connected to project {secrets['project_key']}")
    if event["type"] != "alert.raised":
        return Result(False, False, error="Jira receives alerts only, not scheduled reports")

    key = correlation_key(event)
    jql = urlencode({"jql": f'labels = "{key}"', "maxResults": 1, "fields": "key"})
    search = f"{base}/rest/api/3/search/jql?{jql}" if secrets.get("cloud") else f"{base}/rest/api/2/search?{jql}"
    found = await transport.request("GET", search, headers=headers, read=True)
    result = _outcome(host, found, hints)
    if not result.ok or not isinstance(found, Reply):
        return result
    issues = (found.data or {}).get("issues") or []
    if issues and isinstance(issues[0], dict) and issues[0].get("key"):
        return Result(True, status_code=found.status, reference=f"{issues[0]['key']} (already existed)")

    t = ticket(event)
    description = f"{{noformat}}\n{_jira_text(t['text'])}\n{{noformat}}"
    if t["url"]:
        description += f"\n[Open in Argus|{t['url']}]"
    fields = {
        "project": {"key": secrets["project_key"]},
        "issuetype": {"name": secrets["issue_type"]},
        "summary": t["summary"],
        "description": description,
        "labels": ["argus", key, f"argus-severity-{event['alert']['severity']}"],
    }
    created = await transport.request(
        "POST", f"{base}/rest/api/2/issue", body=_body({"fields": fields}), headers=headers, read=True
    )
    result = _outcome(host, created, hints)
    if result.ok and isinstance(created, Reply):
        return Result(True, status_code=created.status, reference=str((created.data or {}).get("key") or "") or None)
    return result


# ---------------------------------------------------------------------------- ServiceNow
async def servicenow(transport: Transport, secrets: dict[str, Any], event: dict[str, Any]) -> Result:
    base, host = secrets["url"], secrets["host"]
    headers = {"Authorization": _basic(secrets["username"], secrets["password"]), "Accept": "application/json"}
    hints = {401: "check the user name and password",
             403: "the user needs the itil role (or REST access to the incident table)"}  # fmt: skip
    table = f"{base}/api/now/table/incident"

    if event["type"] == "notification.test":
        reply = await transport.request("GET", f"{table}?sysparm_limit=1&sysparm_fields=sys_id", headers=headers)
        result = _outcome(host, reply, hints)
        return Result(True, status_code=result.status_code, reference="Connected to the incident table") if (
            result.ok) else result  # fmt: skip
    if event["type"] != "alert.raised":
        return Result(False, False, error="ServiceNow receives alerts only, not scheduled reports")

    key = correlation_key(event)
    query = urlencode({"sysparm_query": f"correlation_id={key}", "sysparm_limit": 1, "sysparm_fields": "number"})
    found = await transport.request("GET", f"{table}?{query}", headers=headers, read=True)
    result = _outcome(host, found, hints)
    if not result.ok or not isinstance(found, Reply):
        return result
    existing = (found.data or {}).get("result") or []
    if existing and isinstance(existing[0], dict) and existing[0].get("number"):
        return Result(True, status_code=found.status, reference=f"{existing[0]['number']} (already existed)")

    t = ticket(event)
    impact, urgency = SN_PRIORITY.get(event["alert"]["severity"], ("2", "2"))
    record = {
        "short_description": t["summary"][:160],
        "description": t["text"] + (f"\n\nOpen in Argus: {t['url']}" if t["url"] else ""),
        "impact": impact,
        "urgency": urgency,
        "correlation_id": key,
        "correlation_display": "Argus",
    }
    if secrets.get("assignment_group"):
        record["assignment_group"] = secrets["assignment_group"]
    created = await transport.request("POST", table, body=_body(record), headers=headers, read=True)
    result = _outcome(host, created, hints)
    if result.ok and isinstance(created, Reply):
        number = ((created.data or {}).get("result") or {}).get("number")
        return Result(True, status_code=created.status, reference=str(number) if number else None)
    return result


# ---------------------------------------------------------------------------- SIEM records
def _epoch(iso: str | None) -> float:
    try:
        return datetime.fromisoformat(str(iso)).timestamp()
    except ValueError:
        return time.time()


def siem_record(event: dict[str, Any]) -> dict[str, Any]:
    """A flat record (for Sentinel tables and Splunk searches); the full event goes in ``Details``."""
    alert, report = event.get("alert") or {}, event.get("report") or {}
    return {
        "TimeGenerated": event.get("occurred_at") or datetime.now(timezone.utc).isoformat(),
        "EventType": event["type"],
        "EventId": event["id"],
        "Severity": alert.get("severity") or "",
        "Target": alert.get("target") or report.get("target") or "",
        "Headline": alert.get("headline") or (f"Report {report.get('id')}" if report else event.get("message", "")),
        "WorkspaceId": event["workspace"].get("id") or "",
        "WorkspaceName": event["workspace"].get("name") or "",
        "Url": alert.get("url") or report.get("url") or "",
        "Details": event,
    }


async def splunk(transport: Transport, secrets: dict[str, Any], event: dict[str, Any]) -> Result:
    payload: dict[str, Any] = {
        "time": round(_epoch(event.get("occurred_at")), 3),
        "host": "argus",
        "source": "argus",
        "sourcetype": secrets.get("sourcetype") or "argus:event",
        "event": event,
    }
    if secrets.get("index"):
        payload["index"] = secrets["index"]
    reply = await transport.request(
        "POST", f"{secrets['url']}{SPLUNK_PATH}", body=_body(payload),
        headers={"Authorization": f"Splunk {secrets['token']}"}, read=True,
    )  # fmt: skip
    return _outcome(
        secrets["host"], reply, {401: "the HEC token is missing", 403: "the HEC token is invalid or disabled"}
    )


async def _azure_token(transport: Transport, secrets: dict[str, Any]) -> str | Result:
    fingerprint = hashlib.sha256(
        "|".join([secrets["authority"], secrets["tenant_id"], secrets["client_id"], secrets["client_secret"]]).encode()
    ).hexdigest()
    cached = transport.tokens.get(fingerprint)
    if cached and cached[1] > time.monotonic():
        return cached[0]
    form = urlencode({"client_id": secrets["client_id"], "client_secret": secrets["client_secret"],
                      "grant_type": "client_credentials", "scope": secrets["scope"]}).encode()  # fmt: skip
    reply = await transport.request(
        "POST", f"https://{secrets['authority']}/{quote(secrets['tenant_id'])}/oauth2/v2.0/token",
        body=form, content_type="application/x-www-form-urlencoded", read=True,
    )  # fmt: skip
    result = _outcome(secrets["authority"], reply, {401: "check the client ID and secret"})
    if not result.ok or not isinstance(reply, Reply):
        return Result(False, result.retryable, result.status_code, f"Microsoft sign-in failed: {result.error}",
                      result.retry_after)  # fmt: skip
    token = (reply.data or {}).get("access_token")
    if not token:
        return Result(False, True, reply.status, "Microsoft sign-in returned no access token")
    lifetime = float((reply.data or {}).get("expires_in") or 3600)
    transport.tokens[fingerprint] = (str(token), time.monotonic() + max(60.0, lifetime - TOKEN_MARGIN))
    return str(token)


async def sentinel(transport: Transport, secrets: dict[str, Any], event: dict[str, Any]) -> Result:
    token = await _azure_token(transport, secrets)
    if isinstance(token, Result):
        return token
    url = (f"{secrets['url']}/dataCollectionRules/{quote(secrets['dcr_id'])}/streams/{quote(secrets['stream'])}"
           "?api-version=2023-01-01")  # fmt: skip
    reply = await transport.request(
        "POST", url, body=_body([siem_record(event)]), headers={"Authorization": f"Bearer {token}"}, read=True
    )
    if isinstance(reply, Reply) and reply.status == 401:  # token revoked or expired early: sign in again next time
        transport.tokens.clear()
        return Result(False, True, 401, f"{secrets['host']} rejected the access token; signing in again")
    return _outcome(secrets["host"], reply, {
        403: "the app registration needs the Monitoring Metrics Publisher role on the data collection rule",
        404: "the data collection rule or stream was not found",
    })  # fmt: skip


SENDERS = {"jira": jira, "servicenow": servicenow, "splunk": splunk, "sentinel": sentinel}
