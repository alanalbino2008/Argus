"""Events, and how each channel type displays them.

Alert text is partly built from what scans discover on the internet (host names, path
titles), so it is **untrusted** and escaped for every destination:

* Slack: ``&``, ``<`` and ``>`` are escaped, so text cannot inject ``<!channel>`` pings or
  disguised ``<https://evil|links>``;
* Teams: Markdown control characters are escaped, so text cannot add links or formatting;
* email: the HTML part is HTML-escaped and the subject cannot contain line breaks (header
  injection).
"""

from __future__ import annotations

import html
import re
import secrets
from datetime import datetime, timezone
from email.message import EmailMessage
from typing import Any

SEVERITY_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}
SEVERITY_COLOR = {"critical": "attention", "high": "warning", "medium": "accent", "low": "default"}
MAX_PATHS = 3


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _link(public_url: str | None, path: str) -> str | None:
    return f"{public_url.rstrip('/')}{path}" if public_url else None


def alert_event(alert: dict[str, Any], workspace: dict[str, Any], public_url: str | None) -> dict[str, Any]:
    """The JSON document sent to webhooks and stored in the outbox (contains no secrets)."""
    summary = alert.get("summary") or {}
    counts = summary.get("summary") or {}
    paths = [
        {"title": str(p.get("title", ""))[:300], "severity": p.get("severity")}
        for p in (summary.get("new_paths") or [])[:5]
    ]
    return {
        "type": "alert.raised",
        "id": f"evt_{alert['id']}",
        "occurred_at": alert.get("created_at") or _now_iso(),
        "workspace": {"id": workspace.get("id"), "name": workspace.get("name")},
        "alert": {
            "id": alert["id"],
            "severity": alert["severity"],
            "target": alert["target"],
            "headline": alert["headline"],
            "monitor_id": alert.get("monitor_id"),
            "investigation_id": alert["investigation_id"],
            "previous_investigation_id": alert["previous_investigation_id"],
            "counts": {
                k: counts.get(k)
                for k in ("new_paths", "escalated_paths", "resolved_paths", "added", "changed", "risk_delta", "trend")
                if k in counts
            },
            "new_paths": paths,
            "url": _link(public_url, f"/?ws={workspace.get('id')}&inv={alert['investigation_id']}"),
        },
    }


def probe_event(workspace: dict[str, Any], channel_name: str, by: str) -> dict[str, Any]:
    return {
        "type": "notification.test",
        "id": f"evt_test_{secrets.token_hex(6)}",
        "occurred_at": _now_iso(),
        "workspace": {"id": workspace.get("id"), "name": workspace.get("name")},
        "message": f"Test notification for “{channel_name}”, sent by {by}. If you can read this, alerts will arrive here.",
    }


# ---------------------------------------------------------------------------- escaping
def slack_escape(text: Any) -> str:
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]()#+\-.!|>~])")


def markdown_escape(text: Any) -> str:
    return _MD_SPECIAL.sub(r"\\\1", str(text))


def header_safe(text: Any, limit: int = 200) -> str:
    return re.sub(r"[\r\n\t]+", " ", str(text))[:limit]


# ---------------------------------------------------------------------------- renderers
def _title(event: dict[str, Any]) -> str:
    if event["type"] == "alert.raised":
        alert = event["alert"]
        return f"{alert['severity'].upper()} drift on {alert['target']}"
    return "Argus test notification"


def slack(event: dict[str, Any]) -> dict[str, Any]:
    workspace = slack_escape(event["workspace"].get("name") or "")
    if event["type"] != "alert.raised":
        text = slack_escape(event.get("message", ""))
        return {
            "text": text,
            "blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": f":white_check_mark: {text}"}}],
        }
    alert = event["alert"]
    emoji = SEVERITY_EMOJI.get(alert["severity"], "")
    lines = [f"{emoji} *{slack_escape(_title(event))}*", slack_escape(alert["headline"])]
    lines += [f"• {slack_escape(p['title'])} ({slack_escape(p['severity'])})" for p in alert["new_paths"][:MAX_PATHS]]
    blocks: list[dict[str, Any]] = [
        {"type": "section", "text": {"type": "mrkdwn", "text": "\n".join(lines)[:2900]}},
        {"type": "context", "elements": [{"type": "mrkdwn", "text": f"Argus · workspace {workspace}"}]},
    ]
    if alert.get("url"):
        blocks.append(
            {
                "type": "actions",
                "elements": [
                    {"type": "button", "text": {"type": "plain_text", "text": "Open in Argus"}, "url": alert["url"]}
                ],
            }
        )
    return {"text": slack_escape(f"{emoji} {_title(event)}: {alert['headline']}")[:3000], "blocks": blocks}


def teams(event: dict[str, Any]) -> dict[str, Any]:
    body: list[dict[str, Any]] = []
    actions: list[dict[str, Any]] = []
    if event["type"] != "alert.raised":
        body.append({"type": "TextBlock", "text": markdown_escape(event.get("message", "")), "wrap": True})
    else:
        alert = event["alert"]
        body += [
            {
                "type": "TextBlock",
                "text": markdown_escape(_title(event)),
                "weight": "Bolder",
                "size": "Medium",
                "color": SEVERITY_COLOR.get(alert["severity"], "default"),
                "wrap": True,
            },
            {"type": "TextBlock", "text": markdown_escape(alert["headline"]), "wrap": True},
            {
                "type": "FactSet",
                "facts": [
                    {"title": "Severity", "value": markdown_escape(alert["severity"])},
                    {"title": "Target", "value": markdown_escape(alert["target"])},
                    {"title": "Workspace", "value": markdown_escape(event["workspace"].get("name") or "")},
                ],
            },
        ]
        body += [
            {
                "type": "TextBlock",
                "text": f"• {markdown_escape(p['title'])} ({markdown_escape(p['severity'])})",
                "wrap": True,
            }
            for p in alert["new_paths"][:MAX_PATHS]
        ]
        if alert.get("url"):
            actions.append({"type": "Action.OpenUrl", "title": "Open in Argus", "url": alert["url"]})
    card: dict[str, Any] = {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.4",
        "body": body,
    }
    if actions:
        card["actions"] = actions
    return {
        "type": "message",
        "attachments": [
            {"contentType": "application/vnd.microsoft.card.adaptive", "contentUrl": None, "content": card}
        ],
    }


def email(event: dict[str, Any], sender: str, recipients: list[str]) -> EmailMessage:
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)
    msg["Subject"] = header_safe(f"[Argus] {_title(event)}")
    msg["Message-ID"] = f"<{event['id']}.{secrets.token_hex(4)}@argus>"
    if event["type"] != "alert.raised":
        text = event.get("message", "")
        msg.set_content(text)
        msg.add_alternative(f"<p>{html.escape(text)}</p>", subtype="html")
        return msg
    alert = event["alert"]
    paths = alert["new_paths"][:MAX_PATHS]
    text_lines = [
        _title(event),
        "",
        alert["headline"],
        "",
        *(f"- {p['title']} ({p['severity']})" for p in paths),
        "",
        f"Workspace: {event['workspace'].get('name')}",
    ]
    if alert.get("url"):
        text_lines.append(f"Open in Argus: {alert['url']}")
    msg.set_content("\n".join(text_lines))
    items = "".join(f"<li>{html.escape(str(p['title']))} ({html.escape(str(p['severity']))})</li>" for p in paths)
    link = f'<p><a href="{html.escape(alert["url"], quote=True)}">Open in Argus</a></p>' if alert.get("url") else ""
    msg.add_alternative(
        f"<h2>{html.escape(_title(event))}</h2><p>{html.escape(alert['headline'])}</p>"
        f"{f'<ul>{items}</ul>' if items else ''}"
        f'<p style="color:#666">Workspace: {html.escape(str(event["workspace"].get("name")))}</p>{link}',
        subtype="html",
    )
    return msg
