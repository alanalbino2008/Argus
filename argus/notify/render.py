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
            "url": _link(
                public_url,
                f"/?ws={workspace.get('id')}#/exposure"
                if summary.get("exposure")
                else f"/?ws={workspace.get('id')}&inv={alert['investigation_id']}",
            ),
            **({"exposure": summary["exposure"]} if summary.get("exposure") else {}),
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


def report_event(
    record: dict[str, Any],
    data: Any,
    schedule: dict[str, Any],
    workspace: dict[str, Any],
    public_url: str | None,
) -> dict[str, Any]:
    """A scheduled report is ready: what Slack/Teams/webhooks receive (email also gets the PDF)."""
    return {
        "type": "report.scheduled",
        "id": f"evt_report_{record['id']}",
        "occurred_at": record.get("created_at") or _now_iso(),
        "workspace": {"id": workspace.get("id"), "name": workspace.get("name")},
        "report": {
            "id": record["id"],
            "schedule": {"id": schedule["id"], "name": schedule["name"]},
            "target": record["target"],
            "investigation_id": record["investigation_id"],
            "rating": data.rating,
            "score": data.score,
            "counts": data.counts,
            "severity_counts": data.severity_counts,
            "trend": data.trend,
            "tlp": record["tlp"],
            "prepared_for": record.get("prepared_for"),
            "sha256": record["sha256"],
            "filename": record.get("filename"),
            "url": _link(public_url, f"/?ws={workspace.get('id')}&inv={record['investigation_id']}"),
            "verify_url": _link(public_url, f"/api/reports/verify/{record['sha256']}"),
        },
    }


def _report_lines(event: dict[str, Any], *, attached: bool) -> list[str]:
    r = event["report"]
    sev = r["severity_counts"]
    lines = [
        f"Overall exposure: {str(r['rating']).upper()} (risk score {r['score']}/100)",
        f"{r['counts']['paths']} attack paths: "
        + ", ".join(f"{sev.get(s, 0)} {s}" for s in ("critical", "high", "medium", "low")),
    ]
    if r.get("trend"):
        t = r["trend"]
        lines.append(
            f"Since {t['previous_date']}: risk {t['risk_delta']:+d}, {t['new_paths']} new and "
            f"{t['resolved_paths']} resolved attack path(s)"
        )
    lines.append(
        f"Classification: TLP:{r['tlp']}" + (f" · prepared for {r['prepared_for']}" if r.get("prepared_for") else "")
    )
    lines.append(f"Report {r['id']} · SHA-256 {r['sha256']}")
    lines.append("The PDF is attached." if attached else "Download the PDF from Argus.")
    return lines


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
    if event["type"] == "report.scheduled":
        report = event["report"]
        return f"{report['schedule']['name']}: {report['target']} ({str(report['rating']).upper()})"
    if event["type"] == "alert.raised":
        alert = event["alert"]
        return f"{alert['severity'].upper()} drift on {alert['target']}"
    return "Argus test notification"


def slack(event: dict[str, Any]) -> dict[str, Any]:
    workspace = slack_escape(event["workspace"].get("name") or "")
    if event["type"] == "report.scheduled":
        report = event["report"]
        text = "\n".join([f":page_facing_up: *{slack_escape(_title(event))}*",
                          *(slack_escape(x) for x in _report_lines(event, attached=False))])  # fmt: skip
        report_blocks: list[dict[str, Any]] = [
            {"type": "section", "text": {"type": "mrkdwn", "text": text[:2900]}},
            {"type": "context", "elements": [{"type": "mrkdwn", "text": f"Argus · workspace {workspace}"}]},
        ]
        if report.get("url"):
            report_blocks.append({"type": "actions", "elements": [
                {"type": "button", "text": {"type": "plain_text", "text": "Open in Argus"}, "url": report["url"]}]})  # fmt: skip
        return {"text": slack_escape(_title(event))[:3000], "blocks": report_blocks}
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
    if event["type"] == "report.scheduled":
        body.append({"type": "TextBlock", "text": markdown_escape(_title(event)), "weight": "Bolder", "size": "Medium",
                     "wrap": True})  # fmt: skip
        body += [{"type": "TextBlock", "text": markdown_escape(x), "wrap": True}
                 for x in _report_lines(event, attached=False)]  # fmt: skip
        if event["report"].get("url"):
            actions.append({"type": "Action.OpenUrl", "title": "Open in Argus", "url": event["report"]["url"]})
    elif event["type"] != "alert.raised":
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


def email(
    event: dict[str, Any], sender: str, recipients: list[str], attachment: tuple[str, bytes] | None = None
) -> EmailMessage:
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)
    msg["Subject"] = header_safe(f"[Argus] {_title(event)}")
    msg["Message-ID"] = f"<{event['id']}.{secrets.token_hex(4)}@argus>"
    if event["type"] == "report.scheduled":
        lines = _report_lines(event, attached=attachment is not None)
        report = event["report"]
        verify = f"Verify this report: {report['verify_url']}" if report.get("verify_url") else ""
        msg.set_content("\n".join([_title(event), "", *lines, "", verify]).strip() + "\n")
        items = "".join(f"<li>{html.escape(x)}</li>" for x in lines)
        link = (f'<p><a href="{html.escape(report["verify_url"], quote=True)}">Verify this report</a></p>'
                if report.get("verify_url") else "")  # fmt: skip
        msg.add_alternative(f"<h2>{html.escape(_title(event))}</h2><ul>{items}</ul>{link}", subtype="html")
        if attachment is not None:
            filename, pdf = attachment
            msg.add_attachment(pdf, maintype="application", subtype="pdf", filename=header_safe(filename, 255))
        return msg
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
