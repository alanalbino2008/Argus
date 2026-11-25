"""Two-person approval for sensitive actions (Phase 90).

A workspace can require that some actions are approved by a second administrator before they
happen: deleting a case, exporting a case's evidence bundle, revealing leaked email addresses in
clear, or creating an admin API key. One stolen admin key, or one person acting alone, can then no
longer destroy or carry off a case.

How it works:

1. The protected call is made as usual. Without an approval, Argus records a **request** (or reuses
   the caller's pending one for the same thing), notifies the workspace through its alert channels,
   and answers ``202 Accepted`` with the request.
2. **Another** administrator approves or rejects it (``POST /api/approvals/{id}/approve``). Approving
   one's own request is refused, whichever key or session it comes from.
3. The requester repeats the call with ``X-Argus-Approval: <id>``. The approval is checked for the
   same action, resource and requester, and spent: it works once, and expires 24 hours after it
   was requested.

Every step is in the audit log. Loosening the policy (removing a protected action) needs an
approval itself, so the protection cannot be switched off by the person it protects against.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select, update

from argus.storage.db import ApprovalPolicyRow, ApprovalRow, Database

ACTIONS = {
    "case.delete": "Delete a case",
    "case.export": "Export a case's evidence bundle",
    "exposure.reveal": "Reveal leaked email addresses in clear",
    "key.create_admin": "Create an admin API key",
    "audit.stream_stop": "Stop or remove an audit log stream to a SIEM",
    "approval.policy": "Remove an action from the approval policy",
}
POLICY_ACTIONS = [a for a in ACTIONS if a != "approval.policy"]  # what a workspace can protect
TTL = timedelta(hours=24)
HEADER = "X-Argus-Approval"


class ApprovalRequired(Exception):
    """The action needs an approval: answered as 202 with the (pending) request."""

    def __init__(self, approval: dict[str, Any], message: str):
        super().__init__(message)
        self.approval = approval
        self.message = message


class ApprovalRefused(Exception):
    """An approval id was presented but cannot be used (wrong action, not approved, expired, spent)."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: datetime | None) -> datetime | None:
    return value if value is None or value.tzinfo else value.replace(tzinfo=timezone.utc)


def _view(row: ApprovalRow) -> dict[str, Any]:
    status = row.status
    expires = _aware(row.expires_at)
    if status in ("pending", "approved") and expires is not None and expires <= _now():
        status = "expired"
    return {
        "id": row.id, "action": row.action, "label": ACTIONS.get(row.action, row.action), "resource": row.resource,
        "summary": row.summary, "reason": row.reason, "requested_by": row.requested_by,
        "requested_at": _aware(row.requested_at).isoformat() if row.requested_at else None,  # type: ignore[union-attr]
        "expires_at": expires.isoformat() if expires else None, "status": status, "decided_by": row.decided_by,
        "decided_at": _aware(row.decided_at).isoformat() if row.decided_at else None,  # type: ignore[union-attr]
        "decision_note": row.decision_note, "workspace_id": row.workspace_id,
    }  # fmt: skip


def same_person(row: ApprovalRow, key_id: str, name: str) -> bool:
    """Whether the decider is the requester: the same key or session, or the same name (another key of theirs)."""
    return row.requested_key == key_id or row.requested_by.strip().lower() == name.strip().lower()


class ApprovalRepository:
    def __init__(self, db: Database):
        self.db = db

    # ------------------------------------------------------------------ policy
    async def policy(self, workspace_id: str) -> dict[str, Any]:
        async with self.db.session() as s:
            row = await s.get(ApprovalPolicyRow, workspace_id)
        return {
            "actions": list(row.actions or []) if row else [],
            "updated_at": _aware(row.updated_at).isoformat() if row else None,  # type: ignore[union-attr]
            "updated_by": row.updated_by if row else None,
            "available": {a: ACTIONS[a] for a in POLICY_ACTIONS},
        }

    async def set_policy(self, workspace_id: str, actions: list[str], by: str) -> dict[str, Any]:
        async with self.db.session() as s, s.begin():
            row = await s.get(ApprovalPolicyRow, workspace_id)
            if row is None:
                s.add(ApprovalPolicyRow(workspace_id=workspace_id, actions=actions, updated_at=_now(), updated_by=by))
            else:
                row.actions, row.updated_at, row.updated_by = actions, _now(), by
        return await self.policy(workspace_id)

    async def protects(self, workspace_id: str, action: str) -> bool:
        if action == "approval.policy":
            return bool((await self.policy(workspace_id))["actions"])
        return action in (await self.policy(workspace_id))["actions"]

    # ------------------------------------------------------------------ requests
    async def request(
        self, workspace_id: str, *, action: str, resource: str, summary: str, reason: str, key_id: str, name: str
    ) -> tuple[dict[str, Any], bool]:
        """A pending request for this action, reusing the caller's own if one is open. Returns (request, new)."""
        now = _now()
        async with self.db.session() as s, s.begin():
            open_rows = (await s.scalars(select(ApprovalRow).where(
                ApprovalRow.workspace_id == workspace_id, ApprovalRow.action == action, ApprovalRow.resource == resource,
                ApprovalRow.requested_key == key_id, ApprovalRow.status.in_(("pending", "approved"))))).all()  # fmt: skip
            for row in open_rows:
                if (_aware(row.expires_at) or now) > now:
                    return _view(row), False
            row = ApprovalRow(
                id=f"apr_{secrets.token_hex(8)}", workspace_id=workspace_id, action=action, resource=resource[:128],
                summary=summary[:500], reason=reason[:500], requested_by=name[:128], requested_key=key_id[:64],
                requested_at=now, expires_at=now + TTL, status="pending",
            )  # fmt: skip
            s.add(row)
        return _view(row), True

    async def get(self, approval_id: str, workspace_id: str) -> dict[str, Any] | None:
        async with self.db.session() as s:
            row = await s.get(ApprovalRow, approval_id)
        return _view(row) if row is not None and row.workspace_id == workspace_id else None

    async def list(self, workspace_id: str, status: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        async with self.db.session() as s:
            rows = (await s.scalars(select(ApprovalRow).where(ApprovalRow.workspace_id == workspace_id)
                                    .order_by(ApprovalRow.requested_at.desc()).limit(500))).all()  # fmt: skip
        views = [_view(r) for r in rows]
        return [v for v in views if status in (None, "all") or v["status"] == status][:limit]

    async def decide(
        self, approval_id: str, workspace_id: str, *, approve: bool, key_id: str, name: str, note: str
    ) -> dict[str, Any]:
        """Approve or reject a pending request. Raises ValueError (with the reason) when not allowed."""
        async with self.db.session() as s, s.begin():
            row = await s.get(ApprovalRow, approval_id)
            if row is None or row.workspace_id != workspace_id:
                raise LookupError("Approval request not found")
            view = _view(row)
            if view["status"] != "pending":
                raise ValueError(f"This request is {view['status']}")
            if same_person(row, key_id, name):
                raise PermissionError("A request must be approved by someone else")
            row.status = "approved" if approve else "rejected"
            row.decided_by, row.decided_at, row.decision_note = name[:128], _now(), (note or "")[:500] or None
        return _view(row)

    async def consume(self, approval_id: str, workspace_id: str, *, action: str, resource: str, key_id: str) -> None:
        """Spend an approval for this action. Raises ApprovalRefused with the reason."""
        async with self.db.session() as s, s.begin():
            row = await s.get(ApprovalRow, approval_id)
            if row is None or row.workspace_id != workspace_id:
                raise ApprovalRefused("Approval not found")
            if row.action != action or row.resource != resource[:128]:
                raise ApprovalRefused("This approval is for another action")
            if row.requested_key != key_id:
                raise ApprovalRefused("Only the person who asked can use this approval")
            view = _view(row)
            if view["status"] != "approved":
                raise ApprovalRefused(f"This approval is {view['status']}")
            spent = await s.execute(update(ApprovalRow).where(ApprovalRow.id == approval_id,
                                                             ApprovalRow.status == "approved")
                                    .values(status="used", used_at=_now()).execution_options(synchronize_session=False))  # fmt: skip
            if not getattr(spent, "rowcount", 0):
                raise ApprovalRefused("This approval was already used")
