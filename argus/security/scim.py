"""SCIM 2.0 provisioning (RFC 7643/7644): the identity provider manages who has access (Phase 94).

Okta, Microsoft Entra ID, OneLogin and JumpCloud push users and groups to applications over SCIM.
With it, joining and leaving the organisation is handled in one place: a person removed in the
identity provider loses Argus access at once, without anyone remembering to do it here.

* **Users** created over SCIM are *provisioned*: they exist before anyone signs in. Their first
  single sign-on with the same email links to that record, so no duplicate appears. Only
  provisioned records that never signed in are linked this way, so an existing account cannot be
  taken over by email. Deactivating a user (``active: false``, or ``DELETE``) disables them and ends
  every session at once.
* **Groups** carry members. Argus administrators map group names to a workspace and a role
  (``PUT /api/scim/group-roles``); members of a mapped group become members of that workspace with
  that role (the highest, if several groups apply). SCIM only ever changes memberships it created;
  memberships added by hand are left alone.
* Authentication is a bearer token, ``ARGUS_SCIM_TOKEN``: without it, the SCIM endpoints do not
  exist. Every change is audited as ``scim.*``.
"""

from __future__ import annotations

import re
import secrets
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import delete, func, or_, select

from argus.storage.db import Database, ScimGroupRoleRow, ScimGroupRow, SessionRow, UserRow, WorkspaceMemberRow

USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group"
LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"
ISSUER = "scim"  # provisioned users' issuer until their first sign-in
ADDED_BY = "scim"  # memberships SCIM manages
RANK = {"viewer": 1, "analyst": 2, "admin": 3}
FILTER = re.compile(r'^\s*(userName|externalId|displayName|emails\.value)\s+eq\s+"((?:[^"\\]|\\.)*)"\s*$', re.I)


class ScimError(Exception):
    def __init__(self, status: int, detail: str, scim_type: str | None = None):
        super().__init__(detail)
        self.status, self.detail, self.scim_type = status, detail, scim_type

    def body(self) -> dict[str, Any]:
        out = {"schemas": [ERROR_SCHEMA], "status": str(self.status), "detail": self.detail}
        if self.scim_type:
            out["scimType"] = self.scim_type
        return out


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return (value if value.tzinfo else value.replace(tzinfo=timezone.utc)).isoformat()


def parse_filter(expression: str | None) -> tuple[str, str] | None:
    """``attribute eq "value"``, the filter identity providers use to look a resource up."""
    if not expression:
        return None
    match = FILTER.match(expression)
    if not match:
        raise ScimError(400, "Only 'attribute eq \"value\"' filters are supported", "invalidFilter")
    return match.group(1).lower(), match.group(2).replace('\\"', '"')


def _truthy(value: Any) -> bool:
    """Entra ID sends booleans as the strings "True"/"False"."""
    return value if isinstance(value, bool) else str(value).strip().lower() == "true"


def _primary_email(payload: dict[str, Any]) -> str | None:
    emails = payload.get("emails") or []
    chosen = next((e for e in emails if isinstance(e, dict) and e.get("primary")), None) or (
        emails[0] if emails else None
    )
    value = (chosen or {}).get("value") if isinstance(chosen, dict) else None
    return str(value).strip().lower()[:320] if value else None


def _display_name(payload: dict[str, Any]) -> str | None:
    name = payload.get("name") or {}
    parts = [name.get("givenName"), name.get("familyName")] if isinstance(name, dict) else []
    text = (
        payload.get("displayName")
        or (name.get("formatted") if isinstance(name, dict) else None)
        or " ".join(p for p in parts if p)
    )
    return str(text).strip()[:255] or None


class Scim:
    def __init__(self, db: Database, base_url: str = ""):
        self.db = db
        self.base_url = base_url.rstrip("/")

    # ------------------------------------------------------------------ views
    def user_view(self, row: UserRow) -> dict[str, Any]:
        email = row.email or row.user_name
        return {
            "schemas": [USER_SCHEMA], "id": row.id, "externalId": row.external_id,
            "userName": row.user_name or email, "displayName": row.name, "name": {"formatted": row.name},
            "emails": [{"value": email, "primary": True, "type": "work"}] if email else [],
            "active": not row.disabled,
            "meta": {"resourceType": "User", "created": _iso(row.created_at), "lastModified": _iso(row.created_at),
                     "location": f"{self.base_url}/scim/v2/Users/{row.id}"},
        }  # fmt: skip

    def group_view(self, row: ScimGroupRow) -> dict[str, Any]:
        return {
            "schemas": [GROUP_SCHEMA], "id": row.id, "externalId": row.external_id, "displayName": row.display_name,
            "members": [{"value": m, "$ref": f"{self.base_url}/scim/v2/Users/{m}"} for m in row.members or []],
            "meta": {"resourceType": "Group", "created": _iso(row.created_at), "lastModified": _iso(row.updated_at),
                     "location": f"{self.base_url}/scim/v2/Groups/{row.id}"},
        }  # fmt: skip

    @staticmethod
    def page(resources: list[dict[str, Any]], start: int, count: int) -> dict[str, Any]:
        start = max(1, start)
        window = resources[start - 1 : start - 1 + max(0, count)]
        return {"schemas": [LIST_SCHEMA], "totalResults": len(resources), "startIndex": start,
                "itemsPerPage": len(window), "Resources": window}  # fmt: skip

    # ------------------------------------------------------------------ users
    async def list_users(self, expression: str | None) -> list[dict[str, Any]]:
        wanted = parse_filter(expression)
        stmt = select(UserRow).order_by(UserRow.created_at)
        if wanted:
            attribute, value = wanted
            low = value.lower()
            if attribute == "username":
                stmt = stmt.where(or_(func.lower(UserRow.user_name) == low, func.lower(UserRow.email) == low))
            elif attribute == "externalid":
                stmt = stmt.where(UserRow.external_id == value)
            elif attribute == "emails.value":
                stmt = stmt.where(func.lower(UserRow.email) == low)
            else:
                stmt = stmt.where(func.lower(UserRow.name) == low)
        async with self.db.session() as s:
            rows = (await s.scalars(stmt)).all()
        return [self.user_view(r) for r in rows]

    async def get_user(self, user_id: str) -> dict[str, Any]:
        async with self.db.session() as s:
            row = await s.get(UserRow, user_id)
        if row is None:
            raise ScimError(404, "User not found")
        return self.user_view(row)

    async def create_user(self, payload: dict[str, Any]) -> dict[str, Any]:
        user_name = str(payload.get("userName") or "").strip()[:320]
        if not user_name:
            raise ScimError(400, "userName is required", "invalidValue")
        email = _primary_email(payload) or (user_name.lower() if "@" in user_name else None)
        async with self.db.session() as s, s.begin():
            taken = (await s.scalars(select(UserRow).where(func.lower(UserRow.user_name) == user_name.lower()))).first()
            if taken is not None:
                raise ScimError(409, "A user with this userName already exists", "uniqueness")
            # Someone who already signed in with single sign-on: the identity provider takes them over.
            row = (
                (await s.scalars(select(UserRow).where(func.lower(UserRow.email) == email))).first() if email else None
            )
            if row is None:
                row = UserRow(id=f"usr_{secrets.token_hex(8)}", issuer=ISSUER, subject=str(payload.get("externalId") or user_name)[:255],
                              email=email, name=_display_name(payload), role="viewer", disabled=False, created_at=_now())  # fmt: skip
                s.add(row)
            row.scim_managed, row.user_name = True, user_name
            row.external_id = str(payload["externalId"])[:255] if payload.get("externalId") else row.external_id
            row.name = _display_name(payload) or row.name
            if "active" in payload:
                row.disabled = not _truthy(payload["active"])
            await s.flush()
            return self.user_view(row)

    async def replace_user(self, user_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        async with self.db.session() as s, s.begin():
            row = await s.get(UserRow, user_id)
            if row is None:
                raise ScimError(404, "User not found")
            if payload.get("userName"):
                row.user_name = str(payload["userName"]).strip()[:320]
            row.external_id = str(payload["externalId"])[:255] if payload.get("externalId") else row.external_id
            row.name = _display_name(payload) or row.name
            row.email = _primary_email(payload) or row.email
            row.scim_managed = True
            ended = await self._set_active(s, row, _truthy(payload.get("active", True)))
            await s.flush()
            return {**self.user_view(row), "_sessions_ended": ended}

    async def patch_user(self, user_id: str, operations: list[dict[str, Any]]) -> dict[str, Any]:
        async with self.db.session() as s, s.begin():
            row = await s.get(UserRow, user_id)
            if row is None:
                raise ScimError(404, "User not found")
            ended = 0
            for op in operations:
                kind = str(op.get("op") or "").lower()
                if kind not in ("add", "replace", "remove"):
                    raise ScimError(400, f"Unsupported operation: {op.get('op')}", "invalidSyntax")
                path, value = str(op.get("path") or "").strip(), op.get("value")
                changes = value if not path and isinstance(value, dict) else {path: value}
                for attribute, new in changes.items():
                    key = attribute.lower()
                    if key == "active":
                        ended += await self._set_active(s, row, _truthy(new))
                    elif key in ("username",):
                        row.user_name = str(new).strip()[:320]
                    elif key in ("displayname", "name.formatted"):
                        row.name = str(new).strip()[:255] or row.name
                    elif key == "externalid":
                        row.external_id = str(new)[:255]
                    elif key.startswith("emails"):
                        email = _primary_email({"emails": new}) if isinstance(new, list) else str(new).strip().lower()
                        row.email = email or row.email
                    # Other attributes (title, phone numbers…) are not kept: Argus does not use them.
            row.scim_managed = True
            await s.flush()
            return {**self.user_view(row), "_sessions_ended": ended}

    async def deactivate_user(self, user_id: str) -> int:
        async with self.db.session() as s, s.begin():
            row = await s.get(UserRow, user_id)
            if row is None:
                raise ScimError(404, "User not found")
            return await self._set_active(s, row, False)

    @staticmethod
    async def _set_active(s: Any, row: UserRow, active: bool) -> int:
        """Enable or disable; disabling signs the person out everywhere. Returns sessions ended."""
        row.disabled = not active
        if active:
            return 0
        result = await s.execute(delete(SessionRow).where(SessionRow.user_id == row.id))
        return int(getattr(result, "rowcount", 0) or 0)

    # ------------------------------------------------------------------ groups
    async def list_groups(self, expression: str | None) -> list[dict[str, Any]]:
        wanted = parse_filter(expression)
        stmt = select(ScimGroupRow).order_by(ScimGroupRow.created_at)
        if wanted:
            attribute, value = wanted
            stmt = stmt.where(func.lower(ScimGroupRow.display_name) == value.lower()) if attribute == "displayname" \
                else stmt.where(ScimGroupRow.external_id == value)  # fmt: skip
        async with self.db.session() as s:
            rows = (await s.scalars(stmt)).all()
        return [self.group_view(r) for r in rows]

    async def get_group(self, group_id: str) -> dict[str, Any]:
        async with self.db.session() as s:
            row = await s.get(ScimGroupRow, group_id)
        if row is None:
            raise ScimError(404, "Group not found")
        return self.group_view(row)

    async def create_group(self, payload: dict[str, Any]) -> tuple[dict[str, Any], set[str]]:
        name = str(payload.get("displayName") or "").strip()[:255]
        if not name:
            raise ScimError(400, "displayName is required", "invalidValue")
        members = await self._existing([m.get("value") for m in payload.get("members") or [] if isinstance(m, dict)])
        async with self.db.session() as s, s.begin():
            if (
                await s.scalars(select(ScimGroupRow).where(func.lower(ScimGroupRow.display_name) == name.lower()))
            ).first():
                raise ScimError(409, "A group with this displayName already exists", "uniqueness")
            row = ScimGroupRow(id=f"grp_{secrets.token_hex(8)}", display_name=name, members=sorted(members),
                               external_id=str(payload["externalId"])[:255] if payload.get("externalId") else None,
                               created_at=_now(), updated_at=_now())  # fmt: skip
            s.add(row)
        return self.group_view(row), members

    async def replace_group(self, group_id: str, payload: dict[str, Any]) -> tuple[dict[str, Any], set[str]]:
        members = await self._existing([m.get("value") for m in payload.get("members") or [] if isinstance(m, dict)])
        async with self.db.session() as s, s.begin():
            row = await s.get(ScimGroupRow, group_id)
            if row is None:
                raise ScimError(404, "Group not found")
            touched = set(row.members or []) | members
            row.display_name = str(payload.get("displayName") or row.display_name).strip()[:255]
            row.members, row.updated_at = sorted(members), _now()
        return self.group_view(row), touched

    async def patch_group(self, group_id: str, operations: list[dict[str, Any]]) -> tuple[dict[str, Any], set[str]]:
        async with self.db.session() as s, s.begin():
            row = await s.get(ScimGroupRow, group_id)
            if row is None:
                raise ScimError(404, "Group not found")
            members, touched = set(row.members or []), set(row.members or [])
            for op in operations:
                kind, path, value = str(op.get("op") or "").lower(), str(op.get("path") or "").strip(), op.get("value")
                if not path and isinstance(value, dict):  # Entra: {"op": "replace", "value": {"displayName": …}}
                    if value.get("displayName"):
                        row.display_name = str(value["displayName"]).strip()[:255]
                    continue
                if path.lower() == "displayname":
                    row.display_name = str(value).strip()[:255]
                    continue
                selector = re.match(r'^members\[value eq "([^"]+)"\]$', path, re.I)
                if selector and kind == "remove":  # Okta removes one member by filter
                    members.discard(selector.group(1))
                    continue
                if path.lower() != "members":
                    raise ScimError(400, f"Unsupported path: {path}", "invalidPath")
                ids = [m.get("value") for m in (value or []) if isinstance(m, dict)]
                if kind == "add":
                    members |= await self._existing(ids)
                elif kind == "remove":
                    members -= set(ids) if ids else set(members)
                elif kind == "replace":
                    members = await self._existing(ids)
                else:
                    raise ScimError(400, f"Unsupported operation: {op.get('op')}", "invalidSyntax")
            row.members, row.updated_at = sorted(members), _now()
            touched |= members
        return self.group_view(row), touched

    async def delete_group(self, group_id: str) -> set[str]:
        async with self.db.session() as s, s.begin():
            row = await s.get(ScimGroupRow, group_id)
            if row is None:
                raise ScimError(404, "Group not found")
            members = set(row.members or [])
            await s.delete(row)
        return members

    async def _existing(self, ids: list[Any]) -> set[str]:
        wanted = {str(i) for i in ids if i}
        if not wanted:
            return set()
        async with self.db.session() as s:
            return set((await s.scalars(select(UserRow.id).where(UserRow.id.in_(wanted)))).all())

    # ------------------------------------------------------------------ group -> workspace roles
    async def group_roles(self) -> list[dict[str, Any]]:
        async with self.db.session() as s:
            rows = (await s.scalars(select(ScimGroupRoleRow).order_by(ScimGroupRoleRow.group_name))).all()
        return [{"group": r.group_name, "workspace_id": r.workspace_id, "role": r.role, "updated_by": r.updated_by,
                 "updated_at": _iso(r.updated_at)} for r in rows]  # fmt: skip

    async def set_group_role(self, group: str, workspace_id: str, role: str | None, by: str) -> set[str]:
        """Map (or, with role None, unmap) a group to a workspace role. Returns the members to re-sync."""
        name = group.strip().lower()
        async with self.db.session() as s, s.begin():
            row = await s.get(ScimGroupRoleRow, (name, workspace_id))
            if role is None:
                if row is not None:
                    await s.delete(row)
            elif row is None:
                s.add(ScimGroupRoleRow(group_name=name, workspace_id=workspace_id, role=role, updated_by=by,
                                       updated_at=_now()))  # fmt: skip
            else:
                row.role, row.updated_by, row.updated_at = role, by, _now()
            groups = (await s.scalars(select(ScimGroupRow).where(func.lower(ScimGroupRow.display_name) == name))).all()
        return {m for g in groups for m in g.members or []}

    async def sync(self, user_ids: set[str]) -> list[dict[str, Any]]:
        """Make these users' SCIM memberships match their groups; returns the changes made."""
        changes: list[dict[str, Any]] = []
        if not user_ids:
            return changes
        async with self.db.session() as s, s.begin():
            groups = (await s.scalars(select(ScimGroupRow))).all()
            roles = (await s.scalars(select(ScimGroupRoleRow))).all()
            by_group: dict[str, list[ScimGroupRoleRow]] = {}
            for r in roles:
                by_group.setdefault(r.group_name, []).append(r)
            for user_id in user_ids:
                user = await s.get(UserRow, user_id)
                if user is None:
                    continue
                desired: dict[str, str] = {}
                if not user.disabled:
                    for g in groups:
                        if user_id in (g.members or []):
                            for mapping in by_group.get(g.display_name.lower(), []):
                                current = desired.get(mapping.workspace_id)
                                if current is None or RANK[mapping.role] > RANK[current]:
                                    desired[mapping.workspace_id] = mapping.role
                existing = {m.workspace_id: m for m in (await s.scalars(
                    select(WorkspaceMemberRow).where(WorkspaceMemberRow.user_id == user_id))).all()}  # fmt: skip
                for workspace_id, member in existing.items():
                    if member.added_by == ADDED_BY and workspace_id not in desired:
                        await s.delete(member)
                        changes.append({"user": user_id, "workspace": workspace_id, "removed": member.role})
                for workspace_id, role in desired.items():
                    held = existing.get(workspace_id)
                    if held is None:
                        s.add(WorkspaceMemberRow(workspace_id=workspace_id, user_id=user_id, role=role, added_at=_now(),
                                                 added_by=ADDED_BY))  # fmt: skip
                        changes.append({"user": user_id, "workspace": workspace_id, "role": role})
                    elif held.added_by == ADDED_BY and held.role != role:
                        held.role = role
                        changes.append({"user": user_id, "workspace": workspace_id, "role": role})
                    # A membership added by hand is left as it is.
        return changes
