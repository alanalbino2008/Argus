"""Cases, their items, and preserved evidence with its chain of custody.

**Who can see a case.** Every member of the workspace, unless the case is *restricted*: then only
its owner and the people listed as members. There is no administrator exception, because a
journalist protecting a source needs the case to be invisible even to colleagues. A restricted
case someone may not open answers "not found", exactly like a case that does not exist.

**Chain of custody.** Every action on a piece of evidence (captured, viewed, downloaded,
exported, verified) is an entry whose hash covers the previous entry's hash. Altering or
removing any entry breaks every hash after it, which :meth:`verify_custody` detects.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, or_, select

from argus.evidence.capture import Capture, canonical, sha256
from argus.storage.db import CaseItemRow, CaseRow, Database, EvidenceCaptureRow, EvidenceCustodyRow, EvidenceFileRow

GENESIS = "0" * 64
CASE_FIELDS = ("title", "purpose", "summary", "status", "restricted", "members", "tags", "egress", "opsec_mode")
ITEM_FIELDS = ("title", "body", "data", "occurred_at")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return (value if value.tzinfo else value.replace(tzinfo=timezone.utc)).isoformat()


def _case(row: CaseRow) -> dict[str, Any]:
    return {
        "id": row.id, "workspace_id": row.workspace_id, "title": row.title, "purpose": row.purpose,
        "summary": row.summary, "status": row.status, "restricted": bool(row.restricted),
        "members": list(row.members or []), "tags": list(row.tags or []), "egress": row.egress or "",
        "opsec_mode": row.opsec_mode or "standard", "created_by": row.created_by,
        "created_at": _iso(row.created_at), "updated_at": _iso(row.updated_at),
        "legal_hold": bool(row.legal_hold), "legal_hold_note": row.legal_hold_note, "legal_hold_by": row.legal_hold_by,
    }  # fmt: skip


def _item(row: CaseItemRow) -> dict[str, Any]:
    return {
        "id": row.id, "case_id": row.case_id, "kind": row.kind, "title": row.title, "body": row.body,
        "data": row.data or {}, "occurred_at": _iso(row.occurred_at), "created_by": row.created_by,
        "created_at": _iso(row.created_at), "updated_at": _iso(row.updated_at),
    }  # fmt: skip


def _capture(row: EvidenceCaptureRow) -> dict[str, Any]:
    m = row.manifest or {}
    return {
        "id": row.id, "case_id": row.case_id, "kind": row.kind, "url": row.url, "final_url": m.get("final_url"),
        "title": row.title, "note": row.note, "digest": row.digest, "status": m.get("status"),
        "browser": m.get("browser"), "route": m.get("route"), "files": m.get("files", []), "timestamped": row.timestamp_token is not None,
        "warnings": list(row.warnings or []), "captured_by": row.captured_by, "captured_at": _iso(row.captured_at),
    }  # fmt: skip


def custody_hash(prev: str, seq: int, at: str, by: str, action: str, detail: str, digest: str) -> str:
    return hashlib.sha256("|".join([prev, str(seq), at, by, action, detail, digest]).encode()).hexdigest()


def visible(case: CaseRow | dict[str, Any], who: str) -> bool:
    get = case.get if isinstance(case, dict) else lambda k: getattr(case, k)
    return not get("restricted") or who == get("created_by") or who in (get("members") or [])


class CaseRepository:
    def __init__(self, db: Database):
        self.db = db
        self.quotas: Any = None  # set at start-up: evidence storage is held to the workspace's quota

    # ------------------------------------------------------------------ cases
    async def create(self, *, workspace_id: str, by: str, **fields: Any) -> dict[str, Any]:
        moment = _now()
        row = CaseRow(id=f"case_{secrets.token_hex(8)}", workspace_id=workspace_id, created_by=by, created_at=moment,
                      updated_at=moment, **{"summary": "", "status": "open", "restricted": False, "members": [],
                                            "tags": [], "egress": "", "opsec_mode": "standard", **fields})  # fmt: skip
        async with self.db.session() as s, s.begin():
            s.add(row)
        return _case(row)

    async def list_cases(self, *, workspace_id: str, who: str) -> list[dict[str, Any]]:
        async with self.db.session() as s:
            rows = (await s.scalars(select(CaseRow).where(CaseRow.workspace_id == workspace_id)
                                    .order_by(CaseRow.updated_at.desc()))).all()  # fmt: skip
            cases = [_case(r) for r in rows if visible(r, who)]
            ids = [c["id"] for c in cases]
            counts: dict[str, dict[str, int]] = {i: {} for i in ids}
            if ids:
                for case_id, kind, n in (await s.execute(select(CaseItemRow.case_id, CaseItemRow.kind, func.count())
                                                         .where(CaseItemRow.case_id.in_(ids))
                                                         .group_by(CaseItemRow.case_id, CaseItemRow.kind))).all():  # fmt: skip
                    counts[case_id][kind] = n
                for case_id, n in (await s.execute(select(EvidenceCaptureRow.case_id, func.count())
                                                   .where(EvidenceCaptureRow.case_id.in_(ids))
                                                   .group_by(EvidenceCaptureRow.case_id))).all():  # fmt: skip
                    counts[case_id]["evidence"] = n
        return [{**c, "counts": counts[c["id"]]} for c in cases]

    async def get(self, case_id: str, *, workspace_id: str, who: str) -> dict[str, Any] | None:
        async with self.db.session() as s:
            row = await s.get(CaseRow, case_id)
        if row is None or row.workspace_id != workspace_id or not visible(row, who):
            return None
        return _case(row)

    async def info(self, case_id: str) -> dict[str, Any] | None:
        """The case without a visibility check: for Argus's own background work, never for a person."""
        async with self.db.session() as s:
            row = await s.get(CaseRow, case_id)
        return _case(row) if row is not None else None

    async def update(self, case_id: str, *, workspace_id: str, who: str, **changes: Any) -> dict[str, Any] | None:
        async with self.db.session() as s, s.begin():
            row = await s.get(CaseRow, case_id)
            if row is None or row.workspace_id != workspace_id or not visible(row, who):
                return None
            for key, value in changes.items():
                if key in CASE_FIELDS:
                    setattr(row, key, value)
            row.updated_at = _now()
            return _case(row)

    async def delete(self, case_id: str, *, workspace_id: str, who: str) -> bool:
        async with self.db.session() as s, s.begin():
            row = await s.get(CaseRow, case_id)
            if row is None or row.workspace_id != workspace_id or not visible(row, who):
                return False
            await s.delete(row)
        return True

    async def set_legal_hold(
        self, case_id: str, *, workspace_id: str, hold: bool, note: str, by: str
    ) -> dict[str, Any] | None:
        async with self.db.session() as s, s.begin():
            row = await s.get(CaseRow, case_id)
            if row is None or row.workspace_id != workspace_id:
                return None
            row.legal_hold = hold
            row.legal_hold_note, row.legal_hold_by = (note[:200] or None, by) if hold else (None, None)
            row.updated_at = _now()
            return _case(row)

    async def touch(self, case_id: str) -> None:
        async with self.db.session() as s, s.begin():
            row = await s.get(CaseRow, case_id)
            if row is not None:
                row.updated_at = _now()

    # ------------------------------------------------------------------ items
    async def add_item(self, case_id: str, *, by: str, kind: str, **fields: Any) -> dict[str, Any]:
        moment = _now()
        row = CaseItemRow(id=f"item_{secrets.token_hex(8)}", case_id=case_id, kind=kind, created_by=by,
                          created_at=moment, updated_at=moment,
                          **{"body": "", "data": {}, "occurred_at": None, **fields})  # fmt: skip
        async with self.db.session() as s, s.begin():
            s.add(row)
            case = await s.get(CaseRow, case_id)
            if case is not None:
                case.updated_at = moment
        return _item(row)

    async def items(self, case_id: str) -> list[dict[str, Any]]:
        async with self.db.session() as s:
            rows = (await s.scalars(select(CaseItemRow).where(CaseItemRow.case_id == case_id)
                                    .order_by(CaseItemRow.created_at))).all()  # fmt: skip
        return [_item(r) for r in rows]

    async def get_item(self, item_id: str, case_id: str) -> dict[str, Any] | None:
        async with self.db.session() as s:
            row = await s.get(CaseItemRow, item_id)
        return _item(row) if row and row.case_id == case_id else None

    async def update_item(self, item_id: str, case_id: str, **changes: Any) -> dict[str, Any] | None:
        async with self.db.session() as s, s.begin():
            row = await s.get(CaseItemRow, item_id)
            if row is None or row.case_id != case_id:
                return None
            for key, value in changes.items():
                if key in ITEM_FIELDS:
                    setattr(row, key, value)
            row.updated_at = _now()
            return _item(row)

    async def delete_item(self, item_id: str, case_id: str) -> bool:
        async with self.db.session() as s, s.begin():
            row = await s.get(CaseItemRow, item_id)
            if row is None or row.case_id != case_id:
                return False
            await s.delete(row)
            # Links pointing at the removed item go with it.
            for link in (await s.scalars(select(CaseItemRow).where(CaseItemRow.case_id == case_id,
                                                                   CaseItemRow.kind == "link"))).all():  # fmt: skip
                if item_id in ((link.data or {}).get("from"), (link.data or {}).get("to")):
                    await s.delete(link)
        return True

    # ------------------------------------------------------------------ evidence
    async def add_capture(
        self, case_id: str, workspace_id: str, capture: Capture, *, by: str, note: str = ""
    ) -> dict[str, Any]:
        if self.quotas is not None:
            size = sum(len(data) for _, data in capture.files.values())
            await self.quotas.check(workspace_id, "evidence_mb", size / (1024 * 1024))
        moment = _now()
        m = capture.manifest
        row = EvidenceCaptureRow(
            id=f"ev_{secrets.token_hex(8)}", case_id=case_id, workspace_id=workspace_id,
            kind="web" if m.get("kind") == "web_capture" else "upload", url=m.get("url"),
            title=(m.get("title") or m.get("original_filename") or m.get("url") or "")[:300], note=note[:1000],
            digest=capture.digest, manifest=m, timestamp_token=capture.timestamp_token, warnings=capture.warnings,
            captured_by=by, captured_at=moment,
        )  # fmt: skip
        async with self.db.session() as s, s.begin():
            s.add(row)
            await s.flush()
            for name, (media, data) in capture.files.items():
                s.add(EvidenceFileRow(capture_id=row.id, name=name, media_type=media, sha256=sha256(data), size=len(data),
                                      data=data))  # fmt: skip
            await self._custody(s, row, by, "captured", f"{len(capture.files)} file(s), digest {capture.digest}")
            case = await s.get(CaseRow, case_id)
            if case is not None:
                case.updated_at = moment
        return _capture(row)

    async def captures(self, case_id: str) -> list[dict[str, Any]]:
        async with self.db.session() as s:
            rows = (await s.scalars(select(EvidenceCaptureRow).where(EvidenceCaptureRow.case_id == case_id)
                                    .order_by(EvidenceCaptureRow.captured_at))).all()  # fmt: skip
        return [_capture(r) for r in rows]

    async def capture(
        self, capture_id: str, *, workspace_id: str, who: str
    ) -> tuple[dict[str, Any], dict[str, Any]] | None:
        """(capture, its case), if ``who`` may see the case."""
        async with self.db.session() as s:
            row = await s.get(EvidenceCaptureRow, capture_id)
            case = await s.get(CaseRow, row.case_id) if row else None
        if row is None or case is None or case.workspace_id != workspace_id or not visible(case, who):
            return None
        return {**_capture(row), "manifest": row.manifest}, _case(case)

    async def file(self, capture_id: str, name: str, *, by: str, action: str) -> tuple[str, bytes] | None:
        async with self.db.session() as s, s.begin():
            row = await s.get(EvidenceFileRow, (capture_id, name))
            capture = await s.get(EvidenceCaptureRow, capture_id)
            if row is None or capture is None:
                return None
            await self._custody(s, capture, by, action, name)
            return row.media_type, row.data

    async def timestamp_token(self, capture_id: str) -> bytes | None:
        async with self.db.session() as s:
            row = await s.get(EvidenceCaptureRow, capture_id)
        return row.timestamp_token if row else None

    async def files(self, capture_id: str) -> dict[str, tuple[str, bytes]]:
        async with self.db.session() as s:
            rows = (await s.scalars(select(EvidenceFileRow).where(EvidenceFileRow.capture_id == capture_id))).all()
        return {r.name: (r.media_type, r.data) for r in rows}

    async def image_files(self, capture_ids: list[str]) -> list[tuple[str, str, bytes]]:
        """(capture id, name, data) of the images people added or captured (not Argus's own screenshots).

        For Argus's own reading (photo locations and dates on the map and timeline): not a viewing,
        so nothing is written to the custody log.
        """
        if not capture_ids:
            return []
        async with self.db.session() as s:
            rows = (await s.scalars(select(EvidenceFileRow).where(
                EvidenceFileRow.capture_id.in_(capture_ids), EvidenceFileRow.name != "screenshot.png",
                or_(EvidenceFileRow.media_type.like("image/%"),
                    *(func.lower(EvidenceFileRow.name).like(f"%.{ext}") for ext in ("jpg", "jpeg", "png", "tif", "tiff", "webp")))
            ))).all()  # fmt: skip
        return [(r.capture_id, r.name, r.data) for r in rows]

    async def log(self, capture_id: str, *, by: str, action: str, detail: str = "") -> None:
        async with self.db.session() as s, s.begin():
            row = await s.get(EvidenceCaptureRow, capture_id)
            if row is not None:
                await self._custody(s, row, by, action, detail)

    async def _custody(self, s: Any, capture: EvidenceCaptureRow, by: str, action: str, detail: str) -> None:
        last = await s.scalar(select(EvidenceCustodyRow).where(EvidenceCustodyRow.capture_id == capture.id)
                              .order_by(EvidenceCustodyRow.seq.desc()).limit(1))  # fmt: skip
        seq = (last.seq + 1) if last else 1
        prev = last.hash if last else GENESIS
        at = _now()
        detail = detail[:500]
        s.add(EvidenceCustodyRow(
            id=f"cus_{secrets.token_hex(8)}", capture_id=capture.id, seq=seq, at=at, by=by[:128], action=action,
            detail=detail, prev_hash=prev,
            hash=custody_hash(prev, seq, _iso(at) or "", by[:128], action, detail, capture.digest),
        ))  # fmt: skip

    async def custody(self, capture_id: str) -> list[dict[str, Any]]:
        async with self.db.session() as s:
            rows = (await s.scalars(select(EvidenceCustodyRow).where(EvidenceCustodyRow.capture_id == capture_id)
                                    .order_by(EvidenceCustodyRow.seq))).all()  # fmt: skip
        return [{"seq": r.seq, "at": _iso(r.at), "by": r.by, "action": r.action, "detail": r.detail,
                 "prev_hash": r.prev_hash, "hash": r.hash} for r in rows]  # fmt: skip

    async def verify(self, capture_id: str) -> dict[str, Any]:
        """Recompute every file hash, the manifest digest and the custody chain."""
        async with self.db.session() as s:
            row = await s.get(EvidenceCaptureRow, capture_id)
            stored = (await s.scalars(select(EvidenceFileRow).where(EvidenceFileRow.capture_id == capture_id))).all()
        if row is None:
            return {"intact": False, "problems": ["The capture does not exist"]}
        problems = []
        listed = {f["name"]: f["sha256"] for f in (row.manifest or {}).get("files", [])}
        present = {f.name: sha256(f.data) for f in stored}
        for name, expected in listed.items():
            if name not in present:
                problems.append(f"{name} is missing")
            elif present[name] != expected:
                problems.append(f"{name} has changed (its SHA-256 no longer matches the manifest)")
        problems += [f"{name} is not in the manifest" for name in present.keys() - listed.keys()]
        if sha256(canonical(row.manifest or {})) != row.digest:
            problems.append("The manifest no longer matches the recorded digest")
        prev = GENESIS
        for entry in await self.custody(capture_id):
            if entry["prev_hash"] != prev or entry["hash"] != custody_hash(
                prev, entry["seq"], entry["at"], entry["by"], entry["action"], entry["detail"], row.digest
            ):
                problems.append(f"Custody entry {entry['seq']} was altered or removed")
                break
            prev = entry["hash"]
        return {"intact": not problems, "problems": problems, "digest": row.digest, "files": len(present),
                "timestamped": row.timestamp_token is not None}  # fmt: skip
