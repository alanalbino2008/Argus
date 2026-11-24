"""Per-workspace data versions: a cheap way to know whether derived results are still current.

Campaigns and TAXII collections are computed from every lookalike, watched server and annotation of
a workspace. Each write to those raises the workspace's version (in the same transaction), so:

* a computed result is cached in memory under the version it was computed at, and reused while the
  version has not moved (:class:`VersionedCache`);
* responses carry an ETag derived from it, and a client that sends ``If-None-Match`` with the same
  value gets ``304 Not Modified`` without anything being read or computed.

Reading the version is one primary-key lookup. The counter is in the database, so a write on one
replica is seen by the others at once.
"""

from __future__ import annotations

import hashlib
from collections import OrderedDict
from typing import Any, cast

from sqlalchemy import Table, select
from sqlalchemy.ext.asyncio import AsyncSession

from argus.storage.db import Database, DataVersionRow


async def bump(s: AsyncSession, workspace_id: str) -> None:
    """Raise ``workspace_id``'s version inside the caller's transaction."""
    table = cast(Table, DataVersionRow.__table__)
    dialect = s.bind.dialect.name if s.bind is not None else "sqlite"
    if dialect == "postgresql":
        from sqlalchemy.dialects.postgresql import insert
    else:
        from sqlalchemy.dialects.sqlite import insert  # type: ignore[assignment]
    statement = insert(table).values(workspace_id=workspace_id, version=1)
    await s.execute(
        statement.on_conflict_do_update(index_elements=[table.c.workspace_id], set_={"version": table.c.version + 1})
    )


async def current(db: Database, workspace_id: str) -> int:
    async with db.session() as s:
        return int(
            await s.scalar(select(DataVersionRow.version).where(DataVersionRow.workspace_id == workspace_id)) or 0
        )


def etag(version: int, *parts: Any) -> str:
    """A weak ETag for a response computed from data at ``version`` (``parts``: the request's path, query…)."""
    from argus import __version__

    digest = hashlib.sha256("|".join(map(str, (__version__, version, *parts))).encode()).hexdigest()[:24]
    return f'W/"{digest}"'


def not_modified(if_none_match: str | None, tag: str) -> bool:
    if not if_none_match:
        return False
    if if_none_match.strip() == "*":
        return True
    plain = tag.removeprefix("W/")
    return any(candidate.strip().removeprefix("W/") == plain for candidate in if_none_match.split(","))


class VersionedCache:
    """The latest result per key, reused while its version is current. Bounded (least recently used)."""

    def __init__(self, maxsize: int = 64):
        self.maxsize = maxsize
        self._items: OrderedDict[Any, tuple[int, Any]] = OrderedDict()
        self.hits = self.misses = 0

    def get(self, key: Any, version: int) -> Any | None:
        item = self._items.get(key)
        if item is None or item[0] != version:
            self.misses += 1
            return None
        self._items.move_to_end(key)
        self.hits += 1
        return item[1]

    def put(self, key: Any, version: int, value: Any) -> None:
        self._items[key] = (version, value)
        self._items.move_to_end(key)
        while len(self._items) > self.maxsize:
            self._items.popitem(last=False)

    def clear(self) -> None:
        self._items.clear()
