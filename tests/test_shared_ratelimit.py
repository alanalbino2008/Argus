"""Phase 86: named rate limits are counted in the database, so they hold across every replica."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from argus.security import ratelimit
from argus.security.ratelimit import SlidingWindowLimiter, estimate, wait_for
from argus.storage.db import Base, Database, RateLimitCounterRow


@pytest.fixture
async def db(tmp_path):
    database = Database(f"sqlite+aiosqlite:///{tmp_path / 'limits.db'}")
    async with database.engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    ratelimit.use_database(database)
    yield database
    ratelimit.use_memory()
    await database.engine.dispose()


async def test_two_replicas_share_one_limit(db):
    # Two processes each build their own limiter object with the same name: one budget between them.
    replica_a = SlidingWindowLimiter(limit=5, window=60, name="vault_unlock_test")
    replica_b = SlidingWindowLimiter(limit=5, window=60, name="vault_unlock_test")
    allowed = [await (replica_a if i % 2 else replica_b).allow("203.0.113.9") for i in range(8)]
    assert allowed == [True] * 5 + [False] * 3
    assert 1 <= replica_a.retry_after("203.0.113.9") <= 120 or 1 <= replica_b.retry_after("203.0.113.9") <= 120
    assert await replica_a.allow("198.51.100.1")  # another caller has its own budget
    async with db.session() as s:
        rows = (await s.scalars(select(RateLimitCounterRow))).all()
    assert {r.count for r in rows if r.name == "vault_unlock_test"} == {5, 1}  # refusals are not counted
    assert all("203.0.113.9" not in r.key for r in rows)  # addresses are stored hashed


async def test_unnamed_or_local_limiters_stay_in_memory(db):
    local = SlidingWindowLimiter(limit=1, window=60, name="api", shared=False)
    other = SlidingWindowLimiter(limit=1, window=60, name="api", shared=False)
    assert await local.allow("k") and await other.allow("k")  # separate counts
    async with db.session() as s:
        assert (await s.scalars(select(RateLimitCounterRow))).all() == []


async def test_a_broken_database_falls_back_to_memory(tmp_path):
    class Broken:
        dialect = "sqlite"

        def session(self):
            raise OSError("database is down")

    ratelimit.use_database(Broken())
    try:
        limiter = SlidingWindowLimiter(limit=2, window=60, name="login_test")
        assert [await limiter.allow("k") for _ in range(3)] == [True, True, False]
    finally:
        ratelimit.use_memory()


def test_the_sliding_estimate():
    assert estimate(10, 2, elapsed=30, window=60) == 7  # half of the previous window still counts
    assert estimate(10, 2, elapsed=60, window=60) == 2
    assert wait_for(0, 5, elapsed=10, window=60, limit=5) == 50  # next window: the previous one counts 5*(1-e/60)
    assert wait_for(8, 2, elapsed=30, window=60, limit=5) == 8  # 8*(1-t/60)+2 < 5 once t > 37.5: 8 s from now
    assert wait_for(8, 2, elapsed=30, window=60, limit=5) <= 120


def test_the_server_shares_its_limits(make_client):
    c = make_client()
    for _ in range(3):
        assert c.get("/api/campaigns").status_code == 200
    rows = c.portal.call(_rows, c.app.state.db)
    assert ("campaign_read", 3) in rows


async def _rows(db):
    async with db.session() as s:
        return [(r.name, r.count) for r in (await s.scalars(select(RateLimitCounterRow))).all()]
