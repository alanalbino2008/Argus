"""Phase 86: named rate limits are counted in the database, so they hold across every replica."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from argus.security import ratelimit
from argus.security.ratelimit import SlidingWindowLimiter, bucket_size, in_window, wait_for
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
    per_caller: dict[str, int] = {}
    for r in rows:
        if r.name == "vault_unlock_test":  # a caller's calls can fall into two time buckets: add them up
            per_caller[r.key] = per_caller.get(r.key, 0) + r.count
    assert sorted(per_caller.values()) == [1, 5]  # refusals are not counted
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


def test_the_exact_count_never_undercounts_at_a_boundary():
    assert bucket_size(60) == 1 and bucket_size(3600) == 60 and bucket_size(5) == 1
    now = 1_000_030.5
    # Ten attempts in the last seconds of one minute, the eleventh at the start of the next: still refused.
    late = [(1_000_000 - i, 1) for i in range(1, 11)]
    assert in_window([*late, (1_000_030, 1)], now, 60) == 11
    assert in_window([(999_960, 4)], now, 60) == 0  # long gone
    assert in_window([(999_970, 4)], now, 60) == 4  # the bucket the window's start falls in counts in full
    # Waiting: the oldest attempts must leave the window first.
    assert wait_for([(999_990, 5), (1_000_020, 5)], now, 60, 10) == 21  # 999_991 + 60 - now
    assert wait_for([(1_000_030, 1)], now, 60, 5) >= 1


async def test_a_burst_across_a_minute_boundary_is_held_to_the_limit(monkeypatch, db):
    """The CI failure: a slow burst straddling a minute boundary let an 11th attempt through."""
    from argus.security import ratelimit as rl

    clock = {"t": 1_000_050.0}
    monkeypatch.setattr(rl.time, "time", lambda: clock["t"])
    limiter = SlidingWindowLimiter(limit=10, window=60, name="boundary_test")
    results = []
    for _ in range(11):
        results.append(await limiter.allow("k"))
        clock["t"] += 2.6  # one report every 2.6 s, crossing the minute at 1_000_080
    assert results == [True] * 10 + [False]
    assert 1 <= limiter.retry_after("k") <= 60
    clock["t"] = 1_000_050.0 + 61  # a minute after the first attempt: room again
    assert await limiter.allow("k")


def test_the_server_shares_its_limits(make_client):
    c = make_client()
    for _ in range(3):
        assert c.get("/api/campaigns").status_code == 200
    rows = c.portal.call(_rows, c.app.state.db)
    assert ("campaign_read", 3) in rows


async def _rows(db):
    async with db.session() as s:
        return [(r.name, r.count) for r in (await s.scalars(select(RateLimitCounterRow))).all()]
