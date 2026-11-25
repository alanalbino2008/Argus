"""Phase 88: the Python client polls cheaply (ETag / 304), reads TAXII collections and reports watch health."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from argus.core.models import EntityType, generate_entity_id
from argus.intel import internet_search
from tests.test_fingerprint_watches import _tick, _watch, watch_client  # noqa: F401
from tests.test_taxii import _fill, tc  # noqa: F401  (fixture used by name)

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "clients" / "python"))
from argus_client import ArgusClient


def test_polling_campaigns_reuses_unchanged_answers(tc):  # noqa: F811
    c, _ = tc
    _fill(c)
    argus = ArgusClient(http=c)
    first = argus.campaigns()
    assert argus.campaigns() == first and argus.not_modified == 1  # the server answered 304
    first[0]["name"] = "changed by the caller"  # what is remembered is a copy
    assert argus.campaigns()[0]["name"] != "changed by the caller" and argus.not_modified == 2
    tag = {"entity_type": "ip_address", "value": "203.0.113.5", "tags": ["c2"]}
    assert (
        c.put(f"/api/annotations/{generate_entity_id(EntityType.IP_ADDRESS, '203.0.113.5')}", json=tag).status_code
        == 200
    )
    argus.campaigns()
    assert argus.not_modified == 2  # the data changed: a full answer
    other = argus.in_workspace("ws_default")
    other.campaigns()
    assert other.not_modified == 0  # another workspace header is another answer, asked for in full


def test_reading_a_taxii_collection_page_by_page(tc):  # noqa: F811
    c, _ = tc
    _fill(c)
    argus = ArgusClient(http=c)
    assert argus.taxii_root() == "/taxii2/ws_default/"
    assert {col["alias"] for col in argus.taxii_collections()} == {"tagged", "lookalikes", "fingerprint-servers",
                                                                  "campaigns"}  # fmt: skip
    every = list(argus.taxii_objects("tagged"))
    paged = list(argus.taxii_objects("tagged", page_size=1))
    assert [o["id"] for o in paged] == [o["id"] for o in every] and len(every) >= 3
    assert {o["type"] for o in every} >= {"indicator", "identity"}
    newest = max(o.get("created", "") for o in every)
    assert list(argus.taxii_objects("tagged", added_after="2999-01-01T00:00:00Z")) == []
    assert newest
    list(argus.taxii_objects("tagged"))
    assert argus.not_modified >= 1  # an unchanged collection comes back as 304


def test_watch_health_and_run_now(watch_client):  # noqa: F811
    c, state = watch_client
    watch = _watch(c).json()
    argus = ArgusClient(http=c)
    state["fail"] = internet_search.SearchError(429, "Shodan is rate-limiting this key")
    _tick(c)
    for _ in range(2):
        argus.run_watch("fingerprint", watch["id"])
        _tick(c)
    (health,) = argus.watch_health()
    assert health["kind"] == "fingerprint" and health["failures"] == 3 and not health["paused"]
    assert "rate-limiting" in health["last_message"]
    state["fail"] = None
    argus.run_watch("fingerprint", watch["id"])
    _tick(c)
    assert argus.watch_health() == []
    argus.delete_watch("fingerprint", watch["id"])
    assert argus.fingerprint_watches() == []
    with pytest.raises(ValueError, match="brand"):
        argus.run_watch("monitor", "x")
