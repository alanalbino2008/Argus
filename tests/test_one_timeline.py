"""One timeline: people's online lives on the case timeline, activity hours, gaps, and towns on the map."""

from __future__ import annotations

from argus.intel import subjects as S
from tests.test_learning import INSTA, LearningScans
from tests.test_person_overview import DATA
from tests.test_subjects import run, wait


def test_person_entries_join_the_case_timeline_with_their_precision():
    entries = S.case_timeline_entries("subj_1", "Jane Doe", DATA)
    first = entries[0]
    assert first["title"] == "Jane Doe: Born (per Insolvency notice: Jane Doe)" and first["precision"] == "year"
    assert first["kind"] == "person" and first["ref"]["type"] == "subject"
    assert any(e["precision"] == "month" and "First archived copy" in e["title"] for e in entries)


def test_activity_hours_and_gaps():
    data = {"known": S.clean_known({"utc_offset": "+00:00"}), "candidates": {
        "t": {"id": "t", "status": "confirmed", "kind": "profile", "value": "x", "label": "Telegram: jane",
              "facts": {"channel": {"post_hours_utc": {"22": 5, "23": 3, "9": 1}}, "created_at": "2015-03-01T22:10:00Z"}},
        "r": {"id": "r", "status": "confirmed", "kind": "record", "value": "y", "label": "Notice", "facts": {"date": "2019-06-01"}},
    }}  # fmt: skip
    a = S.activity(data)
    assert a["hours_utc"] == {"9": 1, "22": 6, "23": 3} and a["busiest_utc"][0] == 22 and a["samples"] == 10
    assert len(a["gaps"]) == 1 and a["gaps"][0]["from"] == "2015-03-01" and a["gaps"][0]["to"] == "2019-06-01"
    assert a["utc_offset"] == "+00:00"


def test_the_case_timeline_and_map_include_the_person(make_client):
    c = make_client(monitors_enabled="false")
    c.app.state.playbook_scan = LearningScans()
    case_id = c.post("/api/cases", json={"title": "F", "purpose": "Fraud report R-50", "confirmed": True}).json()["id"]
    sid = c.post(f"/api/cases/{case_id}/subjects", json={"name": "Jane Doe", "confirmed": True,
                 "known": {"names": ["Jane Doe"], "usernames": ["janedoe84"], "city": "York"}}).json()["id"]  # fmt: skip
    run(c, case_id, sid, rounds=1)
    insta = next(x for x in wait(c, case_id, sid)["candidates"] if x["value"] == INSTA)
    c.post(f"/api/cases/{case_id}/subjects/{sid}/candidates/{insta['id']}/confirm", json={})
    unplaced = {p["label"] for p in c.get(f"/api/cases/{case_id}/places").json()["unplaced"]}
    assert {"York", "Leeds"} <= unplaced  # the known town, and the confirmed account's town, to be looked up
    c.post(f"/api/cases/{case_id}/subjects/{sid}/candidates/{insta['id']}/confirm", json={})
    assert sorted(p["label"] for p in c.get(f"/api/cases/{case_id}/places").json()["unplaced"]) == ["Leeds", "York"]
    timeline = c.get(f"/api/cases/{case_id}/subjects/{sid}/timeline").json()
    assert set(timeline) == {"events", "contradictions", "activity"} and "gaps" in timeline["activity"]
    case_tl = c.get(f"/api/cases/{case_id}/timeline?facts=false").json()
    assert isinstance(case_tl, list)
