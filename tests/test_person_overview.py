"""The person's timeline, contradictions, connected people and the AI dossier."""

from __future__ import annotations

from argus.intel import subjects as S
from tests.test_learning import INSTA, LearningScans
from tests.test_subjects import run, wait


def cand(cid, status="confirmed", kind="profile", label=None, **facts):
    return {"id": cid, "key": f"k:{cid}", "kind": kind, "value": f"https://site.example/{cid}", "label": label or cid,
            "status": status, "url": f"https://site.example/{cid}", "facts": facts, "verdict": "likely", "score": 80}  # fmt: skip


DATA = {
    "known": S.clean_known({"names": ["Jane Doe"], "city": "Leeds", "birth_year": 1984, "utc_offset": "+00:00"}),
    "candidates": {
        "a": cand("a", label="X: janedoe84", created_at="2012-04-01T10:00:00Z", location="Leeds, UK",
                  archived={"first": "2013-01", "last": "2019-06"},
                  name_history=[{"date": "2013-01-02", "name": "Jane Smith"}, {"date": "2019-06-01", "name": "Jane Doe"}]),
        "b": cand("b", label="OpenAlex: Jane Doe", coauthors=["Ann Lee", "Bo Chan"], location="Manchester"),
        "c": cand("c", kind="record", label="Insolvency notice: Jane Doe", date="2020-01-02", born="1951"),
        "d": cand("d", status="open", label="TikTok: janed", created_at="2021-05-05"),
        "e": cand("e", label="Telegram: janedoe84", channel={"last_post": "2026-11-20T22:15:00+00:00"},
                  mentions=["leeds_nurses_uk"], timezone={"usual_offset": "-05:00"}),
        "f": cand("f", status="rejected", label="Reddit: jdoe", coauthors=["Not Shown"]),
    },
}  # fmt: skip


def test_the_timeline_of_their_online_life():
    events = S.timeline(DATA)
    titles = [(e["date"], e["title"]) for e in events]
    assert titles[0] == ("1951", "Born (per Insolvency notice: Jane Doe)")
    assert ("2012-04-01", "Account created: X: janedoe84") in titles
    assert ("2013-01", "First archived copy: X: janedoe84") in titles
    assert ("2019-06-01", 'Shown as "Jane Doe" (was "Jane Smith"): X: janedoe84') in titles
    assert any(t.startswith("Latest post in their Telegram channel") for _, t in titles)
    assert [d for d, _ in titles] == sorted(d for d, _ in titles)
    assert not any("TikTok" in t for _, t in titles)  # open candidates only when asked
    assert any("TikTok" in e["title"] for e in S.timeline(DATA, include_open=True))


def test_contradictions_between_confirmed_findings():
    found = {c["what"]: c["detail"] for c in S.contradictions(DATA)}
    assert "Leeds" in found["different towns"] and "Manchester" in found["different towns"]
    assert "1951" in found["different years of birth"] and "1984" in found["different years of birth"]
    assert "UTC-05:00" in found["different time zones"]
    assert (
        S.contradictions({"known": S.clean_known({"city": "Leeds"}), "candidates": {"a": DATA["candidates"]["a"]}})
        == []
    )


def test_other_people_are_listed_from_confirmed_findings_only():
    people = {p["name"]: p for p in S.associates(DATA)}
    assert set(people) == {"Ann Lee", "Bo Chan", "@leeds_nurses_uk"}  # not from the rejected candidate
    assert people["Ann Lee"]["relations"] == ["co-author"] and people["Ann Lee"]["via"] == ["OpenAlex: Jane Doe"]


def test_the_dossier_material_and_its_checks():
    material, sources = S.dossier_material("Jane Doe", DATA)
    assert "[K1] Name: Jane Doe" in material and "[C1]" in material and "[P1]" in material and "[T1]" in material
    assert "RULED OUT BY THE INVESTIGATOR: 1 (not listed)" in material and "Reddit" not in material
    assert "Ann Lee" not in material and "OTHER PEOPLE CONNECTED (not to be described): 3" in material
    assert "CONTRADICTIONS FOUND" in material
    p_ref = next(r for r, v in sources.items() if v["kind"] == "open")
    output = {"summary": "s", "gaps": [], "next_steps": [], "conflicts": [],
              "established": [{"finding": "Has a TikTok", "sources": [p_ref], "confidence": "confirmed"},
                              {"finding": "Lives in Leeds", "sources": ["K1", "Z9"], "confidence": "confirmed"},
                              {"finding": "Invented", "sources": ["Q7"], "confidence": "likely"}],
              "likely": []}  # fmt: skip
    checked = S.check_dossier(output, sources)["established"]
    assert checked[0]["confidence"] == "possible" and checked[0]["downgraded"]  # an open candidate is not established
    assert [s["ref"] for s in checked[1]["sources"]] == ["K1"] and not checked[1]["unsupported"]
    assert checked[2]["unsupported"]


def test_the_api(make_client, monkeypatch):
    from argus.accounts import connect_client

    c = make_client(monitors_enabled="false")
    c.app.state.playbook_scan = LearningScans()
    case_id = c.post("/api/cases", json={"title": "F", "purpose": "Fraud report R-30", "confirmed": True}).json()["id"]
    sid = c.post(f"/api/cases/{case_id}/subjects", json={"name": "Jane Doe", "confirmed": True,
                 "known": {"names": ["Jane Doe"], "usernames": ["janedoe84"]}}).json()["id"]  # fmt: skip
    run(c, case_id, sid, rounds=1)
    insta = next(x for x in wait(c, case_id, sid)["candidates"] if x["value"] == INSTA)
    c.post(f"/api/cases/{case_id}/subjects/{sid}/candidates/{insta['id']}/confirm", json={})
    base = f"/api/cases/{case_id}/subjects/{sid}"
    assert set(c.get(f"{base}/timeline").json()) == {"events", "contradictions"}
    assert "not the subject" in c.get(f"{base}/associates").json()["note"]

    assert c.post(f"{base}/dossier", json={"ai_acknowledged": False}).status_code == 428
    monkeypatch.setattr(connect_client, "ai_access", lambda: None)
    assert c.post(f"{base}/dossier", json={"ai_acknowledged": True}).status_code == 503

    sent = {}

    async def fake_ai(task, material):
        sent.update(task=task, material=material)
        return {"output": {"summary": "Jane Doe, a nurse in Leeds.", "gaps": ["No employer confirmed"],
                           "next_steps": [{"action": "Check the register", "why": "Employer", "how": "Companies House"}],
                           "established": [{"finding": "Uses Instagram as janedoe84", "sources": ["C1"],
                                            "confidence": "confirmed"}], "likely": [], "conflicts": []},
                "model": "test-model", "via": "own_key", "credits": None}  # fmt: skip

    monkeypatch.setattr(connect_client, "ai_access", lambda: "own_key")
    monkeypatch.setattr(connect_client, "ai", fake_ai)
    made = c.post(f"{base}/dossier", json={"ai_acknowledged": True})
    assert made.status_code == 200, made.text
    assert sent["task"] == "dossier" and "PERSON: Jane Doe" in sent["material"] and INSTA in sent["material"]
    result = made.json()["result"]
    assert result["established"][0]["sources"][0]["ref"] == "C1"
    assert c.get(f"{base}/dossier").json()["result"]["summary"] == "Jane Doe, a nurse in Leeds."
    entry = next(
        e for e in c.get("/api/audit?limit=50").json() if e["action"] == "subject.dossier" and e["outcome"] == "success"
    )
    assert entry["details"]["via"] == "own_key" and entry["details"]["characters"] > 0


def test_the_dossier_is_an_analyst_task():
    from argus.intel import analyst

    assert "dossier" in analyst.TASKS and analyst.BASE_CREDITS["dossier"] and analyst.SCHEMAS["dossier"]
    assert "never call an open candidate confirmed" in analyst.TASK_PROMPTS["dossier"]


def test_coauthors_come_from_the_authors_works():
    from argus.modules.identity.public_records import coauthors

    works = {"results": [
        {"authorships": [{"author": {"display_name": "Jane Doe"}}, {"author": {"display_name": "Ann Lee"}}]},
        {"authorships": [{"author": {"display_name": "J. Doe"}}, {"author": {"display_name": "Ann Lee"}},
                         {"author": {"display_name": "Bo Chan"}}]}]}  # fmt: skip
    assert coauthors(works, "Jane Doe") == ["Ann Lee", "Bo Chan"]
