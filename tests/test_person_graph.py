"""The person's graph, and groups of accounts that seem to share an owner."""

from __future__ import annotations

from argus.intel import subjects as S
from tests.test_learning import INSTA, LearningScans
from tests.test_subjects import run, wait

PIC = "0f0f0f0f0f0f0f0f"


def cand(cid, status="open", **facts):
    avatar = facts.pop("avatar", None)
    found = facts.pop("found_from", [{"kind": "username", "value": "janedoe84"}])
    return {"id": cid, "key": f"profile:{cid}", "kind": "profile", "value": f"https://{cid}.example/janedoe84",
            "url": f"https://{cid}.example/janedoe84", "label": cid, "status": status, "avatar_hash": avatar,
            "grade": "probable", "facts": facts, "found_from": found, "score": 50, "verdict": "possible"}  # fmt: skip


def data():
    return {
        "known": S.clean_known({"names": ["Jane Doe"], "usernames": ["janedoe84"]}),
        "candidates": {
            "insta": cand("insta", "confirmed", avatar=PIC, display_name="Jane D",
                          bio="Night nurse, cyclist and baker in Leeds", links=["https://janedoe.dev"]),
            "tiktok": cand("tiktok", avatar=PIC),  # the same picture
            "blog": cand("blog", links=["https://insta.example/janedoe84"]),  # links to the confirmed account
            "shop": cand("shop", links=["https://janedoe.dev/shop"]),  # only a shared website: shown, not grouped
            "fan": cand("fan", bio="Night nurse cyclist baker fan page"),  # similar bio only
            "other": cand("other", avatar="f0f0f0f0f0f0f0f0", display_name="Someone Else"),
            "gone": cand("gone", "rejected", avatar=PIC),
        },
    }  # fmt: skip


def test_groups_of_accounts_that_share_an_owner():
    groups = S.clusters(data())
    main = groups[0]
    assert main["includes_confirmed"] and {m["id"] for m in main["members"]} == {"insta", "tiktok", "blog"}
    reasons = {(link["a"], link["b"]): link["reasons"] for link in main["links"]}
    assert "the same profile picture" in reasons[("insta", "tiktok")]
    assert "one links to the other" in reasons[("insta", "blog")]
    assert not any(m["id"] in ("shop", "fan", "other", "gone") for g in groups for m in g["members"])


def test_sharing_a_picture_or_a_link_with_a_confirmed_account_raises_the_score():
    d = data()
    before = S.score(d["candidates"]["tiktok"], d["known"])["score"]
    S.rescore(d["candidates"], d["known"])
    tiktok = d["candidates"]["tiktok"]
    assert any(
        r.startswith("shares the same profile picture with a confirmed account (insta)") for r in tiktok["agree"]
    )
    assert tiktok["score"] > before
    assert any("shares one links to the other" in r for r in d["candidates"]["blog"]["agree"])
    assert not any(r.startswith("shares") for r in d["candidates"]["shop"]["agree"])


def test_the_person_graph():
    g = S.graph("Jane Doe", data())
    nodes = {n["id"]: n for n in g["nodes"]}
    assert nodes["person"]["status"] == "subject" and "gone" not in nodes
    known_user = next(n for n in g["nodes"] if n["status"] == "known" and n["label"] == "janedoe84")
    assert {"source": known_user["id"], "target": "insta", "label": "confirmed"} in g["edges"]
    shared = [e for e in g["edges"] if e.get("kind") == "shared"]
    assert any({e["source"], e["target"]} == {"insta", "tiktok"} for e in shared)
    assert "site:janedoe.dev" in nodes and nodes["site:janedoe.dev"]["status"] == "shared"
    assert "gone" in {n["id"] for n in S.graph("Jane Doe", data(), include_rejected=True)["nodes"]}


def test_the_api(make_client):
    c = make_client(monitors_enabled="false")
    c.app.state.playbook_scan = LearningScans()
    case_id = c.post("/api/cases", json={"title": "F", "purpose": "Fraud report R-41", "confirmed": True}).json()["id"]
    sid = c.post(f"/api/cases/{case_id}/subjects", json={"name": "Jane Doe", "confirmed": True,
                 "known": {"names": ["Jane Doe"], "usernames": ["janedoe84"]}}).json()["id"]  # fmt: skip
    run(c, case_id, sid, rounds=1)
    insta = next(x for x in wait(c, case_id, sid)["candidates"] if x["value"] == INSTA)
    c.post(f"/api/cases/{case_id}/subjects/{sid}/candidates/{insta['id']}/confirm", json={})
    g = c.get(f"/api/cases/{case_id}/subjects/{sid}/graph").json()
    assert any(n["id"] == insta["id"] and n["status"] == "confirmed" for n in g["nodes"])
    assert c.get(f"/api/cases/{case_id}/subjects/{sid}/clusters").json() == {"groups": []}


def test_a_confirmed_account_is_drawn_once():
    d = data()
    d["known"] = S.add_to_known(d["known"], d["candidates"]["insta"])
    d["candidates"]["insta"]["key"] = S.key_of("profile", d["candidates"]["insta"]["value"])
    g = S.graph("Jane Doe", d)
    assert sum(1 for n in g["nodes"] if n["label"] in ("insta", d["candidates"]["insta"]["value"])) == 1
