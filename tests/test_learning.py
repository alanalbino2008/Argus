"""Learning from confirmed accounts: suggested details, ticked by the investigator, then searched."""

from __future__ import annotations

from argus.core.graph import IntelligenceGraph
from argus.core.models import Entity, EntityType
from argus.intel import subjects as S
from tests.test_subjects import Scans, profile, run, wait

E = EntityType
INSTA = "https://www.instagram.com/janedoe84"


def graph_for(target: str) -> IntelligenceGraph:
    g = IntelligenceGraph(target)
    g.add_entity(Entity.create(E.USERNAME, target), is_seed=True)
    if target == "janedoe84":
        g.add_entity(profile(INSTA, name="Jane Doe-Smith", location="Leeds, UK",
                             bio="Nurse. Bookings: hello@janedoe.dev | also tiktok.com/@janed_x",
                             links=["https://janedoe.dev", "https://linktr.ee/janedoe", "https://x.com/janed_x"],
                             public_phone="+44 7700 900123"))  # fmt: skip
    return g


class LearningScans(Scans):
    async def __call__(self, app, config, *, by, purpose, workspace_id, egress):
        self.targets.append(config.target)
        self.configs.append(config)
        return f"inv-{len(self.targets)}", graph_for(config.target)


def test_what_a_confirmed_account_suggests():
    known = S.clean_known({"names": ["Jane Doe"], "usernames": ["janedoe84"], "profiles": ["https://x.com/janed_x"]})
    cand = {"id": "c_1", "kind": "profile", "value": INSTA, "label": "Instagram: janedoe84",
            "facts": {"display_name": "Jane Doe-Smith", "location": "Leeds, UK", "company": "St James's Hospital",
                      "bio": "Nurse. Bookings: hello@janedoe.dev | also tiktok.com/@janed_x | www.janedoe.dev/blog",
                      "links": ["https://janedoe.dev", "https://linktr.ee/janedoe", "https://x.com/janed_x", INSTA],
                      "public_phone": "+44 7700 900123"}}  # fmt: skip
    found = {(s["field"], s["value"]) for s in S.suggestions(cand, known)}
    assert found == {
        ("names", "Jane Doe-Smith"), ("city", "Leeds"), ("employer", "St James's Hospital"),
        ("websites", "https://janedoe.dev"), ("websites", "https://www.janedoe.dev/blog"),
        ("profiles", "https://tiktok.com/@janed_x"), ("emails", "hello@janedoe.dev"), ("phones", "+447700900123"),
    }  # fmt: skip
    # Not suggested: what is already known (the X account), link pages (linktr.ee) and the account itself.
    learned = S.accept_suggestions(known, [s for s in S.suggestions(cand, known) if s["field"] in ("city", "emails")])
    assert learned["city"] == "Leeds" and learned["emails"] == ["hello@janedoe.dev"]
    assert S.suggestions({**cand, "facts": {"display_name": "Jane Doe"}}, known) == []  # the same name: nothing new


def test_confirm_review_accept_and_search(make_client):
    c = make_client(monitors_enabled="false")
    scans = LearningScans()
    c.app.state.playbook_scan = scans
    case_id = c.post("/api/cases", json={"title": "F", "purpose": "Fraud report R-20", "confirmed": True}).json()["id"]
    sid = c.post(f"/api/cases/{case_id}/subjects", json={"name": "Jane Doe", "confirmed": True,
                 "known": {"names": ["Jane Doe"], "usernames": ["janedoe84"]}}).json()["id"]  # fmt: skip
    assert run(c, case_id, sid, rounds=1).status_code == 202
    done = wait(c, case_id, sid)
    insta = next(x for x in done["candidates"] if x["value"] == INSTA)

    after = c.post(
        f"/api/cases/{case_id}/subjects/{sid}/candidates/{insta['id']}/confirm", json={"search": True}
    ).json()
    pending = {x["field"]: x for x in after["suggestions"]}
    assert {"names", "city", "websites", "emails", "phones", "profiles"} <= set(pending)
    assert all(x["from"] == insta["label"] and x["status"] == "pending" for x in after["suggestions"])
    # Confirming searched what became known (the profile itself) straight away.
    wait(c, case_id, sid)
    assert INSTA in scans.targets

    # Dismiss the phone number, accept the website and the email address: they are searched at once.
    c.post(f"/api/cases/{case_id}/subjects/{sid}/suggestions/dismiss", json={"ids": [pending["phones"]["id"]]})
    take = [x["id"] for x in after["suggestions"] if x["field"] in ("websites", "emails")]
    accepted = c.post(f"/api/cases/{case_id}/subjects/{sid}/suggestions/accept", json={"ids": take}).json()
    assert accepted["known"]["emails"] == ["hello@janedoe.dev"] and accepted["known"]["websites"]
    assert not any(x["id"] in take for x in accepted["suggestions"])
    wait(c, case_id, sid)
    assert "hello@janedoe.dev" in scans.targets and "janedoe.dev" in scans.targets
    # Confirming again never brings back what was dismissed or accepted.
    again = c.post(f"/api/cases/{case_id}/subjects/{sid}/candidates/{insta['id']}/confirm", json={}).json()
    assert {x["field"] for x in again["suggestions"]} == {x["field"] for x in accepted["suggestions"]}
    assert "phones" not in {x["field"] for x in again["suggestions"]}
    assert (
        c.post(f"/api/cases/{case_id}/subjects/{sid}/suggestions/accept", json={"ids": ["s_nope"]}).status_code == 404
    )
    assert "subject.learn" in {e["action"] for e in c.get("/api/audit?limit=100").json()}


def test_details_accepted_during_a_search_are_searched_by_it(make_client):
    import threading

    c = make_client(monitors_enabled="false")
    gate = threading.Event()

    class Slow(LearningScans):
        async def __call__(self, app, config, *, by, purpose, workspace_id, egress):
            import asyncio

            if not self.targets:
                await asyncio.to_thread(gate.wait, 10)
            return await super().__call__(app, config, by=by, purpose=purpose, workspace_id=workspace_id, egress=egress)

    scans = Slow()
    c.app.state.playbook_scan = scans
    case_id = c.post("/api/cases", json={"title": "F", "purpose": "Fraud report R-21", "confirmed": True}).json()["id"]
    sid = c.post(f"/api/cases/{case_id}/subjects", json={"name": "Jane", "confirmed": True,
                 "known": {"usernames": ["janedoe84"]}}).json()["id"]  # fmt: skip
    assert run(c, case_id, sid, rounds=1).status_code == 202
    updated = c.put(f"/api/cases/{case_id}/subjects/{sid}", json={"known": {"usernames": ["janedoe84"],
                                                                            "emails": ["jane@doe.family"]}})  # fmt: skip
    assert updated.status_code == 200
    gate.set()
    done = wait(c, case_id, sid)
    assert done["run"]["status"] == "completed" and "jane@doe.family" in scans.targets
