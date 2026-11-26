"""Phase 101: known details about a person, one run from all of them, scored candidates, confirm and reject."""

from __future__ import annotations

import asyncio
import io
import threading
import time

import pytest
from PIL import Image

from argus.core.graph import IntelligenceGraph
from argus.core.models import Entity, EntityType, Relation, RelationType
from argus.intel import subjects as S
from argus.intel.avatars import fingerprint

PHOTO_HASH = "0f0f0f0f0f0f0f0f"


def _photo() -> bytes:
    img = Image.new("L", (64, 64))
    img.putdata([(x * 4 + (y // 8) * 30) % 256 for y in range(64) for x in range(64)])
    buf = io.BytesIO()
    img.save(buf, "PNG")
    return buf.getvalue()


def profile(url, *, name="", location="", bio="", links=(), avatar=None, confidence=0.9, source="profile_enricher",
            depth=1, **md):  # fmt: skip
    meta = {"platform": url.split("/")[2], "profile": {"display_name": name, "location": location, "bio": bio,
                                                       "links": list(links)}, **md}  # fmt: skip
    if avatar:
        meta["avatar_hash"] = avatar
    return Entity.create(EntityType.SOCIAL_PROFILE, url, metadata=meta, source_module=source, confidence=confidence,
                         depth=depth)  # fmt: skip


def graph_for(target: str) -> IntelligenceGraph:
    g = IntelligenceGraph(target)
    if target == "jdoe":
        g.add_entity(Entity.create(EntityType.USERNAME, "jdoe"), is_seed=True)
        for e in (
            # Same photo, name and town as the known details: very likely theirs.
            profile(
                "https://github.com/jdoe",
                name="Jane Doe",
                location="Leeds, UK",
                avatar=PHOTO_HASH,
                bio="Engineer at Acme Logistics",
                links=["https://janedoe.dev"],
            ),
            # Same handle, a different person.
            profile(
                "https://reddit.com/user/jdoe",
                name="John Dorian",
                location="San Francisco",
                source="username_hunter",
                confidence=0.6,
            ),
            # A bare hit: the handle exists there, nothing else known.
            profile("https://example.social/jdoe", source="username_hunter", confidence=0.6),
        ):
            g.add_entity(e)
    elif target == "jane@example.org":
        g.add_entity(Entity.create(EntityType.EMAIL, target), is_seed=True)
        g.add_entity(Entity.create(EntityType.USERNAME, "janed84", depth=1, source_module="email_recon"))
        g.add_entity(profile("https://gravatar.com/janed84", name="Jane Doe", location="Leeds", source="email_recon",
                             links=["https://github.com/jdoe"]))  # fmt: skip
    elif target == "Jane Doe":
        person = Entity.create(
            EntityType.PERSON, "Jane Doe", metadata={"born": "1951-02"}, source_module="companies_house"
        )
        org = Entity.create(EntityType.ORGANIZATION, "Doe Antiques Ltd", depth=1)
        g.add_entity(person, is_seed=True)
        g.add_entity(org)
        g.add_relation(Relation.create(person.id, org.id, RelationType.OFFICER_OF))
    elif target == "janed84":  # followed automatically from the confirmed-looking gravatar
        g.add_entity(Entity.create(EntityType.USERNAME, "janed84"), is_seed=True)
        g.add_entity(profile("https://twitter.com/janed84", name="Jane Doe", location="Leeds", avatar=PHOTO_HASH))
    return g


class Scans:
    def __init__(self, hold: bool = False):
        self.targets: list[str] = []
        self.configs: list = []
        self.hold, self.release = hold, threading.Event()

    async def __call__(self, app, config, *, by, purpose, workspace_id, egress):
        self.targets.append(config.target)
        self.configs.append(config)
        if self.hold:
            await asyncio.to_thread(self.release.wait, 10)
        return f"inv-{len(self.targets)}", graph_for(config.target)


@pytest.fixture
def sj(make_client):
    c = make_client(monitors_enabled="false")
    scans = Scans()
    c.app.state.playbook_scan = scans
    case = c.post(
        "/api/cases", json={"title": "Fraud", "purpose": "Romance fraud report R-17", "confirmed": True}
    ).json()
    return c, scans, case["id"]


KNOWN = {"names": ["Jane Doe"], "usernames": ["@jdoe"], "emails": ["jane@example.org"], "city": "Leeds",
         "employer": "Acme Logistics", "birth_year": 1984, "profiles": ["https://janedoe.dev/about"]}  # fmt: skip


def create(c, case_id, known=KNOWN, **extra):
    return c.post(
        f"/api/cases/{case_id}/subjects", json={"name": "Jane Doe", "known": known, "confirmed": True, **extra}
    )


def wait(c, case_id, sid, seconds=10.0):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        subject = c.get(f"/api/cases/{case_id}/subjects/{sid}").json()
        if subject["status"] != "running":
            return subject
        time.sleep(0.05)
    raise AssertionError(subject["run"])


def run(c, case_id, sid, **body):
    return c.post(f"/api/cases/{case_id}/subjects/{sid}/run", json={"confirmed": True, **body})


# ---------------------------------------------------------------------------- the rules
def test_known_details_are_checked_and_tidied():
    known = S.clean_known({"usernames": ["@jdoe", "JDoe"], "phones": ["+44 7700 900 123"],
                           "profiles": ["github.com/jdoe"], "birth_year": "1984"})  # fmt: skip
    assert known["usernames"] == ["jdoe"] and known["phones"] == ["+447700900123"]
    assert known["profiles"] == ["https://github.com/jdoe"] and known["birth_year"] == 1984
    for bad, why in (({"emails": ["nope"]}, "not an email"), ({"phones": ["12"]}, "country code"),
                     ({"birth_year": S._now().year - 12}, "children"), ({"profiles": ["not a link"]}, "web address")):  # fmt: skip
        with pytest.raises(S.KnownDetailsError, match=why):
            S.clean_known(bad)
    assert (
        S.handle_from_url("https://x.com/@jdoe") == "jdoe"
        and S.handle_from_url("https://reddit.com/user/jdoe") == "jdoe"
    )
    assert S.handle_from_url("https://www.linkedin.com/in/jane-doe-123") is None


def test_what_a_run_searches():
    known = S.clean_known({**KNOWN, "profiles": ["https://github.com/jdoe", "https://gitlab.com/jane-d"]})
    found = S.searches(known, set())
    assert [(s["kind"], s["value"]) for s in found] == [
        ("name", "Jane Doe"),
        ("username", "jdoe"),
        ("profile", "https://github.com/jdoe"),
        ("profile", "https://gitlab.com/jane-d"),
        ("username", "jane-d"),
        ("email", "jane@example.org"),
    ]
    assert S.searches(known, {s["key"] for s in found}) == []  # already searched: nothing again


def test_candidates_are_scored_against_what_is_known():
    known = S.clean_known({**KNOWN, "photo_hash": PHOTO_HASH})
    search = {"kind": "username", "value": "jdoe"}
    by_url = {c["value"]: c for c in S.from_graph(graph_for("jdoe"), search, "inv-1")}
    for cand in by_url.values():
        cand.update(S.score(cand, known))
    github = by_url["https://github.com/jdoe"]
    assert github["verdict"] == "likely" and github["score"] >= S.AUTO_FOLLOW
    assert {"the same profile photo", "the same name (Jane Doe)"} <= set(github["agree"])
    reddit = by_url["https://reddit.com/user/jdoe"]
    assert reddit["verdict"] == "unlikely" and any("different names" in r for r in reddit["conflict"])
    assert by_url["https://example.social/jdoe"]["verdict"] == "weak"
    record = S.from_graph(graph_for("Jane Doe"), {"kind": "name", "value": "Jane Doe"}, "inv-2")[0]
    record.update(S.score(record, known))
    assert record["kind"] == "record" and "born in 1951, not 1984" in record["conflict"]
    assert record["verdict"] == "unlikely"  # the same name, but a contradiction outweighs it


# ---------------------------------------------------------------------------- in a case
def test_one_run_from_everything_known_then_review(sj):
    c, scans, case_id = sj
    subject = create(c, case_id).json()
    sid = subject["id"]
    assert subject["known"]["usernames"] == ["jdoe"] and subject["status"] == "idle"
    photo = c.post(f"/api/cases/{case_id}/subjects/{sid}/photo", files={"file": ("me.png", _photo(), "image/png")})
    assert photo.status_code == 200 and photo.json()["known"]["photo_hash"] == fingerprint(_photo())
    # Use a photo hash matching the fixtures' profile pictures.
    c.put(f"/api/cases/{case_id}/subjects/{sid}", json={"known": KNOWN})
    c.portal.call(_set_photo, c.app.state.subjects, sid, PHOTO_HASH)

    assert run(c, case_id, sid).status_code == 202
    done = wait(c, case_id, sid)
    assert done["run"]["status"] == "completed", done["run"]
    # Every known detail was searched once, then the very good new match's handle (round 2).
    assert scans.targets[:4] == ["Jane Doe", "jdoe", "janedoe.dev", "jane@example.org"] or set(scans.targets) >= {
        "Jane Doe", "jdoe", "jane@example.org"}  # fmt: skip
    assert "janed84" in scans.targets and done["run"]["steps"][-1]["round"] == 2
    assert all(cfg.handle_variants for cfg in scans.configs if cfg.target == "jdoe")
    cands = {cand["value"]: cand for cand in done["candidates"]}
    assert "jdoe" not in cands and "jane@example.org" not in cands  # known details are not candidates
    assert cands["https://github.com/jdoe"]["verdict"] == "likely"
    assert cands["https://twitter.com/janed84"]["found_from"][0]["value"] == "janed84"
    assert done["candidates"][0]["verdict"] == "likely"  # best first
    assert done["counts"]["open"] == len(done["candidates"])

    # Confirm the GitHub account: it becomes a known detail and goes into the case.
    gh = cands["https://github.com/jdoe"]
    after = c.post(f"/api/cases/{case_id}/subjects/{sid}/candidates/{gh['id']}/confirm", json={"note": "same photo"})
    assert after.status_code == 200 and "https://github.com/jdoe" in after.json()["known"]["profiles"]
    items = c.get(f"/api/cases/{case_id}").json()["items"]
    entity = next(i for i in items if i["kind"] == "entity" and i["data"]["value"] == "https://github.com/jdoe")
    assert entity["data"]["type"] == "account" and "same photo" in entity["body"]

    # Reject the namesake: never suggested again, even after searching from scratch.
    reddit = cands["https://reddit.com/user/jdoe"]
    c.post(f"/api/cases/{case_id}/subjects/{sid}/candidates/{reddit['id']}/reject", json={})
    assert run(c, case_id, sid).status_code == 202  # only the newly confirmed profile (its archived copies)
    wait(c, case_id, sid)
    assert scans.targets[-1] == "https://github.com/jdoe"
    assert run(c, case_id, sid).status_code == 409  # now everything known has been searched
    assert run(c, case_id, sid, fresh=True, rounds=1).status_code == 202
    again = wait(c, case_id, sid)
    statuses = {cand["value"]: cand["status"] for cand in again["candidates"]}
    assert statuses["https://reddit.com/user/jdoe"] == "rejected" and statuses["https://github.com/jdoe"] == "confirmed"
    reopened = c.post(f"/api/cases/{case_id}/subjects/{sid}/candidates/{reddit['id']}/reopen")
    assert {x["value"]: x["status"] for x in reopened.json()["candidates"]}["https://reddit.com/user/jdoe"] == "open"
    actions = {e["action"] for e in c.get("/api/audit?limit=200").json()}
    assert {"subject.create", "subject.run", "subject.confirm", "subject.reject", "scan.start"} <= actions


async def _set_photo(repo, sid, digest):
    def apply(row, data):
        data["known"] = {**data["known"], "photo_hash": digest}

    await repo.change(sid, apply)


def test_safeguards(sj):
    c, scans, case_id = sj
    assert c.post(f"/api/cases/{case_id}/subjects", json={"name": "X", "confirmed": False}).status_code == 422
    child = create(c, case_id, known={"names": ["Kid"], "birth_year": S._now().year - 10})
    assert child.status_code == 422 and "children" in child.json()["detail"]
    sid = create(c, case_id, known={"usernames": ["jdoe"]}).json()["id"]
    assert c.post(f"/api/cases/{case_id}/subjects/{sid}/run", json={"confirmed": False}).status_code == 422
    blank = c.post(
        f"/api/cases/{case_id}/subjects/{sid}/photo", files={"file": ("x.png", b"not an image", "image/png")}
    )
    assert blank.status_code == 422
    # Another workspace's case is not reachable, and a viewer cannot run anything.
    viewer = c.post("/api/keys", json={"name": "v", "role": "viewer"}).json()["key"]
    as_viewer = {"Authorization": f"Bearer {viewer}"}
    assert c.get(f"/api/cases/{case_id}/subjects/{sid}", headers=as_viewer).status_code == 200
    assert (
        c.post(f"/api/cases/{case_id}/subjects/{sid}/run", json={"confirmed": True}, headers=as_viewer).status_code
        == 403
    )
    # A closed case cannot be searched from.
    c.patch(f"/api/cases/{case_id}", json={"status": "closed"})
    assert run(c, case_id, sid).status_code == 409
    assert scans.targets == []


def test_one_run_at_a_time_and_it_can_be_stopped(make_client):
    c = make_client(monitors_enabled="false")
    scans = Scans(hold=True)
    c.app.state.playbook_scan = scans
    case_id = c.post("/api/cases", json={"title": "F", "purpose": "Fraud report R-18", "confirmed": True}).json()["id"]
    sid = create(c, case_id).json()["id"]
    assert run(c, case_id, sid).status_code == 202
    assert run(c, case_id, sid).status_code == 409
    stopped = c.post(f"/api/cases/{case_id}/subjects/{sid}/run/cancel")
    assert stopped.status_code == 200 and stopped.json()["run"]["status"] == "cancelled"
    scans.release.set()
    done = wait(c, case_id, sid)
    assert done["run"]["status"] == "cancelled" and len(scans.targets) == 1  # nothing after the running scan
    assert c.post(f"/api/cases/{case_id}/subjects/{sid}/run/cancel").status_code == 409


def test_an_anonymous_case_searches_passively_through_its_route(make_client):
    import json

    routes = [{"name": "tor", "kind": "tor", "url": "http://127.0.0.1:9", "description": "Tor"}]
    c = make_client(monitors_enabled="false", egress_routes=json.dumps(routes))
    scans = Scans()
    c.app.state.playbook_scan = scans
    case = c.post("/api/cases", json={"title": "Anon", "purpose": "Source protection test", "confirmed": True,
                                      "opsec_mode": "anonymous", "egress": "tor"})  # fmt: skip
    assert case.status_code == 201, case.text
    case_id = case.json()["id"]
    sid = create(c, case_id, known={"usernames": ["jdoe"]}).json()["id"]
    assert run(c, case_id, sid, rounds=1).status_code == 202
    done = wait(c, case_id, sid)
    assert done["run"]["route"] == "tor" and done["run"]["passive_only"]
    assert scans.configs and all(cfg.passive_only for cfg in scans.configs)


async def _make_due(db, sid):
    from datetime import datetime, timedelta, timezone

    from sqlalchemy import update

    from argus.storage.db import SubjectRow

    async with db.session() as s, s.begin():
        await s.execute(update(SubjectRow).where(SubjectRow.id == sid)
                        .values(next_watch_at=datetime.now(timezone.utc) - timedelta(minutes=1)))  # fmt: skip


def test_the_weekly_watch_searches_again_and_alerts_without_naming_anyone(sj):
    from argus.api import subject_routes

    c, _scans, case_id = sj
    sid = create(c, case_id, known={**KNOWN, "photo_hash": None}).json()["id"]
    on = c.put(f"/api/cases/{case_id}/subjects/{sid}/watch", json={"on": True}).json()
    assert on["watch"] and on["next_watch_at"]
    assert c.get("/api/quota").json()["resources"]["watches"]["used"] == 1  # counts towards the workspace's limit
    assert c.portal.call(subject_routes.watch_tick, c.app) == []  # not due yet
    c.portal.call(_make_due, c.app.state.db, sid)
    assert c.portal.call(subject_routes.watch_tick, c.app) == [sid]
    assert c.portal.call(subject_routes.watch_tick, c.app) == []  # claimed: runs once
    done = wait(c, case_id, sid)
    assert done["run"]["reason"] == "watch" and done["last_watch"]["outcome"] == "started"
    alerts = c.get("/api/alerts").json()
    alerts = alerts.get("alerts", alerts) if isinstance(alerts, dict) else alerts
    alert = next(a for a in alerts if a["headline"].startswith("Known-details watch"))
    text = str(alert)
    assert "Jane" not in text and "jdoe" not in text and "github" not in text  # alerts travel to chat and email
    # A closed case stops its watches.
    c.portal.call(_make_due, c.app.state.db, sid)
    c.patch(f"/api/cases/{case_id}", json={"status": "closed"})
    c.portal.call(subject_routes.watch_tick, c.app)
    after = c.get(f"/api/cases/{case_id}/subjects/{sid}").json()
    assert not after["watch"] and after["last_watch"]["outcome"] == "stopped"
