"""Phase 103: researching a person from what is known, through the Python client."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from tests.test_subjects import KNOWN, PHOTO_HASH, Scans, _photo, _set_photo, sj  # noqa: F401

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "clients" / "python"))
from argus_client import ArgusClient, ValidationError


def test_a_person_researched_end_to_end_from_python(sj):  # noqa: F811
    c, scans, case_id = sj
    argus = ArgusClient(http=c)
    person = argus.add_person(case_id, "Jane Doe", names="Jane Doe", usernames=["@jdoe"], emails=["jane@example.org"],
                              city="Leeds", employer="Acme Logistics", birth_year=1984)  # fmt: skip
    pid = person["id"]
    assert person["known"]["names"] == ["Jane Doe"] and argus.people(case_id)[0]["id"] == pid
    assert argus.person_photo(case_id, pid, _photo())["known"]["photo_hash"]
    c.portal.call(_set_photo, c.app.state.subjects, pid, PHOTO_HASH)  # the fixtures' profile picture

    argus.search_person(case_id, pid, rounds=2)
    done = argus.wait_for_person(case_id, pid, poll=0.05, timeout=10)
    assert done["run"]["status"] == "completed" and "janed84" in scans.targets
    likely = argus.candidates(case_id, pid, verdicts=("likely",))
    assert likely and all(c["verdict"] == "likely" for c in likely)
    assert [c["score"] for c in likely] == sorted((c["score"] for c in likely), reverse=True)
    assert all(c["score"] >= 70 for c in argus.candidates(case_id, pid, min_score=70))

    github = next(c for c in likely if c["value"] == "https://github.com/jdoe")
    argus.confirm_candidate(case_id, pid, github["id"], note="checked the photo")
    reddit = next(c for c in argus.candidates(case_id, pid) if c["value"] == "https://reddit.com/user/jdoe")
    argus.reject_candidate(case_id, pid, reddit["id"])
    assert [c["value"] for c in argus.candidates(case_id, pid, status="rejected")] == [reddit["value"]]
    assert "https://github.com/jdoe" in argus.person(case_id, pid)["known"]["profiles"]
    argus.reopen_candidate(case_id, pid, reddit["id"])
    assert not argus.candidates(case_id, pid, status="rejected")

    after = argus.add_known(case_id, pid, phones="+44 7700 900123", city="York")
    assert after["known"]["phones"] == ["+447700900123"] and after["known"]["city"] == "York"
    assert after["known"]["usernames"] == ["jdoe"] and after["known"]["photo_hash"]  # nothing else lost
    assert argus.watch_person(case_id, pid)["watch"] is True
    assert argus.watch_person(case_id, pid, on=False)["watch"] is False
    with pytest.raises(ValidationError, match="children"):
        argus.add_person(case_id, "Kid", birth_year=2020)
    argus.remove_person(case_id, pid)
    assert argus.people(case_id) == []


def test_the_case_report_shows_what_was_known_and_confirmed_not_ruled_out(sj):  # noqa: F811
    c, _scans, case_id = sj
    argus = ArgusClient(http=c)
    pid = argus.add_person(case_id, "Jane Doe", **KNOWN)["id"]
    c.portal.call(_set_photo, c.app.state.subjects, pid, PHOTO_HASH)
    argus.search_person(case_id, pid, rounds=1)
    argus.wait_for_person(case_id, pid, poll=0.05, timeout=10)
    open_ = {x["value"]: x for x in argus.candidates(case_id, pid)}
    argus.confirm_candidate(case_id, pid, open_["https://github.com/jdoe"]["id"], note="Photo checked <by hand>")
    argus.reject_candidate(case_id, pid, open_["https://reddit.com/user/jdoe"]["id"])
    page = argus.case_report(case_id).decode()
    section = page[page.index("<h2>People researched</h2>") : page.index("<h2>Network</h2>")]
    assert "jane@example.org" in section and "Acme Logistics" in section and "1984" in section
    assert "https://github.com/jdoe" in section and "the same profile photo" in section
    assert "Photo checked &lt;by hand&gt;" in section  # escaped
    assert (
        "reddit.com" not in section and "1 ruled out (not listed" in section and "made directly" in section
    )  # other people's accounts stay out
    assert "only its fingerprint is kept" in section and PHOTO_HASH not in section
    assert "people researched" in page
