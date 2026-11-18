"""Relationships over time, and the link chart and profiles exported for editors and courts."""

from __future__ import annotations

import base64
import io

from PIL import Image
from pypdf import PdfReader

from argus.intel.relationships import edges_at
from tests.test_cases import new_case


def test_relationships_on_a_given_date():
    edges = [{"id": "a", "since": "2015", "until": "2019-06"}, {"id": "b", "since": "2019-03-14"},
             {"id": "c"}, {"id": "d", "until": "2010"}]  # fmt: skip
    ids = lambda when, **kw: [e["id"] for e in edges_at(edges, when, **kw)]  # noqa: E731
    assert ids("2009") == ["c", "d"] and ids("2014") == ["c"] and ids("2015") == ["a", "c"]
    assert ids("2019-04") == ["a", "b", "c"]  # "until 2019-06" lasts to the end of June
    assert ids("2019-07-01") == ["b", "c"] and ids("2019-07-01", undated=False) == ["b"]


def png(colour="red") -> str:
    buf = io.BytesIO()
    Image.new("RGB", (600, 400), colour).save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()


def text_of(pdf: bytes) -> str:
    return "\n".join(page.extract_text() or "" for page in PdfReader(io.BytesIO(pdf)).pages)


def setup(client):
    case = new_case(client, title="Hope Relief network").json()
    add = lambda kind, **kw: client.post(f"/api/cases/{case['id']}/items", json={"kind": kind, **kw}).json()  # noqa: E731
    jane = add("entity", data={"type": "person", "value": "Jane Roe", "attributes": {"Employer": "Hope Relief"}})
    tom = add("entity", data={"type": "person", "value": "Tom Roe"})
    old = add("entity", data={"type": "person", "value": "Old Partner"})
    kid = add("entity", data={"type": "person", "value": "Lily Roe", "protected": True})
    add(
        "link",
        data={"from": jane["id"], "to": tom["id"], "relation": "spouse", "confidence": "confirmed", "since": "2015-06"},
    )
    add(
        "link",
        data={"from": jane["id"], "to": old["id"], "relation": "business_partner", "since": "2008", "until": "2012"},
    )
    add("link", data={"from": jane["id"], "to": kid["id"], "relation": "parent", "confidence": "confirmed"})
    add("note", title="Call", body="Jane Roe met Old Partner again in 2020.")
    return case, jane, kid


def test_the_network_report(client):
    case, _jane, _kid = setup(client)
    r = client.post(f"/api/cases/{case['id']}/network.pdf", json={"chart_png": png()})
    assert r.status_code == 200 and r.headers["content-type"] == "application/pdf"
    text = text_of(r.content)
    assert "CONFIDENTIAL" in text and "Hope Relief network" in text and "Old Partner" in text
    assert "business partner of" in text and "2008" in text and "Lily" not in text and "Protected person" in text
    assert len(PdfReader(io.BytesIO(r.content)).pages[0].images) == 1  # the chart is in it
    in_2016 = text_of(client.post(f"/api/cases/{case['id']}/network.pdf", json={"as_of": "2016"}).content)
    assert (
        "as it stood on 2016" in in_2016 and "business partner of" not in in_2016 and "spouse or partner of" in in_2016
    )
    assert client.post(f"/api/cases/{case['id']}/network.pdf", json={"as_of": "last year"}).status_code == 422
    bad = client.post(
        f"/api/cases/{case['id']}/network.pdf", json={"chart_png": "data:image/png;base64,bm90IGFuIGltYWdl"}
    )
    assert bad.status_code == 422
    jpeg = io.BytesIO()
    Image.new("RGB", (10, 10)).save(jpeg, format="JPEG")
    as_jpeg = "data:image/png;base64," + base64.b64encode(jpeg.getvalue()).decode()
    assert client.post(f"/api/cases/{case['id']}/network.pdf", json={"chart_png": as_jpeg}).status_code == 422
    actions = [e["action"] for e in client.get("/api/audit?limit=20").json()]
    assert "case.export_network" in actions


def test_a_profile_pdf(client):
    case, jane, kid = setup(client)
    r = client.post(f"/api/cases/{case['id']}/entities/{jane['id']}/profile.pdf", json={"chart_png": png("blue")})
    text = text_of(r.content)
    assert r.status_code == 200 and "PROFILE" in text and "Jane Roe" in text and "spouse or partner of" in text
    assert "Hope Relief" in text and "Met Old Partner again" not in text and "Jane Roe met Old Partner again" in text
    assert "Lily" not in text and "leads, not established facts" in text
    protected = text_of(client.post(f"/api/cases/{case['id']}/entities/{kid['id']}/profile.pdf", json={}).content)
    assert "Protected person" in protected and "builds no profile" in protected and "Lily" not in protected
    assert "case.export_profile" in [e["action"] for e in client.get("/api/audit?limit=20").json()]
