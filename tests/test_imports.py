"""Importing call records, statements, contact lists and UFDR phone extractions, and cross-referencing them."""

from __future__ import annotations

import io
import zipfile

import pytest

from argus.intel import imports as I

CDR = """Calling Number,Called Number,Start Time,Duration,Call Type,Cell ID
+447700900001,+447700900123,03/01/2026 21:14:05,125,Voice,234-15-1001
+447700900123,+447700900001,03/01/2026 22:01:00,0,SMS,234-15-1001
+447700900001,07700 900999,04/01/2026 09:30:00,60,Voice,234-15-1002
+447700900001,+447700900123,05/01/2026 21:40:00,300,Voice,234-15-1001
"""
STATEMENT = """Date;Description;Paid in;Paid out;Reference
02/01/2026;ACME LOGISTICS LTD;1.250,00;;SALARY
03/01/2026;Jane Doe;;150,00;rent
05/01/2026;Jane Doe;;150,00;rent
"""
CONTACTS = "Name,Mobile,Email\nJane Doe,07700 900123,jane@doe.family\nBob,+44 7700 900555,\n"


def _xlsx(rows):
    buf = io.BytesIO()
    shared = sorted({c for r in rows for c in r})
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("xl/sharedStrings.xml", '<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                   + "".join(f"<si><t>{s}</t></si>" for s in shared) + "</sst>")  # fmt: skip
        cells = "".join(f'<row r="{i + 1}">' + "".join(f'<c r="{chr(65 + j)}{i + 1}" t="s"><v>{shared.index(v)}</v></c>'
                        for j, v in enumerate(r)) + "</row>" for i, r in enumerate(rows))  # fmt: skip
        z.writestr("xl/worksheets/sheet1.xml", '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                   f"<sheetData>{cells}</sheetData></worksheet>")  # fmt: skip
    return buf.getvalue()


UFDR_XML = """<?xml version="1.0" encoding="utf-8"?>
<project xmlns="http://pa.cellebrite.com/report/2.0"><decodedData>
 <modelType type="Contact"><model type="Contact"><field name="Name"><value>Jane Doe</value></field>
  <multiModelField name="Entries"><model type="PhoneNumber"><field name="Value"><value>+447700900123</value></field></model></multiModelField></model></modelType>
 <modelType type="Call"><model type="Call"><field name="Direction"><value>Outgoing</value></field>
  <field name="TimeStamp"><value>2026-01-03T21:14:05.000+00:00</value></field><field name="Duration"><value>00:02:05</value></field>
  <multiModelField name="Parties"><model type="Party"><field name="Identifier"><value>+447700900123</value></field>
   <field name="Role"><value>To</value></field><field name="Name"><value>Jane Doe</value></field></model></multiModelField></model></modelType>
 <modelType type="InstantMessage"><model type="InstantMessage"><field name="TimeStamp"><value>2026-01-04T08:00:00+00:00</value></field>
  <field name="Source"><value>WhatsApp</value></field>
  <modelField name="From"><model type="Party"><field name="Identifier"><value>447700900555@s.whatsapp.net</value></field></model></modelField>
  <multiModelField name="To"><model type="Party"><field name="Identifier"><value>+447700900001</value></field><field name="Role"><value>To</value></field></model></multiModelField>
 </model></modelType>
 <modelType type="UserAccount"><model type="UserAccount"><field name="Username"><value>janedoe84</value></field>
  <field name="ServiceType"><value>Instagram</value></field></model></modelType>
</decodedData></project>"""


def _ufdr():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("report.xml", UFDR_XML)
    return buf.getvalue()


def test_call_records_are_read_from_operator_columns():
    kind, records = I.parse(CDR.encode(), "cdr.csv")
    assert kind == "cdr" and len(records) == 4
    assert records[0] == {"type": "call", "when": "2026-01-03T21:14:05+00:00", "from": "+447700900001",
                          "to": "+447700900123", "duration": 125, "cell": "234-15-1001", "detail": "voice"}  # fmt: skip
    assert records[1]["type"] == "sms" and records[2]["to"] == "07700900999"


def test_statements_contacts_and_spreadsheets():
    kind, tx = I.parse(STATEMENT.encode(), "statement.csv")
    assert kind == "transactions" and [t["amount"] for t in tx] == [1250.0, -150.0, -150.0]
    kind, contacts = I.parse(CONTACTS.encode(), "contacts.csv")
    assert kind == "contacts" and {c["from"] for c in contacts} == {"07700900123", "jane@doe.family", "+447700900555"}
    kind, rows = I.parse(_xlsx([["From", "To", "Date"], ["+447700900001", "+447700900123", "2026-01-03 21:14:05"]]),
                         "export.xlsx")  # fmt: skip
    assert kind == "cdr" and rows[0]["when"] == "2026-01-03T21:14:05+00:00"
    with pytest.raises(I.ImportError_, match="columns were not recognised"):
        I.parse(b"a,b\n1,2\n", "x.csv")


def test_a_ufdr_phone_extraction():
    _kind, records = I.parse(_ufdr(), "phone.ufdr")
    by_type = {}
    for r in records:
        by_type.setdefault(r["type"], []).append(r)
    assert by_type["contact"][0] == {"type": "contact", "name": "Jane Doe", "from": "+447700900123"}
    call = by_type["call"][0]
    assert (
        call["from"] == "(this phone)"
        and call["to"] == "+447700900123"
        and call["when"].startswith("2026-01-03T21:14:05")
    )
    assert (
        by_type["message"][0]["from"] == "447700900555@s.whatsapp.net" and by_type["message"][0]["detail"] == "WhatsApp"
    )
    assert by_type["account"][0]["from"] == "janedoe84" and by_type["account"][0]["detail"] == "Instagram"


def test_records_are_cross_referenced_with_the_case():
    _, records = I.parse(CDR.encode(), "cdr.csv")
    known = [{"kind": "phone", "value": "07700 900123", "where": "known about Jane Doe"}]
    result = I.analyse(records, known)
    top = result["top"][0]
    assert top["identifier"] == "+447700900001" and top["count"] == 4
    jane = next(e for e in result["in_case"] if e["identifier"] == "+447700900123")
    assert jane["count"] == 3 and jane["in_case"][0]["where"] == "known about Jane Doe"
    assert jane["first"] == "2026-01-03T21:14:05+00:00" and jane["last"] == "2026-01-05T21:40:00+00:00"
    assert result["hours_utc"] == {"9": 1, "21": 2, "22": 1} and result["types"] == {"call": 3, "sms": 1}
    _, tx = I.parse(STATEMENT.encode(), "s.csv")
    money = I.analyse(tx, [{"kind": "person", "value": "Jane Doe", "where": "case entity: Jane Doe"}])
    rent = next(e for e in money["in_case"] if e["identifier"] == "Jane Doe")
    assert rent["paid_out"] == 300.0 and rent["count"] == 2


def test_importing_needs_a_legal_authorisation_and_is_evidence(make_client):
    c = make_client()
    plain = c.post("/api/cases", json={"title": "F", "purpose": "Fraud report R-60", "confirmed": True}).json()["id"]
    refused = c.post(f"/api/cases/{plain}/imports", files={"file": ("cdr.csv", CDR.encode(), "text/csv")})
    assert refused.status_code == 409 and "legal authorisation" in refused.json()["detail"]
    case_id = c.post("/api/cases", json={"title": "F", "purpose": "Fraud report R-61", "confirmed": True,
                                         "authorization": "Production order 2026/0412"}).json()["id"]  # fmt: skip
    c.post(f"/api/cases/{case_id}/subjects", json={"name": "Jane Doe", "confirmed": True,
                                                   "known": {"names": ["Jane Doe"], "phones": ["+44 7700 900123"]}})  # fmt: skip
    made = c.post(f"/api/cases/{case_id}/imports", files={"file": ("cdr.csv", CDR.encode(), "text/csv")})
    assert made.status_code == 201, made.text
    imported = made.json()
    assert imported["data_import"] == {"kind": "cdr", "label": "Call records", "records": 4, "filename": "cdr.csv"}
    assert {f["name"] for f in c.get(f"/api/evidence/{imported['id']}").json()["files"]} == {"cdr.csv", "records.json"}
    assert [i["id"] for i in c.get(f"/api/cases/{case_id}/imports").json()] == [imported["id"]]
    analysis = c.get(f"/api/cases/{case_id}/imports/{imported['id']}").json()
    assert analysis["records"] == 4 and analysis["in_case"][0]["in_case"][0]["where"] == "known about Jane Doe"
    actions = {e["action"]: e for e in c.get("/api/audit?limit=50").json()}
    assert actions["case.import"]["details"]["authorization"] == "Production order 2026/0412"
    assert "case.import_view" in actions
    bad = c.post(f"/api/cases/{case_id}/imports", files={"file": ("x.csv", b"a,b\n1,2\n", "text/csv")})
    assert bad.status_code == 422
    assert c.get(f"/api/cases/{case_id}/imports/ev_nope").status_code == 404
