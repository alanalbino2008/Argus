"""Identity resolution: fragments become personas without over-merging."""

from argus.core.graph import IntelligenceGraph
from argus.core.models import Entity, EntityType, Relation, RelationType
from argus.intel.identity import is_role_mailbox, resolve_people
from argus.modules.identity.email_recon import EmailReconModule
from tests.test_modules_offline import collect

E = EntityType


def graph_of(nodes, links):
    g = IntelligenceGraph("t")
    made = {}
    for i, (key, etype, value, kwargs) in enumerate(nodes):
        made[key] = Entity.create(etype, value, depth=0 if i == 0 else 1, **kwargs)
        g.add_entity(made[key], is_seed=i == 0)
    for a, b in links:
        g.add_relation(Relation.create(made[a].id, made[b].id, RelationType.ASSOCIATED_WITH))
    return g, made


def test_linked_fragments_become_one_persona_with_dossier():
    g, made = graph_of(
        [
            ("domain", E.DOMAIN, "acme.example", {}),
            ("email", E.EMAIL, "dana@acme.example", {}),
            ("user", E.USERNAME, "dana", {}),
            (
                "keybase",
                E.SOCIAL_PROFILE,
                "https://keybase.io/dana",
                {
                    "metadata": {
                        "platform": "Keybase",
                        "username": "dana",
                        "profile": {
                            "display_name": "Dana Whitfield",
                            "created_at": "2017-03-01T00:00:00Z",
                            "bio": "SecOps",
                        },
                    },
                    "confidence": 0.95,
                },
            ),
            (
                "gh",
                E.SOCIAL_PROFILE,
                "https://github.com/dwhit",
                {"metadata": {"platform": "GitHub", "username": "dwhit", "verified": True}, "confidence": 0.95},
            ),
            ("person", E.PERSON, "Dana Whitfield", {"confidence": 0.6}),
            ("place", E.LOCATION, "Leeds, UK", {}),
            ("org", E.ORGANIZATION, "Acme Corp", {}),
            ("site", E.DOMAIN, "dana.example", {}),
            (
                "breach",
                E.BREACH,
                "Adobe",
                {"metadata": {"breach_date": "2013-10-04", "data_classes": ["Email addresses", "Passwords"]}},
            ),
            # A colleague who shares only the employer: must stay a separate persona.
            ("email2", E.EMAIL, "sam@acme.example", {}),
            ("role", E.EMAIL, "info@acme.example", {}),
        ],
        [
            ("domain", "email"),
            ("email", "user"),
            ("user", "keybase"),
            ("keybase", "gh"),
            ("keybase", "person"),
            ("keybase", "place"),
            ("keybase", "org"),
            ("keybase", "site"),
            ("email", "breach"),
            ("email2", "org"),
            ("domain", "email2"),
            ("domain", "role"),
            ("role", "user"),  # even if a role inbox touches a handle, it never bridges people
        ],
    )
    paths = [
        {
            "id": "path_x",
            "title": "Credential exposure",
            "severity": "critical",
            "score": 80,
            "steps": [{"entity_id": made["email"].id}],
        }
    ]
    result = resolve_people(g, paths)

    assert result["summary"]["personas"] == 2
    assert result["role_mailboxes"] == ["info@acme.example"]
    dana = result["personas"][0]
    assert dana["name"] == "Dana Whitfield"
    assert dana["strength"] == "verified"
    assert dana["usernames"] == ["dana", "dwhit"]
    assert dana["emails"] == ["dana@acme.example"]
    assert dana["locations"] == ["Leeds, UK"] and dana["organisations"] == ["Acme Corp"]
    assert dana["websites"] == ["dana.example"]
    assert dana["bio"] == "SecOps"
    assert [t["event"] for t in dana["timeline"]] == ["Data exposed in Adobe breach", "Joined Keybase"]
    assert dana["exposures"][0] == {"severity": "high", "text": "Password exposed in the Adobe breach"}
    assert dana["attack_paths"][0]["id"] == "path_x"
    assert made["breach"].id in dana["entity_ids"] and made["domain"].id not in dana["entity_ids"]
    links = {a["platform"]: a["link"] for a in dana["accounts"]}
    assert links == {"Keybase": "strong", "GitHub": "verified"}
    assert dana["risk"] > result["personas"][1]["risk"]

    sam = result["personas"][1]
    assert sam["name"] == "sam@acme.example" and sam["organisations"] == ["Acme Corp"]
    assert made["role"].id not in sam["entity_ids"] + dana["entity_ids"]


def test_same_handle_hits_are_only_probable_and_lone_handles_are_dropped():
    g, _ = graph_of(
        [
            ("user", E.USERNAME, "zed", {}),
            (
                "hit",
                E.SOCIAL_PROFILE,
                "https://example.test/zed",
                {"metadata": {"platform": "Example"}, "source_module": "username_hunter", "confidence": 0.95},
            ),
            ("lonely", E.USERNAME, "nobody", {}),
        ],
        [("user", "hit")],
    )
    personas = resolve_people(g)["personas"]
    assert len(personas) == 1
    assert personas[0]["strength"] == "probable" and personas[0]["accounts"][0]["link"] == "probable"


def test_persona_ids_are_stable():
    g, _ = graph_of([("e", E.EMAIL, "a@b.example", {}), ("u", E.USERNAME, "a", {})], [("e", "u")])
    assert resolve_people(g)["personas"][0]["id"] == resolve_people(g)["personas"][0]["id"]


def test_role_mailboxes_are_not_hunted_as_people():
    assert is_role_mailbox("Security@acme.example") and is_role_mailbox("info")
    assert not is_role_mailbox("dana@acme.example")
    role = Entity.create(E.EMAIL, "support@acme.example")
    entities, _ = await_collect(role)
    assert not [e for e in entities if e.type == E.USERNAME]
    assert role.metadata["role_mailbox"] is True


def await_collect(entity):
    import asyncio

    return asyncio.run(collect(EmailReconModule(), entity))


def test_people_endpoint_on_demo_is_audited(client):
    from argus.demo import DEMO_ID

    client.post("/api/demo")
    body = client.get(f"/api/investigation/{DEMO_ID}/people").json()
    assert body["summary"]["personas"] >= 1
    assert any(p["accounts"] for p in body["personas"])
    assert client.get("/api/audit", params={"action": "investigation.people"}).json()


def test_email_format_is_learned_and_applied_only_to_people_tied_to_the_target():
    from argus.intel.identity import infer_email_format

    assert (
        infer_email_format([("Dana Whitfield", "dana.whitfield@acme.example")], "acme.example")["pattern"]
        == "first.last"
    )
    assert infer_email_format([("Dana Whitfield", "dwhitfield@acme.example")], "acme.example")["pattern"] == "flast"
    assert infer_email_format([("Dana Whitfield", "dana@other.example")], "acme.example") is None

    g, _ = graph_of(
        [
            ("domain", E.DOMAIN, "acme.example", {}),
            ("email", E.EMAIL, "dana.whitfield@acme.example", {}),
            ("dana", E.PERSON, "Dana Whitfield", {}),
            ("doc", E.URL, "https://acme.example/a.docx", {"metadata": {"category": "document"}}),
            ("aisha", E.PERSON, "Aisha Patel", {"source_module": "document_metadata"}),
            ("stranger", E.PERSON, "Random Person", {}),
            ("stranger_mail", E.EMAIL, "random@else.example", {}),
            ("phone", E.PHONE, "+441134960123", {}),
            ("staff", E.USERNAME, "jsmith", {"source_module": "document_metadata"}),
        ],
        [
            ("domain", "email"),
            ("dana", "email"),
            ("doc", "aisha"),
            ("stranger", "stranger_mail"),
            ("phone", "domain"),
            ("doc", "staff"),
        ],
    )
    result = resolve_people(g)
    assert result["email_format"]["pattern"] == "first.last"
    by_name = {p["name"]: p for p in result["personas"]}
    assert by_name["Aisha Patel"]["likely_email"] == {
        "address": "aisha.patel@acme.example",
        "basis": "first.last",
        "inferred": True,
    }
    assert by_name["Random Person"]["likely_email"] is None  # not linked to the target's assets
    assert by_name["Dana Whitfield"]["likely_email"] is None  # already known
    assert "jsmith" in by_name  # staff handle from document metadata is kept as a lead
    assert result["public_phones"] == ["+441134960123"]


def test_organisation_accounts_never_merge_their_members():
    g, _ = graph_of(
        [
            ("domain", E.DOMAIN, "acme.example", {}),
            (
                "org",
                E.SOCIAL_PROFILE,
                "https://github.com/acme",
                {"metadata": {"platform": "GitHub", "account_type": "organization"}},
            ),
            ("alice", E.USERNAME, "alice", {"source_module": "github_org"}),
            ("bob", E.USERNAME, "bob", {"source_module": "github_org"}),
        ],
        [("domain", "org"), ("alice", "org"), ("bob", "org")],
    )
    personas = resolve_people(g)["personas"]
    assert sorted(p["name"] for p in personas) == ["alice", "bob"]
    assert all(not p["accounts"] for p in personas)  # the org profile is nobody's personal account
