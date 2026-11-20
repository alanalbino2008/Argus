# 68 — The team's tags and notes on entities

## Why

Investigators learn things that no module can: *that* host belongs to the client, *that* domain is
a known phishing kit, *this* email belongs to the suspect's brother. Until now that knowledge lived
in people's heads or in case notes, invisible to the graph, queries and alerts.

## What it does

In the graph's details panel, an analyst can give any entity **tags** (`client-owned`, `c2`,
`suspect`…) and a **note**. Everyone in the team sees them, and the entity wears a gold ring on the
graph.

**Once, everywhere.** An entity's id is derived from its type and value, so the same host has the
same id in every scan. An annotation is stored against that id for the workspace, which means
tagging `vpn.acme.example` today tags it in last month's scan, today's, and every future one.

## Using tags in queries, hunts and alerts

AQL gains two fields:

```text
tag:c2                                  everything tagged c2
tag:*                                   everything the team has tagged
type:subdomain -tag:client-owned        hosts nobody has claimed yet
note~"invoice"                          notes mentioning invoices
tag:vpn -[RESOLVES_TO]-> ip             the IPs behind the VPN hosts
```

Because hunts and saved-query alerts run AQL, tags work there too:

- **Hunt** `tag:c2` across every investigation: where has the known C2 infrastructure turned up?
- **Alert**: save `tag:c2` with alerting on, and Argus alerts as soon as a new scan finds anything
  the team has tagged `c2`.

If an entity has no annotation, `tag` and `note` fall back to a metadata key of the same name, if
a module recorded one, so older queries keep their meaning.

## Safety and limits

- **Scoped to the team**: annotations belong to the workspace, and other teams never see them.
- **Encrypted at rest**: the entity's value, the tags and the note are stored encrypted (a tag like
  `suspect` on a person's email is sensitive).
- **Roles**: analysts and admins edit, viewers read. Every change is written to the audit log.
- **Limits**: up to 20 tags of 40 characters (trimmed, de-duplicated without regard to case,
  stripped of markup) and a note of 4,000 characters. Clearing both removes the annotation.

## API

| Method & path | |
|---|---|
| `GET /api/annotations` | every annotated entity in the workspace |
| `GET /api/annotations/tags` | every tag in use, with counts |
| `PUT /api/annotations/{entity_id}` | `{"entity_type", "value", "tags", "note"}`; empty tags and note remove it |

Tests: `tests/test_annotations.py`.
