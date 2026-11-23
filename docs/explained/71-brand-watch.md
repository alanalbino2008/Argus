# 71 — Brand watch on Certificate Transparency

## Why

Phishing against an organisation almost always uses a domain that *looks* like its own:
`acme-login.com`, `acrne.com`, `secure-acme.com`, or `acme.com` spelled with a Cyrillic "а".
Those sites need HTTPS to look trustworthy, and every certificate a public authority issues is
published in **Certificate Transparency** (CT) logs, usually hours or days before the site is used.
Watching CT for your brand is one of the earliest warnings of a campaign you can get, for free.

## What it does

**Monitoring → Brand watch → Watch a brand**: enter your domain and, optionally, other domains you
own (they are never reported). Every day:

1. **crt.sh, by keyword.** Every unexpired certificate whose names contain the brand
   (`acme-login.net`, `acme.evil.example`…). Skipped for very short brands (fewer than four letters),
   which match too much of the internet.
2. **Cert Spotter, by name.** The lookalikes a keyword cannot find: typos, look-alike letters
   (`rn` for `m`), Cyrillic homographs (`xn--…`), other endings. Argus generates them (Phase 19's
   lookalike engine) and checks ten per run (forty with `ARGUS_CERTSPOTTER_API_KEY`), most dangerous
   first, moving through the list so every candidate is covered over the days.

Each certificate name is **classified**:

| Technique | Example | Severity |
| --- | --- | --- |
| Homoglyph | `acrne.com`, `аcme.com` (Cyrillic) | High |
| Combosquat | `acme-login.com`, `secure-acme.net` | High with a sensitive word (`login`, `secure`, `pay`…), else medium |
| Brand as a subdomain | `acme.com.evil.example`, `login.acme.evil.example` | High with a sensitive word, else medium |
| Typo, other TLD, missing dot | `acem.com`, `acme.co`, `wwwacme.com` | Medium (high with a sensitive word) |

Host names under one registration are **one finding**: `secure-acme.com` with its 60 hosts is one
lookalike domain, reported once, with the worst of its host names deciding the severity.

## Alerts

* The **first run** records what already exists. It alerts only on domains whose first certificate
  was issued in the last 14 days: years-old squats are history, not news.
* After that, **every new lookalike domain** is announced, one alert per run, with up to 20 domains,
  their technique, issuer and first-certificate date. Alerts reach Slack, Teams, email and webhooks;
  webhooks receive a `brand_watch` block.

## Failures

crt.sh is free and often overloaded (it answers `502` for minutes at a time). When one source fails,
the run is **partial**: the other source's results count, and the watch is tried again within the
hour. When both fail, nothing is recorded (it never becomes the baseline) and it is retried within
the hour. The page shows each source's status.

## Access and limits

Analysts create, change, run and remove watches; viewers see them; other teams never do. All changes
and alerts are audited, and the own-domain list and findings are encrypted at rest. Up to 20 brands
per workspace, 5,000 remembered lookalikes per brand. With several replicas, a due watch is claimed
atomically, so it runs once.

## Configuration

| Setting | Default | Meaning |
| --- | --- | --- |
| `ARGUS_BRAND_WATCH_ENABLED` | `true` | Run the loop (also needs `ARGUS_MONITORS_ENABLED`) |
| `ARGUS_CERTSPOTTER_API_KEY` | — | Cert Spotter key: 40 names per run instead of 10 |

## API

```http
POST  /api/brand-watches          {"domain": "acme.com", "allow": ["acme.co.uk"], "interval_hours": 24}
GET   /api/brand-watches
PATCH /api/brand-watches/{id}     {"allow": ["acme.co.uk", "acme-careers.com"]}
POST  /api/brand-watches/{id}/run
DELETE /api/brand-watches/{id}
```

```python
client.watch_brand("acme.com", allow=["acme.co.uk"])
```

## Triage (Phase 74)

Every lookalike is then **triaged** (see [74 — Lookalike triage](74-lookalike-triage.md)): whether it
resolves, can send email, is parked or is a defensive registration of yours, and, if you allow it,
whether its website copies yours with a login form. The verdict sets the severity.

## Storage (Phase 80)

Each lookalike is a row of its own (`brand_lookalikes`): its finding, latest triage and takedown are
encrypted; its verdict, severity, technique and infrastructure (addresses, name servers, mail hosts,
favicon hash, page title) are plain columns so campaigns, TAXII and the metrics read thousands of
lookalikes without decrypting them. A run reads and writes only the lookalikes it checks. Up to 5,000
per watch; beyond that the oldest are forgotten, except those with a takedown.
