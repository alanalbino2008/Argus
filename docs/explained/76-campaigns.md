# 76 — Campaigns

## Why

One actor rarely registers one domain. A phishing operation registers several lookalikes, points
them at the same server, gives them the same name servers and mail host, and copies the same login
page with its favicon. Seen one by one, that is ten alerts, ten takedowns and no picture. Seen
together, it is one campaign: one actor, one hosting provider to report it to, one story to tell.

## What links two items

| Evidence | Strength | Never counted |
| --- | --- | --- |
| Same fingerprint watch (servers sharing a favicon, JARM, HASSH or certificate) | Strong | — |
| Same favicon on two lookalike sites | Strong | — |
| Same IP address | Medium | Cloudflare and Fastly addresses (published ranges); private and documentation addresses |
| Same name servers | Medium | Shared DNS providers: Cloudflare, Route 53, Azure DNS, Google, GoDaddy, Namecheap… |
| Same mail host | Medium | Large mail providers: Google, Microsoft, Zoho, Mailgun, SendGrid… |
| Same page title | Weak | Generic titles: "Welcome to nginx", "Index of /", "Just a moment…", "Account suspended"… |

The "never counted" column matters: millions of unrelated sites sit behind Cloudflare, so sharing
it says nothing about who runs them. Without these exclusions every Cloudflare-fronted lookalike would
merge into one meaningless "campaign".

Items linked directly or through others form a campaign (two or more items).

## What goes in

Everything Argus has already recorded for the workspace; nothing new is looked up:

* **lookalike domains** from brand watches, with their triage (addresses, name servers, mail hosts,
  favicon and title when website checks are on); defensive registrations of your own are left out;
* **servers** found by fingerprint watches;
* **tagged** IP addresses and domains (tags are shown on members, and a tagged address that a
  lookalike points to joins its campaign).

## What you see

**Monitoring → Campaigns**: each campaign with its worst severity, size, the brands it imitates, the
evidence that links it (strongest first, with how many members share each), its members (verdict,
tags, takedown status) and when it was first and last seen. Campaigns are ordered by severity, then
size. They are computed on request, so they change as watches and triage learn more.

## API

```http
GET /api/campaigns
```

Returns `campaigns` (each with `id`, `name`, `severity`, `size`, `members`, `links`, `brands`,
`first_seen`, `last_seen`) and the number of `indicators` considered. A campaign's `id` is derived
from its members, so it is stable while its membership is.
