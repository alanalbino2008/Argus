# 74 — Lookalike triage

## Why

Brand watch (Phase 71) finds lookalike domains as soon as they get a certificate. Some are urgent (a
copy of your login page, live today), most are not (a speculator's parked name, a typo your own IT
team registered years ago). Treating them all alike buries the urgent ones. Triage sorts them.

## What it checks

For every new lookalike, and on every run for the 25 known ones checked longest ago (parked domains
often go live weeks later):

**DNS (passive, always on).** Asked of public resolvers, never of the lookalike's own servers:

| Question | Meaning |
| --- | --- |
| Does it resolve? | No: a dormant registration (*Not resolving*) |
| Mail servers (MX)? | It can send phishing email (*Can send email*) |
| Parking name servers? | A speculator, for now (*Parked*) |
| Your own name servers, or your address behind them? | A defensive registration (*Yours*, not reported) |

Shared DNS and hosting providers (Cloudflare, Route 53, Azure DNS, GoDaddy and others) are **never**
taken as proof that a domain is yours: a phishing site on Cloudflare shares your Cloudflare name
servers and anycast addresses.

**Web (opt-in, per watch).** Argus fetches the home page (HTTPS, then HTTP) and its favicon once, and
compares them with your own site:

* the **same favicon** as yours, your **page title** or brand name in its title, or a page that
  **looks like yours** (visual match): *Copies your site*;
* that, plus a **password field**: *Active phishing page*.

**Visual (Phase 78, with website checks on).** The lookalike's page is rendered by the headless
browser, through the same route, and its first screen compared with your own pages (your home page,
and your login page if you add it): a perceptual fingerprint (a 64-bit difference hash and a 16 x 16
light-and-dark layout, both of which must agree). Phishing kits often change the favicon and title but
keep the look; this catches them. Blank pages never match; at most 8 pages are rendered per run, and
your own pages are re-rendered weekly.

## Verdicts and severity

| Verdict | Severity |
| --- | --- |
| Active phishing page | Critical |
| Copies your site | High |
| Can send email | High with a sensitive word (`login`, `pay`, `secure`…), else medium |
| Live website, Registered | From how the name imitates yours |
| Parked | Low (medium with mail servers) |
| Not resolving | At most medium |
| Yours | Not reported |

## Alerts

* New lookalikes alert as before, with their triaged severity. On the very first run, an **active
  phishing page** always alerts, however old its certificate.
* A known lookalike that **gets worse** (to high or critical, for example parked → active phishing)
  raises an alert of its own, marked with what it was before.

## Visiting websites safely

Visiting a phishing site tells whoever runs it that someone looked, and from which address. So each
watch chooses: **Don't visit** (the default; DNS triage only), **Visit directly**, or **Through** one of
the egress routes configured under Settings → Investigator safety (Tor, a VPN, a proxy). With a
route, the lookalike's operator sees the route's exit, never this server.

## API

`POST /api/brand-watches` and `PATCH /api/brand-watches/{id}` accept `web_check`: `"off"`,
`"direct"`, or a route's name. Each recent finding in `GET /api/brand-watches` carries `triage`:
`verdict`, `label`, `severity`, `reasons`, the DNS answers, the web result and `checked_at`. Alerts'
`brand_watch.findings` carry `verdict`, `reasons` and, for escalations, `escalated_from`.
