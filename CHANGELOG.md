# Changelog

## [1.84.0] — Phase 84: Watching the watchers

Brand and fingerprint watches run unattended; when they stop working, the only symptom is silence.
Operators now see it in Prometheus, Grafana and Alertmanager.

### Added
- **Metrics** for watch runs by kind and outcome (`argus_watch_runs_total`), run time, the last
  successful run, source failures (crt.sh, Cert Spotter, Shodan, Censys), new lookalikes by severity
  and takedown steps (drafted, reported, down, closed).
- **Alerts:** `ArgusWatchesFailing` (every run of a kind failed for 6 hours), `ArgusWatchesStalled`
  (no success for 2 days), `ArgusCertificateTransparencyDegraded` and `ArgusTakedownBacklog`, each
  with a `promtool` unit test.
- A **Brand protection & watches** row on the Grafana dashboard.
- The Phase 83 limits and run-now cooldowns are counted in `argus_rate_limited_total` under their own
  names.

## [1.83.0] — Phase 83: Hardening the recent features

A review of everything added in phases 68 to 82 for what one caller could do to the server, a
workspace's third-party credits, or memory. Each refusal is a `429` with `Retry-After`.

### Security
- **Run now** on a brand or fingerprint watch waits 10 minutes after the last run
  (`ARGUS_WATCH_RUN_COOLDOWN_SECONDS`): each run spends Shodan, Censys or Cert Spotter queries, so a
  script, or a stolen analyst key, could otherwise drain an account.
- **Opening a case from a lookalike** now counts against the same capture limit as *Capture a page*
  (20 a minute; each capture runs a browser), checked before anything is created.
- **Rate limits** where one request does a lot of work: takedown drafts (10 a minute; each asks RDAP
  for a registrar and up to three networks), campaign takedowns (3 a minute; up to 30 domains each),
  campaigns and brand-protection metrics (60 a minute; they read every lookalike), the
  brand-protection PDF (10 a minute), report verification (30 a minute) and TAXII (120 a minute per
  key; every page recomputes campaigns).
- **Bounds:** report verification reads at most 16 MB (was 64 MB); a workspace annotates at most
  20,000 entities (every query, hunt and feed reads them all), while changing an existing annotation
  is always allowed.
- Captures' `429` now carries `Retry-After` like the rest.

## [1.82.0] — Phase 82: From lookalike to case

### Added
- **Open case** on any lookalike in Monitoring → Brand watch (or add it to an existing case). The case
  gets the lookalike and your domain, linked ("imitates"), with what it is (technique, verdict,
  severity, addresses, mail servers, registrar, takedown status); a timeline (first certificate, found
  by Argus, each takedown step); a note with the triage reasons; and a **capture of its website** as
  preserved evidence (response, screenshot, text, fingerprints, chain of custody), ready for a takedown
  escalation, a UDRP complaint or the police.
- **The watch's safety carries over.** A watch that visits websites through an anonymising route
  opens an *anonymous* case on that route, so the capture never comes from this server's address.
  A capture that fails (the site is down, or refuses) is reported; the case is still opened.
- The lookalike shows its case, one click away. API:
  `POST /api/brand-watches/{id}/lookalikes/{domain}/case`; Python client: `lookalike_case()`.

### Fixed
- A brand watch whose website route was later removed from the settings failed every run; it now
  records that the route is missing and carries on with DNS triage.
- A case's header squeezed long titles to a word per line beside its many actions; the actions now
  wrap below the title.

## [1.81.0] — Phase 81: Alert workflow

### Added
- **Alerts are work items.** Each alert has a **status** (open → investigating → resolved, or false
  positive), an **assignee** (a member of the workspace, or yourself) and an **activity** history:
  status changes and assignments with the reason given, and the team's comments. Acknowledging an
  alert now means "seen, someone is on it" (open → investigating).
- **Monitoring → Alerts** has filters (Open, Mine, Unassigned, Closed), shows each alert's status,
  owner and comments, and opens an alert to change its status, assign it and discuss it. The header
  shows open and unassigned alerts and the median time to resolve over 30 days.
- **Response times.** `GET /api/alerts/stats`: open alerts by severity, unassigned, raised and
  resolved in the period, false-positive rate, and the median hours to acknowledge and to resolve.
- Analysts change and comment; viewers read; other teams never see them. Every change is audited
  (`alert.update`, `alert.comment`); comments and activity are encrypted at rest. Migration 0033:
  alerts acknowledged before this version count as resolved.
- API: `GET /api/alerts?status=&assignee=me|none|name`, `GET`/`PATCH /api/alerts/{id}`,
  `POST /api/alerts/{id}/comments`, `GET /api/alerts/stats`, `GET /api/alerts/assignees`. Python
  client: `update_alert()`, `comment_alert()`, `alert_stats()`.

### Fixed
- The Python client's `brand_protection(days=…)` sent the period as a parameter the server ignored
  (it always used 90 days).

## [1.80.0] — Phase 80: Lookalikes in their own table

### Changed
- **Brand watches scale.** Each lookalike a brand watch finds is now a row of its own (with its
  finding, triage and takedown) instead of an entry in one encrypted document per watch, which grew to
  about 3.4 MB at 5,000 lookalikes and was decrypted, parsed and rewritten whole on every run, every
  takedown change and every page view. Measured with 3 brands × 5,000 lookalikes:

  | | Before | After |
  | --- | --- | --- |
  | Poll for due watches (every 5 minutes) | 80 ms | 2 ms |
  | Brand-watch page | 104 ms | 34 ms |
  | Campaigns | 566 ms | 459 ms |
  | Brand-protection summary | 629 ms | 494 ms |
  | TAXII lookalikes | 387 ms | 331 ms |
  | Written per run or takedown change | ~3.4 MB | only the rows touched (~0.9 KB each) |

- Each view reads only what it needs: verdict, severity, technique and the infrastructure campaigns
  group on (addresses, name servers, mail hosts, favicon hash, page title: the attacker's servers, not
  people) are plain columns; findings, full triage and takedown records stay encrypted. Runs fetch just
  the lookalikes they re-check (indexed: newest first, longest unchecked, open takedowns).
- Campaign grouping is linear in the number of links (it was quadratic in the number of groups) and
  caches address classification.
- **Automatic conversion.** Watches saved before are converted the first time they are read, in one
  transaction per watch; nothing to do. Migration 0032.

## [1.79.0] — Phase 79: The brand-protection report

### Added
- **Brand protection in five numbers.** Monitoring → Brand watch opens with the last 90 days: open
  threats (active phishing pages, copies of your site and high-severity mail-capable lookalikes not
  yet taken down), new lookalikes, takedowns that succeeded, the **median time to takedown** (from
  report to down), and campaigns.
- **The report for management (PDF).** Headline numbers, the weekly trend of new lookalikes and
  takedowns, the open threats, the takedowns waiting longest, the campaigns and every watched brand,
  with a note on how to read it. Registered and verifiable by its SHA-256 like every Argus report,
  marked with its TLP, and escaped throughout (domain names come from whoever registered them).
- **Scheduled.** A new report kind in scheduled reports, *Brand protection*: every week or month to
  Slack, Teams, email (with the PDF) or webhooks, with the headline numbers in the message.
- API: `GET /api/brand-protection/summary?days=`, `POST /api/brand-protection/report`, schedule
  `options.kind: "brand"`; Python client: `brand_protection()`, `brand_protection_report()`.

## [1.78.0] — Phase 78: Visual clone detection

### Added
- **Lookalikes are compared by how they look.** Phishing kits copy a login page's look and change
  what a machine checks first (favicon, title, markup). With website checks on, Argus renders each live
  lookalike's page in the headless browser (through the watch's route) and compares its first screen
  with the brand's own pages: a 64-bit difference hash and a 16 x 16 light-and-dark layout, both of
  which must agree. A visual copy counts as a copy of your site; with a password field it is an
  **active phishing page** (critical). The reason says which of your pages it resembles and how
  closely ("Looks like your page https://login.acme.com/ (97% visual match)").
- **Your reference pages.** Your home page by default; add your login page (or up to five pages) when
  creating a watch, or with `reference_urls`. They are rendered once a week, not on every run.
- **Careful by design.** Blank and near-uniform pages never match anything; at most 8 lookalikes are
  rendered per run (newest first); without a headless browser, or with website checks off, nothing is
  rendered. A failed render never breaks the rest of the triage.
- API: `reference_urls` on `POST`/`PATCH /api/brand-watches`; `references` (URL and when rendered) in
  `GET`; each triage carries `visual` (`url`, `similarity`).

## [1.77.0] — Phase 77: Campaign takedowns, and campaigns in the TAXII feed

### Added
- **Take down a whole campaign.** On a campaign, **Take down campaign** looks up every domain's
  registrar and hosts in RDAP and drafts **one abuse report per recipient**: the host gets the list of
  all the campaign's domains on its network, each registrar the ones it registered, with the
  infrastructure they share ("IP address 45.77.10.50, 3 of them") and each domain's evidence.
  Each report can be edited, opened in your mail client or copied, and **Mark reported** marks all its
  domains. Every domain also gets its own takedown record and is followed until it goes down, as in
  Phase 75. Running it again re-shows the reports and drafts only domains not yet reported.
- **Campaigns in TAXII.** A fourth collection, **Campaigns**, carries a STIX `campaign` per campaign
  (name, first and last seen, the evidence linking it, severity and brands as labels), an
  `indicates` relationship from each member's indicator, and those indicators, with the **same ids**
  as in the other collections, so OpenCTI or MISP attach the campaign to indicators they already have.
- API: `POST /api/campaigns/{id}/takedown`; Python client: `take_down_campaign()`. Audited
  (`takedown.campaign`).

## [1.76.0] — Phase 76: Campaigns

### Added
- **Campaigns (Monitoring → Campaigns).** Lookalike domains, fingerprint-watch servers and tagged
  IP addresses and domains are grouped when they share infrastructure a stranger would not share by
  chance: the same **IP address**, the same **private name servers**, the same **mail host**, the same
  **favicon**, a distinctive identical **page title**, or the same **fingerprint watch**. Ten alerts
  about one actor become one campaign, with the evidence that links it (strongest first), its
  members with their verdicts, tags and takedown status, the brands it imitates, and when it was
  first and last seen. One report to their host can take several down.
- **No false campaigns from big providers.** Cloudflare and Fastly addresses (their published
  ranges), shared DNS providers (Cloudflare, Route 53, Azure DNS, GoDaddy…), large mail providers
  (Google, Microsoft, Zoho…), private and documentation addresses, and generic page titles ("Welcome
  to nginx", "Just a moment…") never link anything.
- Computed on request from what the watches and tags already recorded: nothing is looked up.
  API: `GET /api/campaigns`; Python client: `campaigns()`.

## [1.75.0] — Phase 75: Takedown requests

### Added
- **Report abuse, from the finding.** On any lookalike in Monitoring → Brand watch, **Report abuse**
  looks up who can take it down in RDAP (the domain's **registrar** and its IANA id, and the
  **hosting network** of each address, with their abuse emails; RDAP goes to the registries, never to
  the lookalike) and drafts the abuse report: what it imitates, when it got its first certificate,
  the triage evidence (your favicon, your page title, a password field, mail servers), its addresses
  and host names, the registrar and the host.
- **You send it.** Argus does not email third parties on your behalf: **Open in email** fills your
  mail client (recipients, subject, text), **Copy text** copies it, and the text can be edited first.
  Then **Mark as reported**.
- **Followed until it is down.** Domains with an open takedown are re-checked on every run. When the
  name stops resolving (the registrar suspended it), or its website has gone on two runs in a row
  (with website checks on), the takedown is marked **Taken down** and a low-severity alert says so.
  Each takedown keeps its history (drafted, reported, checks, down or closed, and by whom), and can
  be closed (refused, handled elsewhere).
- API: `POST /api/brand-watches/{id}/takedowns`, `…/takedowns/{domain}/reported`,
  `…/takedowns/{domain}/close`; takedowns appear in `GET /api/brand-watches`. Python client:
  `draft_takedown()`, `takedown_reported()`. All audited.

## [1.74.0] — Phase 74: Lookalike triage

### Added
- **Every lookalike is triaged.** Brand watch no longer stops at "a certificate exists". For each new
  lookalike, and for the 25 known ones checked longest ago on every run, Argus asks:
  - **DNS (passive, always):** does it resolve, does it have **mail servers** (it can send phishing
    email), is it **parked** (parking or resale name servers), or is it **yours** (a defensive
    registration on your own name servers)?
  - **Web (opt-in):** does the site answer, does it show a **password field**, and does it use **your
    favicon** or **your page title**? A copy of your site with a password field is an **active
    phishing page**.
- **Severity follows the verdict:** active phishing is critical; a copy of your site, or a
  mail-capable lookalike with a word like `login` or `pay`, is high; parked and dormant names are low;
  your own defensive registrations are not reported. Each finding shows its verdict and reasons.
- **Escalation alerts.** A known lookalike that gets worse (parked → live copy of your login page)
  raises an alert, though it is not new. On the first run, an active phishing page always alerts,
  however old its certificate.
- **Visiting websites is your choice, per watch:** *Don't visit* (default), *Visit directly*, or
  *Through* one of the egress routes (Tor, a VPN), because a visit tells the site's operator that
  someone looked, and from where.

### Changed
- Sharing a **shared DNS provider** (Cloudflare, Route 53, Azure DNS, GoDaddy and others) or a CDN
  address with the brand no longer marks a lookalike as the brand's own: a phishing site on Cloudflare
  shares the brand's Cloudflare name servers. Only the brand's own name servers (or its addresses
  behind its own name servers) count. This also applies to the lookalike check in scans.

## [1.73.0] — Phase 73: A TAXII 2.1 threat-intelligence feed

### Added
- **TAXII 2.1 server (read-only).** OpenCTI, MISP, Microsoft Sentinel, Splunk and any other TAXII
  client can pull a workspace's indicators on their own schedule. Discovery at `/taxii2/`; each
  workspace is its own API root, `/taxii2/{workspace}/` (id or slug), so clients need no custom
  header. Three collections of STIX 2.1 indicators, marked TLP:AMBER:
  - **Tagged entities**: every domain, IP address, email address and URL the team has tagged
    (Phase 68); tags become `labels` and the note the description. "Tag it `c2` in Argus" now means
    "it reaches the SIEM".
  - **Lookalike domains** from brand watches (Phase 71), with technique and brand.
  - **Fingerprint-watch servers** (Phase 69): addresses and ports sharing a watched fingerprint.
- **Incremental and stable.** Indicator ids are deterministic (platforms update rather than
  duplicate them) and `date_added` is when Argus first knew each one, so `added_after` pulls fetch
  only what is new. Paging (`limit`, `next`), `match[id]`, `match[type]`, manifests, single objects
  and the `X-TAXII-Date-Added-*` headers follow the specification. Tested with the OASIS
  `taxii2-client`.
- **Authentication for TAXII clients.** API keys are accepted as the password of HTTP Basic (the
  user name is ignored), which most TAXII clients can send, as well as Bearer tokens. A viewer key
  is enough; other teams' roots are invisible. Every pull is audited (`taxii.read`).
- Settings → API & integrations shows the discovery URL and this workspace's API root.

### Changed
- Fingerprint watches write IPv6 servers as `[2001:db8::5]:22` (the address and port were ambiguous
  before). An IPv6 server already known under the old form is reported once more as new.
- Fingerprint and brand watches record when each server or lookalike was first seen.

## [1.72.0] — Phase 72: Signed case reports

### Added
- **Every case report is signed.** Each installation has an Ed25519 report-signing key, created on
  first use and kept in the database sealed with the server's encryption key, or set with
  `ARGUS_REPORT_SIGNING_KEY` (base64) so replicas and rebuilt servers sign with the same key. The
  report stays one HTML file: the signature and public key are two `<meta>` tags, and its footer
  names the key id and how to check it.
- **Anyone can check a report, without an account.** Any change, down to one character, breaks the
  signature. Ways to check:
  - in Argus: **Cases → Verify a report** (genuine and signed by this server; altered; or intact but
    signed by another key);
  - on the command line: `argus --verify-report report.html --report-key 7a5b-2880-b2fa-813b`;
  - in Python, offline with only `cryptography`: `argus_client.verify_report(path, key_id)`;
  - by comparing the key id in the report with `GET /api/report-signing-key` (public).
- Downloads carry `X-Argus-Report-Key`; the audit log records each report's key id and SHA-256, and
  each verification (`report.verify`).

## [1.71.0] — Phase 71: Brand watch on Certificate Transparency

### Added
- **Brand watch.** On **Monitoring → Brand watch**, enter your domain (and other domains you own).
  Every day Argus looks in the Certificate Transparency logs for certificates on names that imitate
  it and alerts on new ones. Phishing sites need HTTPS, and every public certificate is logged, so
  this often shows a campaign before its first email is sent.
- **Two sources.** crt.sh is searched by keyword (every certificate whose names contain the brand:
  `acme-login.net`, `acme.evil.example`). Cert Spotter is asked by name for the lookalikes a keyword
  cannot find (typos, look-alike letters, Cyrillic homographs), a few per run from the lookalike
  generator's list, most dangerous first, so every candidate is covered over the days.
  `ARGUS_CERTSPOTTER_API_KEY` checks more per run.
- **Classified, grouped, ranked.** Each name is matched to a technique (homoglyph, combosquat,
  typo, other TLD, the brand used as a subdomain of someone else's domain). Names under one
  registration are one finding (`secure-acme.com`, +60 hosts). Sensitive words (`login`, `secure`,
  `pay`…) and look-alike letters make it high severity. Your own domains are never reported.
- **Quiet start.** The first run records what already exists and alerts only on domains whose first
  certificate is from the last 14 days; after that, every new lookalike domain is announced, in one
  alert per run, through Slack, Teams, email and webhooks (with a `brand_watch` block).
- **Resilient.** crt.sh is often overloaded: when a source fails the run is partial, the other source
  still counts, and the watch is retried within the hour. Runs are claimed atomically across replicas.
- Analysts create, change, run and remove watches; viewers see them; other teams never do. Audited;
  the own-domain list and findings are encrypted at rest. Up to 20 brands per workspace.
- API: `GET/POST /api/brand-watches`, `PATCH`/`DELETE /api/brand-watches/{id}`,
  `POST /api/brand-watches/{id}/run`. Python client: `watch_brand()`, `brand_watches()`.
  Migration 0031. Helm chart 0.61.0.

## [1.70.0] — Phase 70: The case report, in one file

### Added
- **Case report.** On a case, the **Case report** button downloads the whole case as a single
  HTML file for an editor, a lawyer, a client, a court or the file. It contains:
  - the case's purpose, status, handling, tags and summary, with key figures;
  - the **network** as a chart (people, organisations and their links, coloured by type, with
    dashed lines for likely and possible links), the most connected entities and every link with
    its confidence and dates;
  - the **timeline**, oldest first: events, evidence, scans, and the dated facts inside the scans;
  - the **evidence**: each capture's files with their SHA-256, the RFC 3161 timestamp, the chain
    of custody, and an **integrity check made at export** (tampered evidence shows as a problem);
  - the scans and the notes.
- **Safe to open anywhere, for years.** The report is one file. Styles are inline, the chart is
  inline SVG, and its Content-Security-Policy forbids scripts and every outside request, so opening
  it never contacts anyone, a subject's server included. Captured addresses are text, not links.
  It prints cleanly and reads on a phone.
- **Provable.** The report's SHA-256 is returned in `X-Argus-Report-SHA256` and recorded in the audit
  log; each piece of evidence listed gets a `reported` entry in its chain of custody. Protected
  people stay unnamed, and the files themselves stay in the evidence bundle, whose hashes match.
- API: `GET /api/cases/{id}/report.html` (viewers and up; restricted cases stay restricted).
  Python client: `case_report()`. Helm chart 0.60.0.

## [1.69.0] — Phase 69: Fingerprint watches

### Added
- **Watch a fingerprint.** On a favicon, JARM, HASSH or certificate, **Watch for new servers**
  re-runs that entity's Shodan or Censys search every day (or week). The first run records the
  servers sharing it today; after that, every server that starts sharing it raises one alert per
  run, with the new addresses, organisations and countries. A known host on a new port counts as new.
- Alerts flow through the usual outbox: the Monitoring page, Slack, Teams, email and webhooks
  (with a `fingerprint_watch` block naming the fingerprint, its query and the new servers).
- **Monitoring → Watched fingerprints** lists each watch with the servers it knows, when it last
  ran and any error (for example a refused key or an exhausted plan), with **Run now** and remove.
- **Careful with credits.** Each run is one search (one Shodan query credit). Watches are capped at
  50 per workspace, the search is always the entity's own (never free text), and with several
  replicas a due watch is claimed atomically, so it runs once. A failed run is recorded and tried
  again on schedule; it never counts as the baseline.
- Analysts create, run and remove watches; viewers see them; other teams never do. All audited.
  Watched queries and known servers are encrypted at rest. `ARGUS_FINGERPRINT_WATCH_ENABLED`
  (default on, needs monitoring) runs the loop.
- API: `GET/POST /api/fingerprint-watches`, `POST /api/fingerprint-watches/{id}/run`,
  `DELETE /api/fingerprint-watches/{id}`. Python client: `watch_fingerprint()`,
  `fingerprint_watches()`. Migration 0030. Helm chart 0.59.0.

## [1.68.0] — Phase 68: The team's tags and notes on entities

### Added
- **Tag and annotate any entity** from the graph's details panel: tags such as `client-owned`,
  `c2` or `suspect`, and a note. Analysts edit; everyone in the team reads. Every change is audited.
- **Once, everywhere.** Entity ids come from type and value, so tagging `vpn.acme.example` tags it
  in every investigation of the workspace, past and future scans included. Tagged entities wear a
  gold ring on the graph.
- **Queryable.** AQL gains `tag` and `note`. For example `tag:c2`, `tag:*`,
  `type:subdomain -tag:client-owned` and `note~"invoice"`, and they work in patterns
  (`tag:vpn -[RESOLVES_TO]-> ip`). Query results list each entity's tags.
- **In hunts and alerts.** Hunts across investigations and saved-query alerts use the team's tags,
  so "alert me when anything tagged `c2` turns up in a new scan" is one saved query.
- **Private to the team.** Annotations belong to the workspace, other teams never see them, and the
  value, tags and note are encrypted at rest. Tags are trimmed, de-duplicated and limited to 20 of
  40 characters, and notes to 4,000 characters.
- If an entity has no annotation, `tag` and `note` still match a module's metadata key of the
  same name, so existing queries keep their meaning.
- API: `GET /api/annotations`, `GET /api/annotations/tags`, `PUT /api/annotations/{entity_id}`.
  Python client: `annotate()`, `annotations()`. Migration 0029. Helm chart 0.58.0.

## [1.67.0] — Phase 67: Censys searches from Argus, on the Censys Platform

### Added
- **Search Censys from a fingerprint.** With `ARGUS_CENSYS_API_TOKEN` (a Censys Platform personal
  access token) and optionally `ARGUS_CENSYS_ORGANIZATION_ID` (whose credits are used), favicon,
  JARM, HASSH and certificate panels gain Censys buttons next to Shodan's:
  - **How common?**: the number of matching hosts, the top organisations and countries, and the
    rarity verdict, from two aggregates (`POST /v3/global/search/aggregate`);
  - **List hosts**: up to 100 hosts (`POST /v3/global/search/query`), only the fields Argus shows,
    each with **Investigate**.
  - Censys does not document whether searches cost credits, so the buttons say they use the
    plan's credits where it charges. Shodan's count stays labelled free.
- `POST /api/investigation/{id}/internet-search` takes `"engine": "shodan" | "censys"`.
  `GET /api/internet-search` reports both.

### Fixed
- **Censys searches use the Platform's query language.** The copyable searches still used the
  retired Search 2.0 syntax. They now use CenQL exact matches, built in one place
  (`argus/intel/cenql.py`):
  - certificates: `host.services.cert.fingerprint_sha256`;
  - favicons: `host.services.endpoints.http.favicons.hash_sha256` (both listed in Censys's CenQL
    documentation; favicons now match on SHA-256 rather than MD5);
  - JARM: `host.services.jarm.fingerprint`;
  - SSH: `host.services.ssh.hassh_fingerprint`, which is new (the last two from the Platform API's
    data schema).
- Helm chart 0.57.0.

## [1.66.0] — Phase 66: The facts inside a case's scans, on its timeline

### Added
- **Dated facts from every scan** of a case now appear on its timeline, each tied to its entity,
  scan and source:
  - domains registered, last changed and expiring (RDAP);
  - certificates' validity;
  - data breaches;
  - accounts created (platforms' public profiles);
  - companies incorporated and dissolved, and directors appointed and resigned (registers);
  - wallets' first and latest transactions;
  - pages archived by the Internet Archive;
  - documents written and edited (their own metadata);
  - PGP keys created;
  - software end-of-life dates;
  - CVEs added to CISA's exploited list.
- **What changed between scans**: for consecutive scans of the same target, "9 new on
  acme-corp.example" and "1 gone", with the kinds and names of what appeared or disappeared.
- **Honest dates**: a fact keeps the precision its source gave (year, month, day or exact time).
  A date-only fact shows "date" rather than a midnight time, and implausible years (0001, 9999)
  are ignored.
- **One fact, once**: a fact seen by several scans appears once ("seen in 2 scans") and links to the
  latest.
- **In the case's Timeline tab**:
  - two new kinds, *Found in a scan* and *Change between scans*, each with a filter pill;
  - every fact names its source ("Source: the breach notification service · found by hibp");
  - **Show on graph** opens the scan and selects the entity, and **Open the scan** opens a change's scan.
- **API**: `GET /api/cases/{id}/timeline` includes facts (`?facts=false` leaves them out). The CSV
  export includes them too. Uses the 20 most recent finished scans, read from the graph cache and
  processed in a worker thread.
- Helm chart 0.56.0.

## [1.65.0] — Phase 65: Very large graphs stay fast

### Changed
- **Large investigations are drawn with bundles.** Above 1,500 entities, a node with 40 or more
  neighbours of one type shows them as one bundle ("25,000 subdomains"). The pass repeats on the
  bundled graph (the sub-domains' IPs bundle, then their ports), and same-type islands across the
  graph are bundled too. Edges between bundles are merged into one edge with a count.
  - **Click a bundle** to show 300 more of its members, most connected first, placed around it.
    **Regroup** folds them back. A bar says how much is shown ("37 of 50,000 shown · 6 bundles").
  - Nothing is hidden from the analyst. Search finds entities inside bundles and reveals them.
    Query results, attack paths and the selection are never bundled (beyond 300 results, their
    bundles light up instead). The legend, details, neighbours and counts cover every entity.
  - Live scans keep working: new discoveries re-bundle at most every 1.5 s.
- **Measured** in Chromium on synthetic investigations shaped like real scans (`tools/bench/`):

  | Entities | Before | Now: cold open | Now: warm open | Longest freeze | Zoom/pan |
  |---|---|---|---|---|---|
  | 5,000 | browser frozen > 3 min | 1.1 s | 0.6 s | 0.3 s | 30 fps |
  | 20,000 | frozen | 2.0 s | 0.5 s | 0.25 s | 59 fps |
  | 50,000 | frozen | 6.4 s | 0.95 s | 0.45 s | 60 fps |

- **The server keeps up**:
  - A stored investigation's live view is served from the graph cache.
  - The serialised snapshot (28 MB at 50,000 entities) is built in a worker thread and cached for
    finished investigations: a warm 50k snapshot takes 0.35 s instead of 4.7 s.
- **Link analysis scales**:
  - Betweenness is sampled to a fixed work budget (12 samples at 50,000 entities), so the whole
    analysis takes 10 s there instead of about 93 s.
  - The browser only asks for it when the Intelligence tab is opened, and once per investigation.
  - The result reports the sample count (`betweenness_samples`).
- **Smoother interaction on big views**: labels update when zooming pauses rather than on every
  frame, and the force layout uses fewer iterations as views grow.
- **JavaScript tests**: the bundling logic is tested with Node's built-in runner
  (`tests/js/bundles.test.mjs`, run from pytest when Node is installed), including a 50,000-entity
  case.
- Helm chart 0.55.0.

## [1.64.0] — Phase 64: A graph cache, and graph loading off the event loop

### Changed
- **Finished investigations' graphs are cached** for read-only views: the graph, attack paths,
  ATT&CK mapping, people, exports, reports, ratings, queries, link analysis and hunts. On a
  5,000-entity investigation, a repeat load drops from 200–360 ms to 1–3 ms. Opening an
  investigation fires several such requests, so the UI feels instant after the first.
  - Every read checks the investigation's row (status, counts, completion time) first, so a
    changed, re-run or deleted investigation is never served stale. That holds across replicas too.
  - Running scans are never cached.
  - Least recently used graphs are dropped beyond `ARGUS_GRAPH_CACHE_SIZE` (default 16; 0 turns
    it off).
  - Only read-only callers use the cache. Everything that may change a graph still gets its own
    copy, and a test sweeps every investigation endpoint to prove none modifies the shared graph.
- **Large graphs are rebuilt in a worker thread** (above 1,500 rows). A cold load of 5,000
  entities used to block the server for its whole duration; the longest stall is now about 26 ms.
- Link analysis, which is cached per graph object, now also persists across requests.
- New metric: `argus_graph_cache_total{result="hit|miss"}`.
- Helm chart 0.54.0.

## [1.63.0] — Phase 63: Shodan pivots on demand

### Added
- **Search Shodan from a fingerprint**: with `ARGUS_SHODAN_API_KEY` set, the panel of every favicon,
  JARM, HASSH and certificate offers two buttons.
  - **How common? (free)** uses Shodan's count endpoint, which spends no query credits. It
    returns how many servers share the fingerprint, the top organisations and countries, and a
    plain verdict: *unique*, *rare* (≤ 50, a strong lead), *uncommon* (≤ 5,000) or *common* (a
    default configuration that says little).
  - **List hosts (1 credit)**: up to 100 of those servers, with IP, port, host names,
    organisation, country, product and when Shodan saw them. Each has an **Investigate** button,
    which starts a new investigation that still has to be authorised.
- Analyst-initiated only, never automatic. The search is the entity's own (not free text), the
  key never leaves the server, appears in no error or log line and is never sent to the
  browser. Every lookup is audited (mode, entity type, total) and rate-limited (10 a minute per
  key). Results are not written into the scan's record.
- **API**: `GET /api/internet-search`, `POST /api/investigation/{id}/internet-search`. **Python
  client**: `internet_search()`.
- Helm chart 0.53.0.

## [1.62.0] — Phase 62: Server fingerprints (JARM, HASSH) and certificate pivots

### Added
- **JARM** (`jarm`, active): the Salesforce TLS fingerprint. Ten unusual ClientHellos go to port
  443 of each domain and sub-domain, and to known TLS ports (443, 4443, 8443, 9443, 10443). The
  server's choices are hashed into 62 characters. Servers with the same JARM are configured the
  same way, which clusters C2 servers, phishing kits and an organisation's estate.
  - A shared node links every host with the same JARM. It carries Shodan (`ssl.jarm:`) and Censys
    (`services.jarm.fingerprint:`) searches.
  - The implementation follows the original reference byte for byte. It was checked against
    pyjarm on five live OpenSSL configurations (identical hashes), and the tests pin a hash
    computed by pyjarm's hasher.
  - pyjarm itself has two quirks Argus avoids: it fails the whole fingerprint when one probe's
    connection is reset, and it merges two ALPN entries.
- **HASSH-server** (`ssh_fingerprint`, active), on SSH ports found by other modules (22, 2222,
  22222, or anything identified as SSH): the banner, and the MD5 of the server's key-exchange,
  cipher, MAC and compression lists, read from its first clear-text packet.
  - No key exchange and no login attempt.
  - A shared node links identically built SSH servers, with a Shodan search (`ssh.hassh:`).
  - The SSH software and version (e.g. *OpenSSH 7.4*) become a technology.
  - Checked against a live paramiko server.
- **Certificate pivots**: certificates now carry their SHA-1 fingerprint and searches for every
  other host serving them (Shodan `ssl.cert.fingerprint:`, Censys
  `services.tls.certificates.leaf_data.fingerprint:`).
- **One fingerprint panel** in the graph for favicons, JARMs, HASSHes and certificates: what the
  hash means, how many hosts here share it, its facts, and copyable searches.
- Both modules are active and use raw sockets. Passive-only and routed scans skip them, and they
  connect only to vetted public addresses. Shared fingerprints link with confidence 0.5.
- The demo gains a JARM shared by two hosts, an SSH server with its HASSH, and certificate searches.
- Helm chart 0.52.0.

## [1.61.0] — Phase 61: Saved queries, hunts and query alerts

### Added
- **Saved queries**: name an Argus Query Language query and share it with the team (up to 200 per
  workspace; name, query and description are encrypted at rest when the vault is on). Run it,
  hunt with it, mute it or delete it from the graph's Query tab.
- **Hunts**: run any query across the workspace's most recent investigations (25 by default, up to
  200), newest first. See which investigations match, how many times and with what, and open one
  with a click. Hunts are bounded by a 25-second budget (`partial` when it runs out) and a
  per-user rate limit, every graph is queried in a worker thread, and each hunt is audited.
- **Query alerts**: a saved query marked *alert* runs after every completed scan in its workspace.
  It raises an alert, with its own severity, when the scan matches something the previous scan of
  the same target did not. Entity IDs are deterministic, so "new" is exact. The first scan of a
  target alerts on any match, and `| limit` or `| count` never hide matches from the comparison.
  Alerts go through the existing outbox: email, webhooks, Slack, Teams, Jira, ServiceNow, Splunk
  and Sentinel. Webhook events carry `alert.saved_query` (name, query, counts, sample of new
  matches).
- **API**: `GET/POST /api/saved-queries`, `PATCH/DELETE /api/saved-queries/{id}`,
  `POST /api/saved-queries/{id}/hunt`, `POST /api/hunt`. Queries that don't parse are refused with
  the position of the problem.
- **Python client**: `query()`, `links()`, `hunt()`, `saved_queries()`, `save_query()`.
- Database migration 0028 (`saved_queries`). Helm chart 0.51.0.

## [1.60.0] — Phase 60: Favicon pivoting

### Added
- **Favicon fingerprints** (`favicon_pivot`, active): for each domain and sub-domain, Argus fetches
  `/favicon.ico`, or the icon the homepage declares (`<link rel="icon">`). It checks the bytes really
  are an image (not an HTML "soft 404") and records a favicon node keyed by its hash.
  - **Shared icons become hubs**: every host serving the same icon links to the same node, which
    exposes an operator's estate, every instance of one product, or one phishing kit.
  - **Find it elsewhere**: ready-to-paste searches for Shodan (`http.favicon.hash:`), FOFA
    (`icon_hash=`), ZoomEye (`iconhash:`) and Censys (MD5). Argus never runs them: the analyst
    pastes them in, so the search engine sees the query, not the target.
  - The Shodan-compatible MurmurHash3 is pure Python, checked against the reference vectors.
  - Icon links to private addresses are refused by the egress guard without failing the module.
    Third parties' assets (`out_of_scope`) are never contacted.
  - A shared icon is a lead, not proof (default icons are common), so the relation's confidence
    is 0.6.
- **Graph panel** for favicon nodes: hosts serving it, hashes, and the four searches with Copy.
- **AQL example**: `category:favicon degree>=2 <-[USES_TECH]- *` lists hosts that share an icon.
- The demo includes an icon shared by three of Acme's hosts.
- Helm chart 0.50.0.

## [1.59.0] — Phase 59: The Argus Query Language and link analysis

### Added
- **Argus Query Language (AQL)**: ask the graph questions from the graph's search box, the
  API or the command line.
  - Filters: `type:ip_address geo.country:RU`, `value~"^vpn"`, `label:*acme*`,
    `confidence<0.8`, `intel.kev:*` (present), `AND` / `OR` / `NOT` / `-term` / brackets,
    dotted metadata paths, and type aliases (`ip`, `sub`, `org`, `cve`…).
  - Relation patterns: `type:domain -[RESOLVES_TO]-> ip <-[RESOLVES_TO]- sub`, `A -- B`, several
    relation types with `|`. Only complete chains match.
  - Shortest routes: `path from type:email to type:ip_address max 6`.
  - Shaping: `| sort pagerank desc | limit 20`, `| group type`, `| count`.
  - Read-only and bounded: query length, filters, regex size (no nested repetition), rows, paths
    and hops are all capped. Errors say what's wrong and point at the character.
- **Link analysis** (pure Python, cached per graph version): PageRank, betweenness (sampled on
  large graphs), Louvain clusters with modularity, articulation points (single points of failure)
  and one combined *key entity* score. Queryable as `pagerank`, `betweenness`, `community`,
  `key_score` and `articulation`.
- **In the graph view**:
  - the search box runs queries (plain names still jump to the entity), and Esc clears;
  - a new **Query** tab lists results, routes and groups, with examples and syntax;
  - matches light up on the graph, and clicking a route shows only that route;
  - the Intelligence tab gains **Link analysis**: key entities, brokers, single points of
    failure and clusters, with **Colour by cluster**.
- **API**: `POST /api/investigation/{id}/query`, `GET /api/investigation/{id}/links`,
  `GET /api/query/help`. Stored graphs are analysed off the event loop.
- **CLI**: `argus --query "<AQL>" --on <investigation id | exported JSON>` (`--query-json` for raw
  output). `IntelligenceGraph.from_dict` rebuilds a graph from a JSON export.
- Helm chart 0.49.0.

## [1.58.0] — Phase 58: Speed and a smoother live graph

### Changed
- **Compressed API responses**: responses over 1 KB are gzipped. Graphs, exports and reports are
  5–10× smaller on the wire (the demo graph: 36.8 KB → 6.9 KB). Security headers and metrics still
  apply to the final response. `ARGUS_COMPRESS_RESPONSES=false` turns it off, for example behind a
  proxy that already compresses.
- **A smoother live graph**: the browser now applies live discoveries once per animation frame in
  a single graph batch, with one redraw, one panel refresh and one feed line ("Found 37 entities:
  21 subdomain, 9 ip address…") however busy the scan is. Only the newest progress report in a
  frame is used. Background tabs catch up four times a second.
- **A quieter stream**: per-module start and finish events stay on the event bus (metrics and
  plugins) but are no longer sent to browsers. No view used them, and they were most of the
  messages on a busy scan.
- Helm chart 0.48.0.

## [1.57.0] — Phase 57: Legal documents and privacy

### Added
- **Legal documents** served by the account service at `/legal/...`:
  - Terms of Service, Privacy Policy, Acceptable Use Policy, Refunds and Cancellation, Data
    Processing Agreement and Subprocessors.
  - Written for how Argus works, and filled in with the owner's business details (owner
    console → **Legal**).
  - Marked as a draft until published. Health warns until they're complete, published and
    reviewed by a lawyer.
  - `GET /api/legal` lists them.
- **Accepting them**:
  - Once published, new accounts must agree (version and time recorded).
  - Publishing a new version asks every customer to accept again: Argus Personal shows the
    updated terms, and new work waits until they're accepted. Reading, exporting and
    backups keep working.
  - `POST /api/accounts/accept-terms`.
- **Customers' data rights**, in Argus Personal (Settings → Your data):
  - Download my account data: everything the account service holds about the account.
  - Delete my account: the customer is deleted at Stripe (ending billing), and their
    personal details, computers, emails, links and invitations are erased. Payment records
    stay anonymously for tax law. Cases stay on the computer.
  - `POST /api/accounts/export`, `POST /api/accounts/delete`, `GET /api/personal/account-data`,
    `POST /api/personal/delete-account`.
- **Retention**: records of sent emails, expired links and invitations go after 6 months;
  computers signed out over a year ago are forgotten (daily).
- **Case reviews**: cases untouched for 12 months are marked for review in the Cases list
  (`ARGUS_CASE_REVIEW_MONTHS`).
- Database migration 0027 (terms acceptance and account deletion). Helm chart 0.47.0.

## [1.56.0] — Phase 56: Backups and alerts

### Added
- **Backups in Argus Personal** (Settings → Backups): automatic, encrypted backups of
  everything (cases, evidence, settings, audit log and the encryption key) to a folder of the
  investigator's choice, ideally a synced cloud folder or an external drive.
  - Encrypted with a backup password (scrypt + AES-256-GCM in authenticated 4 MB pieces). The
    password is never stored, and nothing readable is ever written to the backup folder.
  - Every 6 or 12 hours, daily or weekly; keeps the latest N; *Back up now*.
  - *Check it*: opens a backup and verifies every file's fingerprint, changing nothing.
  - *Restore it*: checked first, then swapped in at a restart (the desktop app restarts itself).
    The previous data is kept in a `before-restore-<date>` folder.
  - Failing backups are retried within the hour and reported at sign-in; a weekly reminder
    when they're off. Backups keep working when a subscription has lapsed.
- **Backups for SQLite servers**: `ARGUS_BACKUP_DIR`, `ARGUS_BACKUP_PASSWORD`,
  `ARGUS_BACKUP_EVERY_HOURS`, `ARGUS_BACKUP_KEEP`; and `argus --backup-to`, `--backup-check`,
  `--backup-restore`.
- **Owner alerts** by email:
  - Health problems as they start (one email for several), a daily reminder while they last,
    and "Fixed" when they're resolved.
  - Disputes opened or lost, failed payments (once per customer every few days), new paying
    customers.
  - An optional daily summary.
  - Owner console → **Alerts**: choose what to get and where, send a test alert, see recent
    alerts (`ARGUS_OWNER_ALERTS_ENABLED`, `ARGUS_OWNER_ALERT_EMAIL`, `ARGUS_OWNER_ALERT_PAYMENTS`,
    `ARGUS_OWNER_ALERT_NEW_CUSTOMERS`, `ARGUS_OWNER_DAILY_SUMMARY`, `ARGUS_OWNER_SUMMARY_HOUR`).
- Health checks: **Backups** and **Disk space**.
- API: `GET/PUT /api/backups`, `POST /api/backups/run`, `/check`, `/restore`,
  `/restore/cancel`; `GET /api/owner/console/alerts`, `POST /api/owner/console/alerts/test`.
- Helm chart 0.46.0.

## [1.55.0] — Phase 55: The desktop app

### Added
- **Installers for Argus Personal**: a Windows installer (no administrator rights needed), a
  Mac disk image (Apple silicon) and a Linux archive, with Python, Argus and a private
  screenshot browser bundled. Built, tested and attached to each release by the new
  *Desktop app* workflow; run it by hand for test builds.
- **The app**: the icon opens Argus in the browser on 127.0.0.1, on the first free port from
  8765. A second click opens the running copy. No terminal window; a rotating log file in the
  data folder. Cases live in the data folder, so updates and uninstalls never touch them.
- **Quit Argus** in Settings → *Argus on this computer*, which also shows the version
  (`POST /api/personal/quit`, same-origin only).
- **Update notice**: set the newest version and download page in the owner console's new
  *Desktop app* tab (`ARGUS_DESKTOP_LATEST_VERSION`, `ARGUS_DESKTOP_DOWNLOAD_URL`). Installed
  copies ask once a day (`POST /api/accounts/app-version`, sending only the installed version)
  and offer a one-click download.
- Evidence captures also find Chrome or Edge in their usual Windows and macOS locations.
- Optional code signing and notarisation from GitHub secrets; installers carry your account
  service address and licence key from repository variables (public values only).
- Helm chart 0.45.0.

## [1.54.0] — Phase 54: Page history and reverse image search

### Added
- **Page history** (free, Internet Archive). In a case: every *different* version of a web page
  the archive holds (identical copies folded together), oldest to newest. Open any version,
  or **capture it as evidence** with the usual fingerprint and chain of custody, noted as an
  archived copy and its date.
- **Reverse image search**. In a case: where else a picture appears on the web.
  - TinEye results inside Argus (own key, or Argus credits): each site and page the picture is
    on, when TinEye first saw it, and its size.
  - One-click searches on Google Lens, Bing, Yandex and TinEye. These also appear under any
    profile picture in the entity panel, with a note that those sites see the picture's
    address and your connection.
- Both go out through the case's network route (an anonymous case never asks directly) and
  are recorded in the audit log.
- Settings: `ARGUS_WAYBACK_URL` (empty turns page history off), `ARGUS_TINEYE_API_KEY` (also in
  the owner console and in Argus Personal's own keys). Helm chart 0.44.0:
  `secrets.tineyeApiKey`.
- API: `GET /api/cases/{id}/page-history?url=`, `GET /api/image-search`,
  `POST /api/cases/{id}/image-search`.

## [1.53.0] — Phase 53: More company registers, insolvency notices and court records

### Added
- **France** (free): company details from SIRENE and the national register, and directors and
  partners with their roles in English (the French kept alongside). A person's directorships
  across every French company: by name only it's a possible match; with the same month of
  birth, a strong one.
- **Norway** (free, Brønnøysund): details, bankruptcy and winding-up flags, and the managing
  director, chair, board and auditor.
- **Finland** (free, PRH): details, former names, line of business, address, and bankruptcy or
  liquidation.
- **OpenCorporates** (own key, or Argus credits): company registers of about 140 countries
  and US states, with current officers. For a person: companies where someone of that name is
  an officer, as possible matches. Runs on the scan's own target only, so costs stay
  predictable. When the same name is registered in several places, the investigator is told.
- **The Gazette** (free): UK insolvency notices (winding-up, administration, receivership,
  bankruptcy) by exact name, newest first. Notices about people are possible matches.
  Deceased estates are never searched.
- **US court cases** (CourtListener; own key from a free account, or Argus credits): federal
  dockets where the company or person is a party.
- The findings show in the entity panel, person profiles and their PDFs. Notice and filing
  dates go on the profile's timeline.
- Directors' dates of birth are kept as month and year only. People a register marks as
  deceased are left out.
- Names written properly: hyphenated and apostrophe names, and company endings such as AS,
  ASA, Oy, Oyj, GmbH and SARL.
- Settings: `ARGUS_OPENCORPORATES_API_KEY`, `ARGUS_COURTLISTENER_API_KEY` (also in the owner
  console and in Argus Personal's own keys), `ARGUS_FRANCE_REGISTRY_URL`,
  `ARGUS_NORWAY_REGISTRY_URL`, `ARGUS_FINLAND_REGISTRY_URL` and `ARGUS_GAZETTE_URL` (empty
  turns a source off). Helm chart 0.43.0.

## [1.52.0] — Phase 52: The owner console

### Added
- **Owner console** at `/admin`: the server owner's own control panel.
- **Only the owner can open it**:
  - one owner, ever: the email in `ARGUS_OWNER_EMAIL`; set-up also needs the server's
    administrator key and closes for good once done;
  - sign-in is a password plus a 6-digit authenticator code (RFC 6238), with ten one-time
    recovery codes; no code is accepted twice;
  - five wrong attempts lock the console for 15 minutes; sign-ins, lock-outs and security
    changes are emailed to the owner;
  - sessions last 8 hours, end after 30 minutes idle, are stored only as hashes, and are
    same-site only; sensitive changes need a code from the last 10 minutes;
  - API keys, workspace users and single sign-on can never open the console. Once the owner
    exists, no administrator key is ever recreated automatically;
  - an optional "owner only" switch stops API keys and other administrators from
    administering the server.
- **Overview**: health checks with plain fixes (database, public address, account service,
  encryption, Stripe and its webhook, email and its queue, background jobs), the business at
  a glance, and recent activity.
- **Settings changed from the browser, applied live** (no restart, other servers within 30
  seconds):
  - Stripe keys, prices and credit packs, with a "Test connection" button;
  - the mail server, senders and support address, with "Send test email";
  - sign-ups, trial length and offline days;
  - the paid data sources' keys;
  - each plan's monthly credits and computers.
  - Each value is checked before saving. Secrets are encrypted, never shown back and never
    logged. Clearing a value returns to the deployment's own.
- **Security**: sessions (sign out one or all others), change password, new recovery codes,
  move the authenticator to a new phone, every API key (revoke), and the activity log with
  filters.
- The owner's session also opens the main app as its administrator.
- Helm chart 0.42.0: `config.ownerEmail`. Migration 0026 (`owner`, `owner_sessions`).

## [1.51.0] — Phase 51: Four plans, each with what it needs

### Changed
- **Plans** are now Bring your own keys, Personal, Professional and Business. The Team plan is
  renamed **Business** (migration 0025); `ARGUS_STRIPE_PRICE_TEAM` becomes
  `ARGUS_STRIPE_PRICE_BUSINESS`, and Helm's `config.stripePriceTeam` becomes
  `config.stripePriceBusiness`.

### Added
- **What each plan includes**:
  - every plan: all investigation tools;
  - Professional and Business add monitoring and watches (scheduled scans, account and breach
    watches, scheduled reports), branded reports and playbooks;
  - Business adds team tools;
  - the free trial includes the Professional features.
- **Enforced from the licence**:
  - the plan's features are inside the signed licence, so Argus Personal enforces them even
    offline;
  - a locked action answers with which plans include it;
  - what already exists stays readable, and background runs pause.
- **Bring your own keys plan** (`ARGUS_STRIPE_PRICE_BYOK`): the cheapest, with no included
  credits and one computer.
- **Your own API keys** in Argus Personal (Settings), for Companies House, web search and Claude:
  - stored encrypted on the computer with its own key (created on first start), never sent to
    the account service;
  - lookups with them go direct and cost no credits;
  - available on every plan.
- **Business**:
  - an optional one-off set-up fee (`ARGUS_STRIPE_PRICE_BUSINESS_SETUP`), charged with the
    first payment;
  - the owner can **create accounts** for their people, who are emailed a link to choose their
    password; existing Argus accounts get an invitation instead, so no account is taken over;
  - the owner can **sign a member out of every computer** (a lost laptop).
- Settings: plan cards showing what each plan includes, with a seat count for Business, and
  "Not in your plan" for locked features.
- API: `GET/PUT/DELETE /api/personal/keys/{provider}`, `POST /api/teams/add`,
  `POST /api/teams/sign-out-member`, and the Argus Personal equivalents. Helm chart 0.41.0.

## [1.50.0] — Phase 50: Team plans

### Added
- **Team plan**, priced per seat (`ARGUS_STRIPE_PRICE_TEAM`):
  - the owner chooses the seats at checkout and changes them in Manage billing;
  - 1,000 shared credits a month per seat, plus any credit packs the owner buys;
  - each member has 2 computers.
- **Invitations by email**:
  - the owner invites from Settings; an invitation works once, for a week, and is stored only
    as a hash; inviting again replaces it, and the owner can cancel it;
  - invitations can't exceed the free seats.
- **Joining** at `/join-team` on the account service, with an existing Argus account (its
  password) or a new one:
  - someone with their own paid subscription is asked to cancel it first, so nobody pays
    twice;
  - nobody can join a full team or two teams.
- **Members follow the team**:
  - their licence carries the team's plan, status and paid-until date;
  - if the team's subscription lapses, ends or is on hold, every member goes read-only (cases
    kept);
  - someone removed, or who leaves, goes back to their own account as it was.
- **Shared credits, private work**:
  - lookups are charged to the team's pool, and each records which member used it;
  - the owner sees members, invitations, last sign-in and credits used this month, never
    what was looked up or anything about anyone's cases.
- Emails: team invitation, member joined, member left, removed from the team. Members get no
  trial reminders.
- Business page: team seats and members; revenue counts every seat; members aren't counted
  as trials.
- API: `POST /api/teams/status|invite|cancel-invite|remove|leave|join/info|join`; Argus
  Personal: `GET /api/personal/team`, `POST /api/personal/team/invite|cancel-invite|remove|leave`.
  Migration 0024.
- Helm chart 0.40.0: `config.stripePriceTeam`.

## [1.49.0] — Phase 49: Refunds and disputes

### Added
- **Refunds** (`charge.refunded`):
  - for a credit pack, the credits bought with the refunded part are taken back (a partial
    refund takes back its share). Credits already spent can't be taken back: the balance never
    goes below zero, and the shortfall is recorded;
  - for a subscription payment, the refund is recorded and the customer emailed. Access is
    unchanged: cancelling the subscription in Stripe ends it as usual.
- **Disputes / chargebacks** (`charge.dispute.created`, `charge.dispute.closed`):
  - the account is put **on hold**: read-only, cases kept, sign-in refused with "contact
    support";
  - the payment's credits are held back, and the customer is emailed kindly in case it was a
    mistake;
  - subscription changes arriving during the hold don't lift it;
  - **won** (or withdrawn): the hold is lifted, the account returns to its earlier status and the
    credits are returned, with an email;
  - **lost**: the hold stays, and the Business page asks the operator to decide.
- Business page: open and lost disputes under "Needs attention"; refunds and disputes for the
  period; each account's payments with refund and dispute state.
- Emails: refund issued, account on hold, account active again.
- New table `billing_payments` (migration 0023). Credit ledger entries of kind `reversal`.
- Stripe webhook: also send `charge.refunded`, `charge.dispute.created`, `charge.dispute.closed`.

## [1.48.0] — Phase 48: Account emails and password resets

### Added
- **Emails to account holders** from the account service (through the SMTP server already used
  for notifications):
  - account emails, always sent: welcome; payment received (plan active); payment failed (with
    the grace period and how to fix it); payment went through after all; plan changed;
    cancellation confirmed (with the last day); subscription ended; credits added; password
    reset; password changed;
  - reminders: trial ending in three days, trial ended. Each has a one-click unsubscribe link and
    a `List-Unsubscribe` header (RFC 8058 one-click supported); the choice is remembered.
- **Reliable sending**: an outbox (migration 0022) so each email is sent exactly once however
  often Stripe repeats an event or however many servers run; retried for about half a day when
  the mail server is down; the text is deleted once sent; history per account on the Business
  page.
- **Forgot your password?** on Argus Personal's sign-in screen opens the account service's reset
  page. The emailed link works once, for an hour, carries its secret in the URL fragment (never in
  server logs) and is stored only as a hash. A new password signs every computer out and is
  confirmed by email. The answer never reveals whether an email has an account; at most three
  links an hour per account.
- Settings: `ARGUS_ACCOUNT_EMAILS_ENABLED`, `ARGUS_ACCOUNT_EMAIL_FROM`, `ARGUS_SUPPORT_EMAIL`.
  Helm chart 0.38.0: `config.accountEmails`, `config.accountEmailFrom`, `config.supportEmail`.
- API: `POST /api/accounts/password-reset`, `POST /api/accounts/password-reset/confirm`,
  `GET|POST /api/accounts/emails/unsubscribe`; `GET /api/accounts/{id}` lists the account's emails.

## [1.47.0] — Phase 47: Business dashboard

### Added
- **Business** page for the operator of the account service (platform admins only; shown only
  on an account service):
  - paying customers by plan, monthly recurring revenue at Stripe's prices (yearly prices count
    a twelfth), customers on trial and the share of finished trials that became paying, and
    payments due;
  - new accounts per week for twelve weeks (with how many now pay), with a table view;
  - credits used by source over 30 days, 90 days or 12 months (refunded lookups don't count),
    the accounts using the most, credits bought and credit packs sold;
  - **Needs attention**: payments failing, trials ending within three days, trials that ended
    without paying, accounts locked after wrong passwords, paying customers out of credits.
- **Accounts**: search by email, name, account or Stripe id, filter by status and plan, and
  download as CSV (cells that could run as spreadsheet formulas are neutralised; the export is
  audited). Open an account to change its plan, status or paid-until date, add or remove credits
  with a reason, sign a computer out, and see its credit history.
- API: `GET /api/business/summary?days=`, `GET /api/business/accounts`,
  `GET /api/business/accounts.csv`; `/api/auth/config` says whether this is an account service.

## [1.46.0] — Phase 46: Payments

### Added
- **Stripe payments** on the account service:
  - subscribe to the Personal or Professional plan, or buy a credit pack, on Stripe's own
    payment page (Argus never sees card details);
  - **Manage billing** opens Stripe's customer portal: card, invoices, change plan, cancel;
  - prices are set in Stripe and shown as Stripe has them.
- **Webhook** `POST /api/billing/webhook` keeps accounts in step:
  - paid or renewed: plan, *active*, paid until the period's end;
  - failed payment: *past_due*, still usable for at least 7 days while Stripe retries;
  - cancelled: usable to the end of the paid period, then read-only;
  - credit pack paid: credits added;
  - upgrade mid-month: the bigger allowance at once.
- Safeguards: signature checked (secret, exact message, five-minute window), each event applied
  once (new `billing_events` table, migration 0021), subscriptions re-read from Stripe so
  out-of-order events can't undo a payment, an old subscription ending can't cancel a new one,
  test-mode services refuse live events, return addresses restricted, audit entries.
- Argus Personal: Subscribe, Buy credits and Manage billing in Settings; returning from Stripe
  checks the subscription straight away.
- API: `GET /api/billing/catalogue`, `POST /api/billing/checkout`, `POST /api/billing/portal`;
  Argus Personal: `GET /api/personal/billing`, `POST /api/personal/billing/checkout`,
  `POST /api/personal/billing/portal`.
- Settings: `ARGUS_STRIPE_SECRET_KEY`, `ARGUS_STRIPE_WEBHOOK_SECRET`,
  `ARGUS_STRIPE_PRICE_PERSONAL`, `ARGUS_STRIPE_PRICE_PROFESSIONAL`, `ARGUS_STRIPE_CREDIT_PACKS`,
  `ARGUS_BILLING_RETURN_URL`. Helm chart 0.36.0: `secrets.stripeSecretKey`,
  `secrets.stripeWebhookSecret` and the `config.stripe*` values.

## [1.45.0] — Phase 45: Relationships over time, and exports

### Added
- **Time slider on the link chart**: drag through the years to see the network as it stood:
  - relationships appear in the year they began and disappear after they ended;
  - people with no relationship that year fade;
  - **Play** steps through the years;
  - relationships with no dates can be shown or hidden.
- **Picture**: download the link chart as a PNG.
- **PDF report of the network**:
  - the chart as on screen, the most connected people, go-betweens and groups, every
    relationship (kind, how sure, when, how it was found), and who is not connected yet;
  - with the slider set, the network as it stood that year.
- **Profile PDF**: a person's or organisation's full profile, with a Download PDF button in the
  profile window.
- Both PDFs:
  - are marked *CONFIDENTIAL: contains personal data* on every page, with the case, the time
    generated and page numbers;
  - say that likely and possible relationships and name matches are leads, not facts;
  - never name protected people;
  - are recorded in the audit log.
  - The chart picture sent by the browser is checked and re-drawn as a clean PNG before it goes
    into the PDF.
- API: `POST /api/cases/{id}/network.pdf` (`as_of`, `chart_png`) and
  `POST /api/cases/{id}/entities/{item}/profile.pdf`. Python client: `network_pdf()`,
  `profile_pdf()`.

## [1.44.0] — Phase 44: People from scans, and person profiles

### Added
- **People join the case from scans automatically.** When a scan linked to a case finishes (from
  the case, or from a playbook), the people and organisations it is fairly sure of (80% or more)
  are added to the case, with the relationships between them:
  - officers become *director of*, people with significant control *owner of*, an account's owner
    *uses*, wallets spent together *shares a wallet with*;
  - start and end dates are kept;
  - each entry notes the scan it came from and what the scan learned (role, date of birth,
    nationality, a possible sanctions match…);
  - nothing is added twice (the same kind and value, ignoring case and spacing). Things found
    only about third parties, and very weak finds, are left out.
- **"From scans"** in a case's People & entities card: everything a linked scan found that could
  join the case (accounts, usernames, emails, phones, wallets, places, and less certain people),
  ticked to add, with the relationships between them.
- **Person profiles**: click a person or organisation (in the case, or "Open full profile" on the
  link chart) for everything the case knows about them:
  - details and notes;
  - relationships, with kinds, dates and evidence;
  - accounts and contacts, and places;
  - their place in the network (key person, go-between, group);
  - what linked scans found: date of birth, nationality, directorships with dates, possible
    sanctions matches (with contradicting details), Offshore Leaks, public profile details;
  - a timeline from events, relationships and company registers;
  - every note, event and evidence document that names them or their usernames and contacts,
    with the passage around each mention.
- Protected people have no profile, and are blanked out of the passages shown in others'
  profiles. Viewing a profile is recorded in the audit log.
- API: `GET`/`POST /api/cases/{id}/scan-people`, `GET /api/cases/{id}/entities/{item}/profile`.
  Python client: `profile()`, `scan_people()`, `add_scan_people()`.

## [1.43.0] — Phase 43: Relationship mapping and the link chart

### Added
- **Kinds of relationship** for links between people and organisations, in six groups:
  - **family**: spouse or partner, parent, sibling, relative;
  - **work**: works for, colleague, director or officer, co-director;
  - **business and money**: owns or controls, business partner, client, pays or funds;
  - **social**: friend, associate, communicates with, follows online;
  - **shared details**: shares a phone, email, address, wallet or website; uses;
  - **other**.
  - Each kind knows whether it reads the same both ways.
  - Links can also record when the relationship began and ended, the evidence that shows it,
    and how it was found.
- **Suggested relationships**, found in the case's own material and never added automatically:
  - **company registers** from linked scans: officers and owners of the case's companies, and
    co-directors (marked when their appointments didn't overlap);
  - **shared details**: people linked to the same phone, email, address, wallet or website, or
    with the same detail recorded about them (labels such as "Mobile" or "Home address" are
    understood);
  - **same employer** recorded;
  - **named together** in the same note or evidence document.
  - Each suggestion says why and how sure it is.
- **Network analysis** (`GET /api/cases/{id}/network`):
  - the most connected people;
  - go-betweens who link otherwise separate groups;
  - the groups themselves;
  - people not connected to anyone yet.
- **How two people are connected** (`GET /api/cases/{id}/network/path`): the best-supported chain
  of relationships, as strong as its weakest link, plus the connections they share.
- **Link chart** tab in every case:
  - an interactive map coloured by kind of relationship, with line style showing how sure each
    link is;
  - filters, and colouring by type or by group;
  - details and relationships for each person;
  - tracing the chain between two people;
  - suggestions to add with one click.
- **Protected people** (for example, children):
  - shown on the link chart only as "Protected person";
  - left out of suggestions and of the analysis lists;
  - for the AI analyst, their entry is removed and their name blanked out of every note and
    document it reads.
- Python client: `case_network()`, `connection()`, `suggested_relationships()`.

## [1.42.0] — Phase 42: Bigger username search, and same-person checks

### Added
- **A second community username catalog**: Maigret's (MIT licence), read at run time like
  WhatsMyName:
  - about 8,000 usable sites;
  - the most visited 3,000 are checked by default (`ARGUS_USERNAME_CATALOG_EXTRA_LIMIT`);
  - site engines (shared forum software) are applied;
  - entries Argus can't check safely are skipped (no HTTPS, redirect-only checks, disabled,
    unreadable rules).
  - Each site is checked once across all lists, by name and by address, and the hand-checked
    list wins over WhatsMyName, which wins over Maigret.
  - As before, every hit is checked against a random, certainly-unregistered name.
  - Settings: `ARGUS_USERNAME_CATALOG_EXTRA_URL` and `ARGUS_USERNAME_CATALOG_EXTRA_FILE` (for
    offline use).
- **Profile details from any site**: for accounts on sites without an official API, Argus reads
  the public page's link-preview information:
  - the name, bio, photo and location (OpenGraph, Twitter cards, JSON-LD `Person`);
  - links to the owner's other accounts (`sameAs`, `rel="me"`).
  - Titles that are only the handle or the site's name, sales-pitch descriptions and sign-in
    pages are ignored.
- **Same person or not**: each account's public profile is compared with the person's other
  accounts:
  - **agreements**: a link between them, both linking to the same website, the same photo, the
    same name (compared word by word), similar bios, the same place;
  - **conflicts**: different real names, different places.
  - Accounts found only because the username exists are upgraded to *strong* when another
    account clearly matches.
  - Accounts are marked **Doubtful** when everything points to a different person.
  - The People page shows the reasons for each.
- Profiles keep their outbound links, for these comparisons.

## [1.41.0] — Phase 41: The case vault

### Added
- **Case vault** (Argus Personal and other single-computer installations): cases, evidence and
  scan results encrypted on disk with the investigator's passphrase.
  - **Keys:**
    - a random 256-bit data key encrypts the data with AES-256-GCM: a fresh nonce for every
      value, and each value bound to its column;
    - the data key is stored only wrapped, by a key derived from the passphrase with scrypt (128
      MiB of memory per attempt), and separately by a one-time **recovery code** shown once at
      set-up;
    - changing the passphrase re-wraps the key without re-encrypting the data;
    - a new recovery code can be issued, and the old one stops working.
  - **Encrypted:**
    - case titles, purposes and summaries;
    - notes, entities, links and events;
    - evidence addresses, titles, notes, manifests and files, and custody details;
    - watched accounts' profiles and history;
    - playbook runs;
    - scan targets, and everything scans found;
    - audit event details, alerts, monitors, reports and their files, and queued notifications.
    Identifiers, dates, statuses and counts stay readable.
  - **No leftovers on disk.** Deleted and overwritten data is zeroed (`secure_delete`), and after
    encrypting or decrypting the database file is rebuilt and its write-ahead log emptied. A test
    reads the raw files to prove the case's words are no longer there.
  - **Locked:**
    - every API request except unlocking, sign-in and health checks answers `423 Locked`, and the
      web interface shows an unlock screen;
    - background jobs (monitors, account watches, scheduled reports, the scan janitor) wait;
    - start-up recovery of interrupted scans and playbooks runs once it is unlocked.
  - **Auto-lock** after `ARGUS_VAULT_IDLE_MINUTES` (15) without activity, never during a scan or
    playbook. A lock button sits in the top bar.
  - **Unlocking:**
    - attempts are rate-limited per caller and overall;
    - failed attempts are written to the audit log at the next successful unlock (the audit log
      is itself encrypted).
  - **Turning it on or off** encrypts or decrypts everything, resumably: an interrupted pass
    finishes at the next unlock.
  - Search, history filters and comparisons with earlier scans keep working: with the vault on,
    they match after decryption.
- API: `/api/vault/status`, `/enable`, `/unlock`, `/lock`, `/passphrase`, `/recovery-code`,
  `/disable`. Python client: `vault_status()`, `unlock_vault()`, `lock_vault()`.

## [1.40.0] — Phase 40: Network ranges

### Added
- **Network ranges** (`network_ranges`), from the official internet registries (RIPEstat and
  RDAP, free and public; the target is never contacted):
  - **for an IP address**: the address block it belongs to, who it is registered to, the
    country, the registry, the abuse contact, and the network (ASN) announcing it;
  - **for a network (ASN)**: its holder and every address range it announces, IPv4 and IPv6,
    with the number of IPv4 addresses;
  - **for a company**: networks registered in its name, matched name against name. A match is
    marked as likely, to be confirmed.
  - Addresses and networks of **cloud and hosting providers** (Amazon, Cloudflare, Google,
    Microsoft, OVH, Hetzner…) are marked *shared*, and their ranges aren't listed: they belong
    to thousands of unrelated customers.
  - Ranges are listed, **never scanned**.
- **Playbooks**: company due diligence finds the company's own networks and their ranges; website
  background shows who owns each address the site uses.
- **Graph**: "Address block" and "Network" panels, with every range listed.

### Fixed
- Timeouts in Argus Connect lookups and the AI analyst's Connect route are now caught on
  Python 3.10 too, where a timeout is a different kind of error from later versions.

## [1.39.0] — Phase 39: Phone footprint

### Added
- **Phone numbers, properly**: `phone_recon` now uses Google's libphonenumber, covering every
  country, offline:
  - whether the number is **valid** (a real, allocated range), including ranges reserved for TV
    and film;
  - the country, and for landlines the **area**;
  - the **line type**: mobile, landline, **VoIP**, toll-free, premium-rate, personal number…
    VoIP and personal numbers are flagged as often used to hide who is behind a number;
  - the original carrier, the time zones, and every way the number is written.
  - It contacts nobody, so it runs in passive scans and anonymous cases, and as enrichment on
    every number found.
- **Web mentions** (`web_mentions`): where a phone number or email address appears on the web:
  - searches for the number in all its written forms, or the exact email address;
  - **keeps only results that really contain it** (near misses dropped);
  - sorts pages into nuisance-call report sites, paste sites, social media, classifieds and other
    pages. They are recorded as third-party pages, never scanned;
  - invented or mistyped numbers are never searched, so they cost nothing.
- **Web search in Argus Connect** (the Brave Search API): 1 credit per search, refunded when
  nothing is found, or free with your own key (`ARGUS_WEB_SEARCH_API_KEY`).
- **Phone number playbook**: number facts and web mentions, preserving the pages that mention it
  (reports first), with findings for:
  - VoIP and personal lines, and numbers that aren't real;
  - mentions on nuisance-call report sites and paste sites.
  The email footprint playbook searches for mentions too.
- **Graph**: a "Phone number" panel (validity, line type, carrier, area, time zone) and an "On the
  web" panel listing confirmed mentions.
- Helm: `secrets.webSearchApiKey`.

### Changed
- The phone module no longer adds a "Telecom Region" organisation to the graph. It was not a real
  organisation, and was screened against sanctions lists as if it were.

### Not added, deliberately
- **Checking which messaging apps a number is registered with.** This only works by misusing the
  apps' contact matching. It breaks their terms, is unlawful in many places, and can alert the
  person.

## [1.38.0] — Phase 38: Website crawling

### Added
- **Website crawler** (`site_crawler`): reads a whole website, not just its home page:
  - starts from the home page and the site's sitemap, follows links within the site only, up to
    `ARGUS_CRAWL_MAX_PAGES` (40) pages, pausing `ARGUS_CRAWL_DELAY_SECONDS` (0.5) between them;
  - **obeys robots.txt** (rules for Argus, else for every crawler; the longest rule wins) and
    counts the pages it skipped;
  - follows redirects only within the site; never fetches images, scripts, login, cart or admin
    pages; reads at most 600 KB per page;
  - lists **email addresses** (including "name [at] site [dot] org"), marking addresses outside
    the site's own domain, such as a personal Gmail;
  - lists **phone numbers** (with a country code), **crypto wallets** (checksums verified) and
    **social media accounts** linked (X, Facebook, Instagram, LinkedIn, YouTube, TikTok,
    Telegram, GitHub, WhatsApp, Bluesky, Patreon, GoFundMe, PayPal…; share buttons ignored);
  - lists **documents offered** (PDF, Word, Excel…); up to ten on the site itself are opened to
    read their hidden author, company and software, and real author names become people in the
    graph;
  - records **analytics and advertising IDs** (Google Analytics, Tag Manager, AdSense, Meta
    pixel) across every page;
  - records the **other websites it links to** by name only: they are never visited or scanned;
  - notes the page each item was found on.
  - Active (it visits the site), so passive-only scans and anonymous cases skip it.
- **Website background playbook** now reads the whole site, preserves the home page plus the
  contact, about, team and legal pages, and reports:
  - published contacts, with outside email addresses and wallets marked *worth checking*;
  - document authors;
  - analytics IDs.
- **Graph**: a "Website read" panel (pages read, skipped by robots.txt, IDs, linked sites, the
  page list) and "Where it was found" on everything the crawler found.

## [1.37.0] — Phase 37: Playbooks

### Added
- **Playbooks** (new **Playbooks** tab in every case): the standard steps of an investigation, run
  in order from one starting point, inside a case:
  - **Company due diligence**: registers, directors and owners, parent companies, sanctions and
    offshore leaks; the register entries preserved as evidence;
  - **Person background**: directorships, sanctions and leaks (name matches marked as
    possibilities); never for children;
  - **Online identity**: accounts for a username and its variants on hundreds of sites; each
    profile found preserved;
  - **Email footprint**: domain, breaches, published keys and the accounts behind the username;
  - **Crypto trail**: payments, services, same-owner wallets and sanctioned counterparties;
  - **Website background**: registration, history, related and look-alike domains; the home page
    preserved through the case's route;
  - **Phone number**: country, carrier and line type.
- **Steps**:
  - **scan**: linked to the case, through its route; anonymous cases use passive sources only;
  - **capture**: preserves the pages that matter, with fingerprints and custody;
  - **findings**: what stands out, most serious first, written to the case as a note;
  - **brief**: an optional AI analyst briefing, only when asked for and confirmed.
- **What stands out**: possible sanctions matches (downgraded when birth year or nationality
  contradict), sanctioned wallets and counterparties, same-owner wallets, Offshore Leaks, breaches,
  directors and owners, accounts found, and names with no exact register match. Ticked items are
  added to the case as entities.
- **Reliable runs**:
  - progress is saved after every step and shown live;
  - a step that can't run (a source needs a key, no capture browser) is skipped or fails without
    stopping the others;
  - one run per case at a time, and a run can be stopped;
  - runs left unfinished by a restart are marked *interrupted*; in a cluster, only the restarted
    server's own runs;
  - playbook scans wait for a free slot under the cluster-wide scan limit.
- **Accountability**: starting a run (with its purpose), every scan, capture and briefing it
  makes are written to the audit log.
- API: `GET /api/playbooks`; `GET`/`POST /api/cases/{id}/playbooks`;
  `GET /api/cases/{id}/playbooks/{run}`; `POST .../{run}/cancel`. Migration `0020`.
- Python client: `playbooks()`, `run_playbook()`, `playbook_run()`.

### Changed
- The AI analyst's work is shared by the button and the playbook step, so both record custody and
  audit entries the same way.

## [1.36.0] — Phase 36: The AI analyst

### Added
- **AI analyst** in every case (new **AI analyst** tab), powered by Claude:
  - **Brief me**: a summary of what the case shows, key findings with their sources and
    confidence, gaps and open questions, next steps (what, why and how), and cautions;
  - **Find names & dates**: people, organisations, accounts, emails, phones, domains, addresses,
    places, vehicles, documents, wallets and dated events named in the evidence, each with the
    exact words it came from; the investigator ticks what to add;
  - **Draft a report**: an editable Markdown draft with cited sources, saved as a note or
    downloaded.
- **Grounded answers**: every part of the case material carries a reference (`[N1]`, `[D2]`...).
  Citations to references that don't exist are dropped or flagged; each extracted name and date is
  checked against its quoted words and marked *checked* or *unverified*.
- **Evidence it reads**: notes, entities, links, events, linked scans, the text of captured pages,
  and text, CSV, JSON, e-mail and PDF files added as evidence. Photos and other files are listed as
  not readable. Up to 60,000 characters per document and `ARGUS_ANALYST_MAX_CHARS` (400,000) per
  request; anything shortened or left out is listed, never cut silently.
- **Safety**:
  - nothing is sent without confirmation (`acknowledged: true`), every time; the dialog shows the
    size, the documents, the cost, and a stronger warning for anonymous cases;
  - the analyst is told to treat evidence as data and never follow instructions inside it, to keep
    fact and inference apart, never to profile children (possible children it marks are removed),
    and to suggest only lawful steps;
  - each document sent is written to its **chain of custody** ("sent for AI analysis"); the audit
    log records task, size and route, never the content;
  - suggestions are never added automatically.
- **Two ways to reach it**:
  - your own Claude API key (`ARGUS_ANTHROPIC_API_KEY`): material goes straight to Anthropic;
  - **Argus Connect** (Argus Personal, signed in): `POST /api/connect/ai/{task}` on the account
    service runs it with the operator's key for **Argus credits** (brief and extract 10, report
    20, plus 2 per 50,000 characters beyond the first 50,000), refunded on failure or refusal.
    The material passes through and is never stored; the ledger records only `ai/<task>`.
- **Model**: the newest Claude Opus model the key can use (or `ARGUS_ANALYST_MODEL`), adaptive
  thinking, effort `ARGUS_ANALYST_EFFORT` (default `high`), structured output for briefs and
  extraction, streaming, and server-side fallback if the model declines on safety grounds.
- API: `GET /api/analyst`, `GET /api/cases/{id}/analyst/preview`, `POST /api/cases/{id}/analyst`.
- Python client: `analyst_preview()`, `analyse_case()`.
- Helm: `secrets.anthropicApiKey`.

### Changed
- The subscription card lists the AI analyst's prices and explains what passes through the
  account service.
- New dependency: the official Anthropic Python SDK.

## [1.35.0] — Phase 35: Companies, sanctions & leaks, and Argus credits

### Added
- **Company and person targets**: a company name ("Acme Holdings Ltd") or a full name ("Jane
  Roe") is detected automatically.
- **Name matching**:
  - accents, punctuation, "SURNAME, Given" order, initials, middle names and legal forms
    (Ltd, LLC, PJSC, GmbH…) are handled;
  - for people, every word must match: "John Smith" never matches "Johnson Smithers", and one word
    never identifies a person;
  - each match carries a 0–1 score.
- **Sanctions screening by name**:
  - the US OFAC SDN list with aliases, the UK Sanctions List (current FCDO and previous OFSI
    layouts) and the UN Consolidated List, each loaded independently and cached daily;
  - matches show the list, programmes, date of birth and nationality;
  - **contradicting details are flagged** ("Born 1980, but the listed person was born 1975").
- **UK Companies House** (`companies_house`):
  - company details, officers with roles and dates;
  - persons with significant control, with the nature of control;
  - each director's other companies (capped per company);
  - a typed-in name gives possible director matches, with month and year of birth;
  - near misses become `registry_candidates` instead of a guess.
- **GLEIF**: LEI, legal and head-office addresses, jurisdiction, direct and ultimate parents.
- **SEC EDGAR**: CIK, ticker, state of incorporation, industry, former names, recent filings
  (`ARGUS_SEC_USER_AGENT`).
- **ICIJ Offshore Leaks**: people and companies named, with links, credited under the ODbL.
- **Argus Connect and Argus credits** (migration `0019`):
  - the account service holds premium-source keys and runs a **fixed menu of lookups**
    (validated parameters, fixed URLs: never an open proxy);
  - it charges credits atomically: a monthly allowance per plan first, then purchased credits;
  - failures, invalid requests and "not found" cost nothing;
  - a ledger records each change without the query text;
  - admin top-up endpoint for payment webhooks.
  - Argus Personal uses it automatically when no own key is set, and shows credits on the
    subscription card.
- Graph panels for companies (register, LEI, SEC), people (role, dates, birth month, other
  companies), sanctions matches and Offshore Leaks hits. Helm 0.25.0 values, Python client
  `add_credits()`.
- `docs/explained/35-companies-sanctions-and-credits.md`.

## [1.34.0] — Phase 34: Crypto investigations

### Added
- **Wallet targets.** Scans accept Bitcoin and Ethereum-style addresses (detected
  automatically). Every address's checksum is verified, so mistyped or invented addresses are
  refused with an explanation:
  - Base58Check for legacy and script addresses;
  - Bech32 and Bech32m for SegWit and Taproot (BIP 173 and BIP 350);
  - EIP-55 for Ethereum, using a Keccak-256 implementation checked against SHA-3 at every padding
    length.
- **Bitcoin wallets** (`bitcoin_wallet`, Esplora API, e.g. mempool.space):
  - balance, totals, transaction count and active dates;
  - who paid the wallet and whom it paid (amounts, counts, dates);
  - **same-owner addresses** by the common-input heuristic, with **CoinJoins detected and
    excluded** from both same-owner links and payments.
- **Ethereum-compatible wallets** (`evm_wallet`, Blockscout, any number of chains):
  - balance, transaction and token-transfer counts per chain;
  - native and token flows (failed transactions excluded);
  - public labels (exchanges, contracts) and ENS names.
- **Sanctions screening** against the US Treasury OFAC SDN list (official CSV files, cached daily,
  or offline copies). Every wallet and every counterparty is checked, with the designated party's
  name and programmes.
- **Services are not followed**: exchanges, contracts and very busy wallets are flagged, and the
  trail stops there, so strangers are never linked through an exchange.
- **Wallets on websites**: scans pick up checksum-valid addresses on a site's pages (including
  `/donate`).
- Graph: wallet type and panel (badges, sanctions warnings, balances, money in and out, explorer
  link). Cases: "wallet" entities, from the graph too. Helm 0.24.0 settings.
- `docs/explained/34-crypto-investigations.md`.

### Fixed
- The graph's details panel now refreshes when a scan finishes, so details that modules add late
  in a scan (for any entity type) appear without reopening the investigation.

## [1.33.0] — Phase 33: Argus accounts & Argus Personal

### Added
- **Argus Personal** (`argus --personal`, `ARGUS_EDITION=personal`): one investigator's Argus on
  their own computer, listening on 127.0.0.1 only, with its data in the user's application-data
  folder.
- **Unlocked by an Argus account.** Sign-in and sign-up happen in the app; the API, including
  admin API keys, answers only after sign-in.
- **The account service** (`ARGUS_ACCOUNT_SERVICE_ENABLED`, migration `0018`):
  - subscription accounts with plans (trial, personal, professional), statuses (trialing,
    active, past_due, cancelled, suspended) and a paid-until date;
  - per-plan computer limits (sign out on one to use another);
  - scrypt password hashing; lock-out after five failed sign-ins; no account enumeration (same
    answer and timing for unknown emails); open or closed sign-up; rate limits;
  - administration endpoints, ready for a payment provider's webhook.
- **Signed licences** (Ed25519):
  - issued per computer, checked offline with the public key, impossible to forge or edit;
  - bound to the issuing service and the computer, so a licence copied to another computer is
    refused;
  - renewed daily in the background; works offline for 14 days by default.
- **Never held hostage**: when a subscription is not current (ended, cancelled, offline too long,
  or the computer was signed out elsewhere), Argus Personal turns **read-only**. Cases stay
  readable, verifiable and exportable, and new work answers `402` with the reason. A banner shows
  it, with "Check again".
- Settings → **Your Argus subscription**: plan, status, paid-until, last renewal, offline limit.
- `argus --generate-licence-keys`; Helm 0.23.0 values for the account service; Python client
  `subscription_accounts()`, `set_subscription()`.
- `docs/explained/33-accounts-and-argus-personal.md`.

## [1.32.0] — Phase 32: Timeline & map

### Added
- **Case timeline** (`/api/cases/{id}/timeline`): investigator events, watched-account changes,
  captures and uploads, linked scans, and the moment each photo in the evidence was taken (read
  from its own metadata, flagged approximate when its time zone is unknown; not duplicated when
  already added by hand). The **Timeline** tab has an activity chart on a true time scale (day,
  month or year), filters by kind, and a CSV export (formula-safe).
- **Case map** (`/api/cases/{id}/places`): location and address entities with coordinates, photos
  with GPS, and addresses looked up on request. The **Map** tab is drawn by Argus itself: no
  mapping library, no third-party scripts. It supports dragging, zooming and the keyboard,
  shows details on click, has "show all", and exports KML for Google Earth.
- Coordinates are read as decimal, degrees-minutes-seconds (`51°30'02.5"N 0°07'28.6"W`,
  `40.7128° N`), or OpenStreetMap and Google Maps links; 0, 0 is ignored.
- **Address look-up** (`POST /api/cases/{id}/items/{item}/geocode`), Nominatim-compatible
  (`ARGUS_GEOCODER_URL`): only on request, through the case's route (anonymous cases never go
  direct), at most once a second, stored on the entity and audited.
- Python client: `case_timeline()`, `case_places()`, `geocode()`.
- `docs/explained/32-timeline-and-map.md`.

### Security
- **Map images are fetched by the server** (`/api/map/tiles`, `ARGUS_MAP_TILE_URL`), validated
  (images only, size-capped) and cached, so the investigator's browser never tells a map provider
  which area they are studying.
- Reading photos' dates and positions for the map and timeline is Argus's own background work,
  so it is not written to the custody log as a person viewing the evidence.

## [1.31.0] — Phase 31: Images & documents

### Added
- **Inspect** evidence files (photos, PDFs, Word, Excel, PowerPoint): what they reveal, and
  signs of editing, all read on the server.
  - **Photos**:
    - EXIF camera, lens and serial numbers; dates with time zones; GPS position, altitude and
      direction (with an OpenStreetMap link);
    - PNG text and XMP (creator tool, edit history);
    - SHA-256, MD5 and a perceptual hash.
  - **Documents**:
    - PDF author, creator, producer and dates; XMP and version IDs; pages;
    - Office authors and last editor, company, template, editing time, comment authors, tracked
      changes;
    - computer user names leaked in file paths.
  - **Findings** in plain words:
    - a file whose real type differs from its name;
    - editing software; changed after being taken;
    - camera clock and GPS disagreeing (or the camera's time zone inferred from GPS);
    - an embedded camera **preview that shows a different picture**;
    - **AI-generator settings** (Stable Diffusion, ComfyUI) and IPTC "AI-generated" labels;
    - Content Credentials (C2PA);
    - PDFs saved more than once, or containing JavaScript, attachments or tracking links;
    - stripped metadata explained as normal for social media.
- **Check the shadows**: the NOAA solar position algorithm gives the sun's direction and height,
  the shadow direction and the shadow length, for the photo's GPS place and time, or any place
  and time (`/api/tools/sun`).
- **Error level analysis** for JPEGs, with its limits stated.
- **Copy without metadata**: an image re-saved with nothing but its pixels, for publishing or
  sharing material from a source safely.
- **Reverse image search** links (Google Lens, Bing, Yandex, TinEye): by address for public
  images, else their upload pages with a warning to upload the clean copy.
- From the inspector: add the photo's place to the case, and the time it was taken to the
  timeline.
- Every inspection is recorded in the evidence's chain of custody.
- Python client: `inspect_evidence()`, `clean_copy()`, `sun()`.
- `docs/explained/31-images-and-documents.md`.

### Security
- Hostile files are parsed defensively: Pillow's decompression-bomb limit (60 megapixels),
  bounded reads of ZIP members (declared size checked first), `defusedxml` for Office XML (no
  entity expansion), PDFs read without running anything, and bounds-checked EXIF thumbnail
  parsing. Each inspection runs off the event loop with a time limit.
- `pypdf` is now a declared dependency.

## [1.30.0] — Phase 30: People & account investigation

### Added
- **Hundreds more sites**: username searches also use the community **WhatsMyName** catalog,
  downloaded and cached (`ARGUS_USERNAME_CATALOG_URL`, `_FILE`, `_TTL_HOURS`). Each entry's
  "profile" and "missing" signatures are both checked; unsafe entries (POST probes, plain HTTP,
  retired sites) are skipped; hand-checked signatures win name clashes. Every hit is still
  double-checked against a random handle, and community hits get lower confidence.
- **Username variants** (`handle_variants`): jane.roe also searches janeroe, jane_roe, jroe…; the
  number is dropped from janeroe1987. Variant finds are graded `possible` ("lead").
- **Profile-picture matching**: pictures are fetched on the server (through the route) and
  fingerprinted (perceptual hash). The same photo on two platforms links the accounts into one
  person and upgrades a possible match to strong. Blank and default pictures are ignored.
- **Watched accounts** (migration `0017`): a case re-reads an account on a schedule (6 hours, a
  day or a week), through the case's route.
  - Nine platforms are read in full through their official APIs (GitHub, GitLab, Reddit, Hacker
    News, Keybase, Dev.to, Mastodon, Docker Hub, Bluesky): name, bio, location, website,
    employer, public email, linked accounts and picture. Every other catalog site is checked for
    existence.
  - Each change goes on the case timeline with before and after, and the profile page can be
    captured as evidence automatically.
  - Deletion is reported only after two misses in a row, and only if the site still finds a known
    account, so a site blocking checks is not mistaken for a deletion.
  - Anonymous cases never check directly.
- Cases page: **Watched accounts** card, watch dialog and account history; scan dialog: "Also try
  variations"; People dossiers show picture matches and variant leads.
- Python client: `watch_account()`, `watches()`, `check_account()`, `account_history()`.
- `docs/explained/30-people-and-accounts.md`.

### Changed
- Modules can declare a longer time limit (`timeout_factor`); the username search, now covering
  hundreds of sites, gets four times the per-module limit and more parallel requests.

## [1.29.0] — Phase 29: Investigator safety

### Added
- **Egress routes** (`ARGUS_EGRESS_ROUTES`): Tor, a VPN or any HTTP CONNECT proxy that captures
  and scans leave through, so the people being investigated never see this server's address.
  Investigators see only a route's name, kind and description, never its address or
  credentials; a route is never stored with a scan.
- **Per-case safety** (migration `0016`): each case has a route, and can be made **anonymous**:
  - captures in an anonymous case must use an anonymous route (Tor, or one the operator marks
    anonymous); a direct capture is refused with `409` before anything is sent;
  - scans started for the case are routed, passive, and linked to the case automatically.
- A route can be chosen per capture and per scan (`egress`), and is recorded in each capture's
  manifest.
- **Route test** (`POST /api/opsec/routes/{name}/check`): asks an IP-echo service who is calling,
  through the route and directly, and warns if the route leaks this server's address or a Tor
  route does not exit through Tor.
- Settings → **Investigator safety**; route and anonymous badges on cases; a warning before any
  direct capture; a route choice when starting a scan.
- Python client: `routes()`, `check_route()`, and `egress` / `anonymous` on `create_case()` and
  `capture()`.
- Helm chart 0.19.0: `secrets.egressRoutes` (kept in the Secret) and `config.egressCheckUrl`.
- `docs/explained/29-investigator-safety.md`.

### Security
- Captures no longer identify themselves: the page fetch and the browser present an ordinary
  Chrome on Windows, US English, UTC timezone and locale (previously "Argus-Capture"). Routed
  scans replace every User-Agent, including modules' own.
- Tor routes never resolve names locally, so the local DNS resolver learns nothing about what
  is visited. Private and internal destinations are still refused before reaching the route.
- WebRTC is restricted to proxied connections and DNS prefetching is off in the capture browser,
  so a page cannot discover the server's real address around the route.
- Modules that open their own connections (TLS analysis) are skipped on routed scans, with a
  warning, because they cannot go through the route.
- A route that is down fails the capture or request; nothing falls back to a direct connection.

## [1.28.0] — Phase 28: Cases & evidence capture

### Added
- **Cases** (migration `0015`), each with a required purpose. A case holds:
  - people and other entities (person, organisation, username, account, email, phone, domain, IP,
    address, location, vehicle, document), with free-form details shown in full;
  - links between them, marked confirmed, likely or possible;
  - a timeline of events;
  - notes and linked scans.
- **Restricted cases** visible only to the owner and named members, with no administrator
  exception (source protection).
- **+ Case** on any graph entity sends it into a case with its details.
- **Evidence capture**: Argus's server fetches the page, so the investigator stays hidden. It keeps
  the raw response, a **full-page screenshot**, the rendered page, the text, and the headers and
  redirects. Evidence files (chat screenshots, documents, photos) can also be uploaded.
- **Proof that holds up**:
  - SHA-256 for every file and a manifest **digest**;
  - optional **RFC 3161 trusted timestamps** (`ARGUS_EVIDENCE_TIMESTAMP_URL`, sending only the
    digest);
  - a hash-chained **chain of custody** (captured, viewed, downloaded, exported, verified);
  - one-click **verify** of files, digest and custody.
- **Evidence bundle** export (ZIP): the case, the captures with their manifests, custody and
  timestamps, `SHA256SUMS`, and a README on how to check everything without Argus.
- **Cases page** (shortcut **K**), API `/api/cases` and `/api/evidence`, Python client
  `create_case()`, `capture()`, `add_to_case()`, `verify_evidence()` and `export_case()`.
- `docs/explained/28-cases-and-evidence.md`.

### Security
- The capture browser's only route out is a **guard proxy**. It resolves each host itself, allows
  public addresses only, connects to the checked address (no DNS rebinding), and lists what it
  refused.
- The browser is driven through the DevTools Protocol: pop-ups that would stall a headless
  browser are dismissed, and downloads are denied.
- Captured HTML and non-image files are never rendered by Argus: they download only, with a
  `sandbox` security policy. SVG is never shown inline.
- Chrome's headless shell, which has no Google services, is preferred to protect the
  investigator's privacy (`ARGUS_CAPTURE_BROWSER`).

## [1.27.0] — Phase 27: Compliance mapping

### Added
- **Compliance mapping** for four frameworks: **Cyber Essentials** (v3.2), **ISO/IEC 27001:2022
  Annex A** (13 controls), **NIST CSF 2.0** (10 outcomes) and **DORA** (6 articles).
- Each control is judged from three kinds of evidence:
  - the open attack paths and exposure findings that would breach it;
  - supplier status;
  - process checks: recent scans, continuous monitoring, alerting, remediation deadlines and SLA
    compliance, the Cyber Essentials 14-day patch window, critical weaknesses with owners, the
    supplier register and monitoring, and threat intelligence.
- **Statuses**: met, partially met (including gaps already owned and on a deadline), gap, and not
  assessed. Each status shows its reasons and evidence, and its findings can be tracked as fixes
  in one click.
- **Honest coverage**: each control is labelled direct, partial or process. Without evidence a
  control is never "met": problems are reported, but a pass needs a recent scan of your own
  organisation.
- Exports: a **CSV per framework** (for audit preparation or a statement of applicability) and a
  **JSON evidence pack** of every framework (for GRC tools), both audited.
- **Compliance page** (shortcut **C**), API `/api/compliance`, Python client `compliance()`, and
  `docs/explained/27-compliance-mapping.md`.

### Quality
- A catalogue integrity test checks that every mapped attack-path rule, exposure kind and process
  check exists, so a typo can never make a control look met.

## [1.26.0] — Phase 26: Executive dashboard & board report

### Added
- **Executive overview** (shortcut **X**, visible to every role), over 30, 90 or 180 days:
  - an overall status with a one-line verdict;
  - five areas, each red, amber, green or not measured, with the reason it was given: attack
    surface, remediation, breach and dark-web exposure, supplier risk, threat activity;
  - up to seven key messages, worst first, good news included;
  - ratings with trends;
  - risks to act on with owners and deadlines, including critical attack paths that nobody owns
    (one click to track them).
- **Board report (PDF)**: two branded A4 pages (overall status, key messages, areas, ratings,
  risks, performance figures, how to read it). It is TLP-marked, fingerprinted and registered for
  verification, and audited.
- **Scheduled board reports**: a report schedule can cover the whole workspace (30, 90 or 180
  days). Email gets the PDF; Slack, Teams and webhooks get the status and key messages.
- API `/api/executive` and `/api/executive/report`, Python client `executive()` and
  `board_report()`, and `docs/explained/26-executive-dashboard.md`.

### Privacy
- Board material names the owners of work but never the people findings are about. Exposure
  appears as counts, and addresses in finding titles are masked.

### Changed
- The supplier view can be built without an HTTP request (shared with the board report).
- Unique OpenAPI operation IDs: `exposure_overview` and `executive_overview`.

## [1.25.0] — Phase 25: Remediation workflow

### Added
- **Remediation tasks** (migration `0014`) from attack paths, exposure findings, suppliers below
  their minimum grade, or manual entry. *Track fix* buttons appear on attack paths, exposure
  findings and supplier rows. There is one task per finding, with a snapshot of its narrative,
  evidence and fix steps.
- **Lifecycle**: open, in progress, fixed, verified, or accepted. Allowed transitions are
  enforced.
- **Deadlines** by severity from a workspace policy (defaults 7/30/90/180 days), with per-task
  dates, owners and ticket references.
- **Risk acceptance** requires a reason and an end date within a year, and reopens automatically
  when it expires.
- **Verification by evidence**: every completed scan verifies the attack-path tasks it no longer
  finds, and reopens fixed or verified tasks whose path is still there or came back (regressions
  are counted). Absence only counts when the scan is comparable: as deep, no more passive, every
  module, not truncated. *Rescan to verify* reruns the original scan's configuration.
- Supplier tasks close when the supplier meets its minimum grade. Exposure tasks and findings
  stay in sync both ways.
- **Automation**: the policy can open tasks for new critical, or critical and high, findings
  (attack paths on watched targets, exposure, suppliers).
- **Overdue alerts**, one per workspace per check, each task announced once across replicas,
  linking to the Remediation page.
- **Timeline** of every change, comment and scan conclusion.
- **Metrics**: overdue, due this week, awaiting verification, SLA compliance (90 days), median
  time to verified fix by severity, regressions, by owner, and a 12-week trend. CSV export.
- **Remediation page** (shortcut **W**), task dialog and policy editor.
- API `/api/remediation`, Python client `tasks()`, `track()` and `update_task()`, and
  `docs/explained/25-remediation-workflow.md`.

### Fixed
- Two API operations shared the OpenAPI operation ID `export`. They are now `export_tasks` and
  `export_exposure`.

## [1.24.0] — Phase 24: Breach & dark-web exposure

### Added
- **Exposure monitoring** (migration `0013`): watched domains are checked daily for:
  - staff credentials in **infostealer logs**;
  - staff accounts in **data breaches**;
  - **breaches of the organisation** itself;
  - **ransomware leak-site posts** naming it.

  Sources: Have I Been Pwned (breach catalogue; domain search and stealer logs for verified
  domains with `ARGUS_HIBP_API_KEY`) and the ransomware.live research feed
  (`ARGUS_RANSOMWARE_FEED_URL`).
- **Supplier sweep**: every supplier in the register is checked for breaches and ransomware posts.
  The register flags affected suppliers.
- Severity rules weigh infostealers and recent domain-matched leak-site posts as critical, and
  breaches by passwords exposed and recency. Name-only leak-site matches are marked for
  verification.
- **Alerts**: the first check is a baseline (high and critical only). After that, every new
  finding goes into one alert per check, through notifications and integrations, linking to the
  Exposure page.
- **Triage**: resolve, accept risk or reopen findings, with a note. **CSV export** for password
  resets.
- **Exposure page** (shortcut **E**) with KPIs, watched domains and per-source status, findings by
  urgency with remediation advice, and breached accounts grouped per person. The demo includes
  fictional exposure.
- API `/api/exposure` (overview, watches, check now, triage, `export.csv`), plus Python client
  methods. Metrics: `argus_exposure_checks_total`, `argus_exposure_findings_total`,
  `argus_exposure_source_errors_total`. Helm: `config.exposureMonitoring`,
  `config.ransomwareFeedUrl`.
- `docs/explained/24-breach-and-dark-web-exposure.md`.

### Security and privacy
- Only metadata is collected: no passwords, cookies or leaked files, and no visits to criminal
  sites.
- Staff addresses are masked by default. Revealing or exporting them requires the analyst role
  and is audited with the number of addresses disclosed. Alerts never contain addresses.
- Closed findings are deleted after `ARGUS_EXPOSURE_RETENTION_DAYS` (default 365).

### Fixed
- On phones, the bottom navigation stretched every page wider than the screen. It now scrolls on
  its own and keeps the active page in view.

## [1.23.0] — Phase 23: API & integrations

### Added
- **Jira integration** (Cloud and Data Center): each alert opens one issue, labelled
  `argus-<alert id>`. A search runs before every create, so a retried delivery finds the issue
  instead of duplicating it. *Send test* checks the project and issue type without creating
  anything.
- **ServiceNow integration**: each alert opens one incident, with `correlation_id` used for the
  same deduplication, impact and urgency set from severity, and an optional assignment group.
- **Splunk integration** (HTTP Event Collector): alerts, scheduled reports and tests as JSON
  events, with optional index and sourcetype.
- **Microsoft Sentinel integration** (Logs Ingestion API): OAuth client credentials with token
  caching and re-sign-in, flat rows plus a `Details` column, and support for Azure commercial,
  Government and China clouds.
- The delivery log shows what each delivery created (`reference`, migration `0012`), e.g.
  `SEC-12` or `INC0010001`.
- **OpenAPI document**:
  - API key security schemes on exactly the authenticated operations;
  - the `X-Argus-Workspace` header, and the minimum role (`x-argus-role`) derived from each
    operation's dependencies;
  - stable operation IDs, tags for every operation, and documented `401`/`403`/`404`/`429`
    responses.
- **Per-key API rate limit** (`ARGUS_API_REQUESTS_PER_MINUTE`, default 600, Helm
  `config.apiRequestsPerMinute`) with `RateLimit-*` headers on every response and `Retry-After` on
  `429`.
- **Official Python client** (`clients/python`): typed errors, automatic waiting on rate limits,
  `wait()` for scans, workspaces, PDF reports and webhook verification.
- **Settings → API & integrations** card with copyable curl and Python examples.
- `docs/API.md` and `docs/explained/23-api-and-integrations.md`.

### Security
- Integration credentials are write-only and sealed together with the destination URL. Editing
  can keep a saved credential only while the host is unchanged.
- `ARGUS_INTEGRATION_ALLOWED_HOSTS` (Helm `notifications.integrationAllowedHosts`): operator-listed
  exact host names may be private. Link-local and cloud-metadata addresses (including
  `fd00:ec2::254` and `100.100.100.200`) stay blocked, at validation and after every DNS lookup.
- Jira descriptions wrap untrusted text in `{noformat}`. Error messages quote only specific error
  fields, never response bodies.

## [1.22.0] — Phase 22: Supplier risk

### Added
- **Supplier register** (migration `0011`): name, domain, criticality tier, data handled, owner,
  notes, an optional minimum grade, and the recorded basis for assessment. Unique per workspace
  domain.
- **CSV import** (`POST /api/suppliers/import`, up to 500 rows): forgiving column names, comma,
  semicolon or tab separators, URLs normalised to domains, duplicates and bad rows reported by
  line, existing suppliers skipped.
- **Passive, continuous assessment**: each supplier gets a passive-only monitor re-assessing it
  by tier (critical weekly, high fortnightly, medium monthly, low quarterly). Changing the tier
  reschedules it; *Assess now* makes it due immediately.
- **Policy and risk**: minimum grade by tier (B, C, D, none) or per supplier. Risk = grade
  likelihood × impact (tier + data sensitivity), on a 5×5 matrix with low, medium, high and
  critical levels.
- **Supplier alerts** when a grade drops or a first assessment is below the minimum, sent
  through notifications (critical-tier breaches are critical). Drift alerts are skipped for
  supplier monitors.
- API `/api/suppliers` (list with summary, matrix and policy; create, import, update, assess,
  delete, `export.csv`), audited. **Suppliers** page (shortcut **S**): register, KPIs, risk
  matrix, policy, add and import dialogs, export.
- `docs/explained/22-supplier-risk.md`.

### Security
- Supplier assessments are always passive (third parties have not consented to testing), with a
  required legitimate-interest confirmation and a recorded basis. Internal names and private
  addresses are refused.

## [1.21.0] — Phase 21: Security rating

### Added
- **Rating engine** (`argus/intel/rating.py`, methodology `2026.11-1`):
  - eight weighted factors fed by attack paths and direct measurements (DMARC/SPF policy, header
    grade, security.txt, certificate expiry, exposed-surface size), with strengths credited;
  - severity points with diminishing returns per factor;
  - critical caps (1 critical → at most 69 (D), 3 or more → at most 59 (F));
  - A–F bands;
  - coverage-based confidence: unassessed factors are excluded, and a rating under 60% confidence
    is provisional;
  - per-issue impact (uncapped) and gain (capped), and the fastest route to the next grade.
- Ratings stored per completed investigation (migration `0010`), recomputed when the methodology
  version changes.
- `GET /api/investigation/{id}/rating` (with trend and benchmark) and `GET /api/ratings`
  (portfolio: grade distribution, median, trend, change, weakest factor, percentile).
  Benchmarks are workspace-relative and need at least 3 organisations.
- Web app: a **Security rating** card on each investigation (grade, factor bars, fastest route,
  trend sparkline, benchmark), and a **Ratings** portfolio page (shortcut **R**).
- PDF reports: rating badge on the cover and a *Security rating* section (factor table,
  fastest route), pseudonymised like the rest of the report.
- `docs/explained/21-security-rating.md`, the published methodology.

## [1.20.0] — Phase 20: Infrastructure pivoting

### Added
- **`infrastructure_pivot` module**, passive and seed domain only. It finds related domains
  through:
  - analytics, ad and tag IDs (GA, GA4, GTM, AdSense, Meta pixel) read from the Internet
    Archive's copy of the homepage and reverse-looked-up;
  - the OV/EV certificate organisation (crt.sh certificate, then all certificates for that
    organisation);
  - dedicated name servers;
  - IPs shared with at most 15 domains.

  Optional `ARGUS_HACKERTARGET_API_KEY`.
- **Attribution model** (`argus/intel/pivots.py`): weighted evidence combined by noisy-OR (each
  kind counted once). Generic DNS providers, hosting companies' certificate organisations and
  crowded IPs are excluded. A shared IP alone never attributes a domain. Labels are "likely the
  same organisation" (≥ 80%) or "possibly related" (≥ 50%).
- Shared things (tracking IDs, the certificate organisation, name servers, IPs) become graph
  nodes, so the graph shows why domains are linked.
- **Impostor campaign mapping**: for suspicious lookalikes, the module finds other brand
  look-alikes on the same server (comparison undoes rn/m, 0/o, 1/l… substitutions), and the new
  `impostor_campaign` attack path (T1583.001/T1583.003 → T1566) recommends reporting the cluster
  together.
- *Related infrastructure* panel (confidence, evidence, **Investigate**, which opens the guided,
  authorised scan) and a report section. Demo: related careers and labs domains, and a second
  impostor on the phishing server.
- `docs/explained/20-infrastructure-pivoting.md`.

### Security
- Related domains are recorded **out of scope**: discovery is not authorisation.
- The engine's out-of-scope rule gains a narrow exception: only modules declared
  `third_party_safe` (never contacting the asset, only querying public databases about it) may
  examine third-party assets. Tests check both directions.

## [1.19.0] — Phase 19: Brand impersonation (lookalike domains)

### Added
- **Lookalike candidate generation** (`argus/intel/lookalikes.py`), deterministic, bounded and
  most dangerous first:
  - combosquatting (brand + 30 credibility words);
  - homoglyphs (`rn`/`m`, `vv`/`w`, `cl`/`d`, `0`/`o`, `1`/`l`) and IDN homographs (Cyrillic
    look-alikes, punycode);
  - TLD swaps, typos (omission, repetition, transposition, adjacent keys, vowels, hyphens),
    doppelgangers and bitsquats;
  - multi-part suffixes (`co.uk`…).
- **`lookalike_domains` module**, passive DNS only, seed domain only:
  - finds registered lookalikes, with per-TLD wildcard calibration;
  - judges each as impostor, parked or yours (shared name servers or IPs), with MX capability
    and a 0–100 risk score;
  - `ARGUS_LOOKALIKE_MAX_CANDIDATES` (default 1500).
- **Attack paths**: `lookalike_domain` for email-capable or high-risk impostors (T1583.001 →
  T1566, with abuse/UDRP/DRS, blocking and defensive-registration guidance) and a
  `lookalike_domain_watchlist` summary for the rest. Monitoring alerts on newly registered
  impostors through the existing drift detection.
- **Brand impersonation** panel on the investigation overview, and a section in the PDF
  report.
- Demo: four lookalikes (an impostor with mail that appeared since the previous scan, a parked
  homoglyph, a combosquat, Acme's own registration).
- `docs/explained/19-brand-impersonation.md`.

### Security
- **Out-of-scope entities**: the engine never runs modules against entities marked
  `out_of_scope` (third parties' assets such as lookalike domains). A test proves it with a full
  scan and a spy module. Out-of-scope entities are also excluded from asset counts and the
  report inventory.

## [1.18.0] — Phase 18: Guided first scan

### Added
- **Guided first scan**, a four-step wizard:
  1. Target: good first targets, and targets that need permission.
  2. Check: server-side pre-flight, purpose, authorisation, and an extra written-authorisation
     confirmation for sensitive targets.
  3. How: passive vs standard, and depth, with the exact source counts.
  4. Run: live counts and the sources consulted in plain English, then the top attack path,
     its first fix, and next steps (attack paths, watch, report).
- `POST /api/scan/preflight`: target type, whether it is allowed, which sources would run and
  which would contact the target, scope warnings, and a recent scan of the same target. Nothing
  is scanned.
- Scope guidance (`argus/security/scope.py`), with warnings rather than blocks:
  - danger: public-sector domains (incl. `.gov.uk`, `.police.uk`, `.nhs.uk`, the zones
    themselves), and large organisations outside bug bounty scope;
  - warning: academic domains, and people (personal data);
  - info: shared IPs, placeholder domains, and active checks.
- Every `scan.start` audit entry records the `scope_warnings` the server computed, so the log
  shows what the person was told.
- `GET /api/onboarding` and a **Getting started** checklist on the home page (demo, first
  scan, attack paths, monitoring, destinations, reports, schedules), role-aware and computed
  from real activity. The guided scan is the home page's main call to action, and the tour
  ends with it.
- `docs/explained/18-guided-first-scan.md`.

### Fixed
- Domains that do not exist are no longer reported as "can be spoofed in phishing emails". The
  DNS collector distinguishes NXDOMAIN (no such domain) from NoAnswer (no such record) and
  records `dns_exists`; the spoofing rule skips nonexistent domains.

## [1.17.0] — Phase 17: Scheduled reports

### Added
- **Report schedules per workspace** (migration `0009`): weekly or monthly, at a local time in
  any IANA time zone (`tzdata`). Arithmetic is done in wall-clock time, so 08:00 stays 08:00
  across daylight saving (gap: one hour later; fold: first occurrence, once).
- Each run takes the latest completed scan of the target, issues the report through the
  on-demand code path (branding, registry, fingerprint) and queues deliveries **in the same
  transaction**. Email gets the PDF attached, a summary and a verification link; Slack, Teams
  and webhooks get the summary, the fingerprint and a link (`report.scheduled` events).
- Every replica runs the scheduler and each due schedule is claimed atomically, so a report is
  sent once. Outcomes (`sent`, `skipped_unchanged`, `no_scan`, `failed`) are recorded on the
  schedule, in the audit log and in `argus_scheduled_report_runs_total`.
- Scheduled PDFs are stored 30 days for delivery retries (`GET /api/reports/{id}/file`), then
  purged.
- API `/api/reports/schedules` (create, update, delete, run now; workspace admins).
  Destinations must belong to the workspace.
- Web app: *Scheduled reports* on the Monitoring page (time zone preselected from the browser,
  target suggestions, destinations, Run now, pause), and PDF download in the report history.
- `argus_reports_generated_total` gains a `trigger` label (manual, scheduled). Helm
  `notifications.scheduledReports`. `docs/explained/17-scheduled-reports.md`.

### Changed
- Until branding is set, reports from the Default workspace say they are issued by "Argus";
  other workspaces use their own name.

### Security and privacy
- Unattended reports are always pseudonymised: the schedule API does not accept the
  personal-details option.

## [1.16.0] — Phase 16: Client reports

### Added
- **Server-side PDF reports** (`argus/reports/`, ReportLab):
  - cover with overall exposure rating;
  - contents with PDF bookmarks and "Page X of Y";
  - executive summary with risk gauge, severity chart and change since the previous scan;
  - prioritised, deduplicated recommendations;
  - attack paths with chain, MITRE ATT&CK, evidence and remediation;
  - exposure indicators, aggregated people exposure, asset inventory, ATT&CK coverage;
  - scope, methodology and limitations, definitions, and verification instructions.

  DejaVu fonts render non-Latin names. The Docker image installs them; reports still render
  with the base fonts if they are missing.
- `POST /api/investigation/{id}/report`: options for the recipient, TLP 2.0 label, inventory,
  comparison with the previous scan, and personal details (off by default). Analysts and up,
  10 a minute per user, rendered off the event loop. The response returns the report id and
  SHA-256 in headers.
- **Report registry and verification** (migration `0008`): every issued file's SHA-256 is
  recorded. `GET /api/reports` lists them. `GET /api/reports/verify/{sha256}` is public and
  rate-limited, so recipients without an account can confirm a copy is genuine and unmodified.
- **Per-workspace branding**: organisation, accent colour, footer note and logo
  (`GET/PUT /api/reports/branding`, admin only, audited).
- Web app: a report dialog (recipient, TLP, options, history with fingerprints), *Report
  branding* and *Verify a report* in Settings. Verification hashes the file in the browser
  and never uploads it.
- Metric `argus_reports_generated_total`; audit events `report.generate` (with the
  fingerprint) and `report.branding_update`.
- `docs/explained/16-client-reports.md`.

### Changed
- The printable HTML "executive report" is replaced by the PDF report.

### Security and privacy
- Every untrusted value is escaped before reaching ReportLab's paragraph markup, which can read
  local files (`<img src>`) and create links. Tests plant these payloads.
- Personal data is pseudonymised in attack paths ("Person A", `d•••@acme.com`) and only
  aggregated elsewhere. Full names require an explicit, audited opt-in.
- Logos are size- and dimension-checked before decoding (decompression bombs), accepted only as
  PNG or JPEG by content, and re-encoded so EXIF/GPS metadata and embedded payloads are removed.

## [1.15.0] — Phase 15: Outbound alerts

### Added
- **Notification destinations per workspace** (migration `0007`): Slack (incoming webhooks),
  Microsoft Teams (Workflows webhooks, Adaptive Cards), email (SMTP) and generic **signed
  webhooks**. Each has a severity threshold, a test button and a health status.
- **Transactional outbox**: an alert's deliveries are written in the alert's own transaction.
  Dispatchers on every replica claim due deliveries with a lease and fencing, retry transient
  failures with exponential backoff and jitter (30 s up to 4 h, 8 attempts, about 7 h, honouring
  `Retry-After`) and give up on permanent errors. Delivery is at-least-once with a stable
  `webhook-id`. Records are purged after 30 days.
- **Standard Webhooks signatures** (`webhook-id`, `webhook-timestamp`, `webhook-signature`),
  pinned to the specification's test vector. Rotating the secret signs with both secrets for 24 h.
- **Encryption at rest** for destination URLs and signing secrets (`argus/security/crypto.py`):
  AES-256-GCM, HKDF-derived key, associated data binding each value to its row and workspace,
  and versioned keys with `ARGUS_ENCRYPTION_PREVIOUS_KEYS` for rotation. The key comes from
  `ARGUS_ENCRYPTION_KEY`, or `ARGUS_ENCRYPTION_KEY_FILE` (created on first start) for single-node
  installs.
- API under `/api/notifications` (capabilities, channels, test, rotate-secret, deliveries, retry),
  all audit-logged and workspace-admin only. Alert audit entries record how many notifications
  were queued.
- Web app: a *Notifications* section in Monitoring, with the destination picker and setup hints,
  a shown-once signing secret, the delivery log and Retry. Links in messages open the right
  workspace (`/?ws=…&inv=…`).
- Metrics `argus_notifications_total`, `argus_notification_delivery_seconds`,
  `argus_notifications_pending`; alerts **ArgusNotificationsFailing** and
  **ArgusNotificationBacklog** (promtool-tested); a *Notifications* dashboard row.
- Helm: `notifications.*` (SMTP), `secrets.encryptionKey` (generated once and kept across
  upgrades), `secrets.smtpPassword`. Compose: encryption key and SMTP variables.
- `docs/explained/15-outbound-alerts.md`, including a receiver example that is tested.

### Security
- Destinations are SSRF-guarded. Slack and Teams types are restricted to their own hosts, and
  webhooks must be public HTTPS without credentials in the URL. The resolved address is checked
  again at connect time, redirects are not followed, and response bodies are never stored.
- Untrusted alert text is escaped for Slack (no `<!channel>` or disguised links), Teams Markdown
  and email HTML, and line breaks are stripped from email subjects (header injection).

## [1.14.0] — Phase 14: Team workspaces

### Added
- **Workspaces** (migration `0006`): investigations, monitors, alerts, API keys, audit entries and
  WebSocket tickets belong to a workspace. Upgrades move existing data, non-admin keys and users
  into a *Default* workspace.
- Per-workspace roles (viewer, analyst, admin) through memberships. Platform administration is
  separate: admin users, and admin keys not bound to a workspace.
- `X-Argus-Workspace` request header. `GET/POST /api/workspaces`, `PATCH/DELETE /api/workspaces/{ref}`
  (only empty, non-default workspaces can be deleted). Members can be listed, added by email,
  given a new role and removed. Admins cannot demote or remove themselves.
- `/api/me` lists the caller's workspaces and whether they are a platform admin. API keys are bound
  to the workspace they are created in; platform admins can opt into a platform-wide key.
- SSO: `oidc_default_workspace` and `oidc_workspace_groups`, which mirror identity-provider groups
  into memberships at each sign-in. Helm values `sso.defaultWorkspace` and `sso.workspaceGroups`.
- Web app: a workspace switcher in the top bar, plus workspace members and platform workspace
  administration in Settings.
- `docs/explained/14-team-workspaces.md`.

### Security
- Objects from another workspace return 404 (not 403) everywhere, including cancel/delete,
  graphs, reports, monitors, alerts and the live WebSocket stream. A route-sweep test enforces it.
- Audit entries hash their workspace ID. Older entries still verify.

## [1.13.0] — Phase 13: Single sign-on

### Added
- **OpenID Connect sign-in** (`argus/security/oidc.py`, `argus/api/auth_routes.py`): authorization
  code flow with PKCE (S256); single-use `state` and `nonce` stored hashed in the database for 10
  minutes (any replica can finish a login); ID tokens verified against the provider's JWKS
  (asymmetric algorithms only), exact issuer, audience/`azp`, expiry and nonce; key-rotation refresh
  rate-limited; HTTPS-only provider endpoints (HTTP only for loopback development).
- Identity policy: verified email (configurable), email-domain allow-list (incl. Google `hd`), roles
  from a groups/roles claim, a default role or refusal, bootstrap admin emails.
- **Users and sessions** (migration `0005`): users keyed by issuer + subject; server-side sessions in
  an HttpOnly, SameSite=Lax, Secure-over-HTTPS cookie storing only a hash server-side; cookie-
  authenticated writes require a same-origin `Origin`/`Referer` (CSRF); sign-out with the provider's
  single logout; `GET /api/users`, `PATCH /api/users/{id}` (role, disable = sign out everywhere;
  admins cannot lock themselves out); `GET /api/auth/config`.
- Web app: "Continue with <provider>" sign-in, plain-English refusal messages, sign-out through the
  provider, *People with access* administration in Settings.
- Audit events `auth.login`, `auth.sso_failed` (with reason), `user.update`; metric
  `argus_sso_logins_total`.
- Helm: `sso.*` values, `publicUrl` (defaults to the ingress host), `secrets.oidcClientSecret`,
  `networkPolicy.internalEgress` for self-hosted identity providers; schema refuses plain-HTTP issuers.
- `docs/explained/13-single-sign-on.md`; provider recipes in `docs/DEPLOYMENT.md`.

### Security
- Query strings are stripped from uvicorn's access log however Argus is launched (they can carry
  OAuth codes/state or WebSocket tickets), and `argus --serve` no longer writes uvicorn's access log.

## [1.12.0] — Phase 12: Observability

### Added
- **Prometheus metrics** at `/metrics` (`argus/observability/metrics.py`): API requests/latency by
  route template, scans (started, finished, running, cluster-wide, capacity, duration, interrupted),
  findings by type, module runs/duration/circuit-breaker trips, outbound requests by outcome
  (incl. SSRF blocks), WebSockets, checkpoints, monitors, drift alerts, auth failures, rate limits,
  audit events, database reachability, process CPU/memory. Optional bearer token
  (`ARGUS_METRICS_TOKEN`); `ARGUS_METRICS_ENABLED`.
- **Structured logging** (`ARGUS_LOG_FORMAT=json`, `ARGUS_LOG_LEVEL`): one JSON object per line with
  `request_id` (from/echoed as `X-Request-ID`), `investigation_id` and `instance`; a single access log
  with route templates and no query strings. Argus's own INFO logs were previously not emitted.
- **12 alert rules** with severities and runbooks, unit-tested with `promtool test rules`.
- **Grafana dashboard** (33 panels) generated from code; tests check every query and alert uses a real
  metric.
- Helm: optional ServiceMonitor, PrometheusRule and dashboard ConfigMap, Prometheus pod annotations,
  JSON logs by default, metrics token; `helm test` checks `/metrics`. Compose: Prometheus + Grafana
  overlay with provisioning.
- CI: CRD schema validation, `promtool check rules` + `promtool test rules`, dashboard-up-to-date check.
- `docs/explained/12-observability.md`.

### Changed
- uvicorn's access log is disabled in the image and chart (Argus logs each request once, structured).
- nginx (Compose) keeps upstream connections alive and forwards an `X-Request-ID`.

### Fixed
- Health-probe 503s during a database outage no longer also trigger the API error-rate alert.

## [1.11.0] — Phase 11: Kubernetes & PostgreSQL

### Added
- **Helm chart** (`deploy/helm/argus`): multi-replica API with rolling updates (`maxUnavailable: 0`),
  zone/node spreading, PodDisruptionBudget, optional HPA, Ingress with WebSocket timeouts,
  startup/readiness/liveness probes, preStop drain, checksum-triggered rollouts, migrations in an
  init container, non-root read-only pods with all capabilities dropped and no service-account token,
  NetworkPolicies (egress to the internet but not to private, link-local or CGNAT ranges), optional
  bundled PostgreSQL for evaluation, external database via an existing Secret, generated secrets kept
  across upgrades, `values.schema.json`, NOTES and a `helm test`.
- **Cluster coordination through PostgreSQL** (migration `0004`): scans record their owner replica
  and a heartbeat; a janitor fails scans whose replica stopped responding (and fences it if it
  recovers); cancel works from any replica; WebSockets opened on a non-owner replica stream the scan
  from database checkpoints; WebSocket tickets are stored (hashed) in the database; the scheduler
  claims due monitors atomically; the audit chain takes an advisory lock; migrations take an
  advisory lock; the concurrent-scan cap is cluster-wide.
- `argus --migrate`, `GET /api/live` (liveness without the database), `instance` in `/api/health`,
  settings `ARGUS_INSTANCE_ID`, `ARGUS_AUTO_MIGRATE`, `ARGUS_SCAN_STALE_SECONDS`.
- `deploy/compose/cluster.yml`: PostgreSQL + migration job + two replicas behind nginx.
- CI: the whole test suite also runs on PostgreSQL 16; the chart is linted, schema-validated in
  several configurations, installed on a kind cluster, checked with `helm test` and rolled while
  under traffic. Releases publish the chart to `oci://ghcr.io/alanalbino2008/charts`.
- `docs/DEPLOYMENT.md`, `docs/explained/11-kubernetes-and-postgresql.md`.

### Changed
- The image includes the PostgreSQL driver, runs as fixed UID 10001, starts uvicorn directly with
  proxy headers and graceful shutdown, and its health check ignores `HTTP(S)_PROXY`.

### Fixed
- A restarting replica marked *every* running scan as failed, including scans on other replicas.
- Checkpoints overwrote columns they did not set (an upsert updated every column), which would
  have erased a scan's owner and heartbeat on every flush.
- Replicas that were not running a scan saw it as "initializing" until it found something: status
  changes are now persisted even without new findings.
- Concurrent audit-log writes from several processes could fork the hash chain.
- Container health checks failed behind a corporate proxy (`urllib` sent localhost to the proxy).
- Replicas starting together raced to install the bootstrap admin key (one crashed on the unique
  constraint; with a generated key two admin keys would have been created): now serialised with a
  cluster-wide lock. `argus --migrate` waits for the database instead of crash-looping.

## [1.10.0] — Phase 10: Deep recon

### Added
- **Username hunting across 127 platforms** (from 35), with signatures moved to data
  (`argus/data/platforms.json`, Sherlock-style) and operator extensions via `ARGUS_EXTRA_PLATFORMS_FILE`.
  **Self-calibration**: every hit is re-checked with a random unregistered handle; sites that claim
  it exists are discarded for the scan and listed as unreliable. Invalid handles for a site are skipped.
- `argus --check-platforms [--platforms-report FILE]` verifies every signature (known account found,
  random one not), and a weekly GitHub Actions workflow publishes the results.
- New collectors: `wayback` (Internet Archive), `document_metadata` (FOCA-style author/software/company
  extraction from archived PDFs and Office files), `passive_dns` (five passive datasets with
  provenance), `github_org` (organisation verified against the domain, public members), `code_leaks`
  (GitHub code search with secret detection; needs `ARGUS_GITHUB_TOKEN`), `pgp_keyserver` (names and
  linked addresses), `web_recon` (active: security.txt, robots.txt, content-verified exposed files,
  published emails/phones) and `cloud_storage` (active: S3/GCS bucket discovery and public listing).
- New `URL` entity type (STIX `url`, ATT&CK T1594) and technique T1595.003 *Wordlist Scanning*.
- **Corroboration**: an entity confirmed by several modules records its `sources` and its confidence
  rises (noisy-OR, capped at 0.99).
- **Passive-only scans** (`passive_only`, UI checkbox, `--passive-only`): modules that contact the
  target's own systems are skipped. Monitors remember the setting (migration `0003`).
- Attack paths: `leaked_secret_in_code`, `exposed_sensitive_file` (live vs. archived),
  `public_cloud_storage`, `staff_enumeration` (14 rules). Risk flags for each.
- Identity resolution learns the organisation's **email format** and predicts likely work addresses
  for staff found without one (marked *inferred*); switchboard numbers and team inboxes are listed as
  public contact points, not people.
- UI: detail panels for leaked secrets, exposed files, archived copies, document metadata, cloud
  storage and a "Deep recon" summary; source provenance on every node; email-format card on People.
- `docs/explained/10-deep-recon.md`.

### Security
- Untrusted XML in documents is parsed with `defusedxml` (no DTDs/entities); downloads and zip
  members are size-capped. Secrets are never stored, only a 4-character preview and length;
  credential values in archived URLs and `.env` files are redacted.

### Fixed
- An organisation's GitHub account no longer merges all its members into one person.
- NPM and PyPI signatures: NPM now uses the registry API (the website is behind a bot challenge);
  PyPI requires profile-only page text (its challenge page answered 200 for any username).

## [1.9.0] — Phase 9: People & software intelligence

### Added
- `profile_enricher` module: when an account is found, reads the platform's official public API
  (GitLab, Reddit, Hacker News, Keybase, Dev.to, Mastodon, Docker Hub, Bluesky) for the owner's
  display name, bio, location, employer, website, join date and linked accounts; Keybase proofs and
  Mastodon `rel="me"` links are recorded as **verified** and their handles are hunted in turn.
  `github_hunter` now records the GitHub profile itself with the same facts.
- New `LOCATION` entity type (ATT&CK T1591.001 *Determine Physical Locations*; STIX `location`).
- `software_intel` module: software end-of-life status (endoflife.date) for banners such as
  `PHP/7.4.3`, and CVE threat intelligence — CISA KEV (exploited in the wild, ransomware use),
  FIRST EPSS exploit probability, NVD CVSS score and description.
- Enrichment modules: the engine runs them on entities at the depth limit, so leaf CVEs and profiles
  are still enriched, without expanding the scan further.
- Identity resolution (`argus/intel/identity.py`) and `GET /api/investigation/{id}/people`: linked
  identifiers grouped into personas with a dossier — accounts and profile facts, emails, handles,
  locations, employer, websites, breaches, a timeline, exposures and related attack paths. Links are
  graded verified / strong / possible. Access is recorded in the audit log.
- Attack paths: new `end_of_life_software` rule (10 rules); `exploitable_public_service` uses KEV,
  ransomware and EPSS to raise likelihood and explain *why* a CVE is urgent.
- Risk analyser flags actively exploited CVEs first, and end-of-life software.
- Web: **People** page (persona cards → dossier with accounts, timeline, exposure and *Show on graph*,
  shortcut `U`); graph panel shows profile facts, support status and CVE intelligence.
- Demo: verified persona with Keybase/GitHub/Mastodon profiles, real KEV/EPSS/CVSS data for its
  FortiOS CVEs and an end-of-life PHP release.
- `docs/explained/09-people-and-software-intelligence.md`.

### Changed
- Shared inboxes (`info@`, `security@`, …) are no longer turned into usernames and hunted across
  social networks: they are not people, and the results were strangers' accounts.
- Remote avatars are never loaded in the UI (initials instead), so viewing a dossier doesn't reveal
  the analyst's IP address to the subject's platforms.

### Fixed
- README claimed 60+ username platforms; the hunter checks 35.
- Duplicate links on profiles (the same URL in a link's address and its text) are de-duplicated.

## [1.8.0] — Phase 8: Interface redesign

### Added
- Redesigned web interface: left navigation with dedicated Overview, Graph, Attack Paths, Monitoring,
  History and Settings pages; welcome page with "Try the demo"; single New-investigation dialog with
  live type detection, depth slider, rules of engagement and "Keep watching".
- Overview dashboard: risk gauge, attack paths by severity, asset breakdown, exposure flags, exports.
- Graph: icons per entity type, size by importance, constant-size labels with importance-based
  visibility, hover focus, label-aware layouts, filterable legend, search; side panel linking each
  entity to its neighbours, attack paths and other investigations.
- Settings page: API-key management, audit log with one-click integrity verification, plugin status.
- Light and dark themes (system-aware, no flash), toasts, progress bar and Stop button, first-run
  tour, tooltips, keyboard shortcuts, phone layout.
- `docs/explained/08-interface-design.md`.

### Changed
- Front end rewritten as ES modules; all HTML built with an auto-escaping template (XSS-safe by
  construction). Still no inline scripts under the strict CSP.
- The three novelty themes are replaced by Light / Dark / System.

## [1.7.0] — Phase 7: Continuous monitoring & drift detection

### Added
- Drift detection (`argus/intel/diff.py`): compare two scans of a target — assets added/removed,
  security-relevant fact changes, attack paths new/escalated/reduced/resolved, risk trend and a
  one-line headline. `GET /api/investigation/{id}/diff[?against=]`.
- Monitors: scheduled re-scans (`/api/monitors`) under the same rules of engagement and scope checks
  as manual scans; the scheduler re-validates scope before each run, respects the concurrent-scan
  cap and is fully audited.
- Alerts on material drift (`/api/alerts`, acknowledge); unread badge on the History tab.
- UI: Alerts and Monitors panels, Compare and Watch on every investigation, "What changed" view, new
  assets highlighted on the graph.
- Demo now includes an earlier snapshot so drift can be explored offline.
- Alembic migration 0002 (`monitors`, `alerts`); `docs/explained/07-continuous-monitoring.md`;
  tests 196 → 204.

### Changed
- Attack-path identity is now rule + subject, so a worsening scenario is reported as escalated rather
  than as one path resolved and another opened.
- Manual and scheduled scans share a single launch function.

## [1.6.0] — Phase 6: Attack Path Engine

### Added
- **Attack Path Engine** (`argus/intel/paths.py`): nine explainable rules chain findings into ranked
  attack scenarios (credential exposure, spoofable email domain, exploitable public service, exposed
  sensitive service, identity correlation, TLS interception, subdomain takeover candidate, malicious
  reputation, web information leak), each with a risk score, the ATT&CK route from Reconnaissance to
  Initial/Credential Access, narrative, evidence and remediation. `GET /api/investigation/{id}/paths`.
- **Attack Paths tab**: severity-coloured cards, entity chain, ATT&CK route; "Show on graph"
  highlights the whole path and fades everything else. Paths also appear in the executive report.
- **Built-in demo investigation** (`argus --load-demo`, `POST /api/demo`): a fictional company using
  only reserved `.example` domains and TEST-NET IPs that exercises every rule.
- DNS module records explicit three-valued facts on domains (`dns_checked`, `dmarc_policy`,
  `spf`: present / missing / unknown) so reasoning never treats a failed lookup as a missing control.
- `docs/explained/06-attack-path-engine.md`; tests 178 → 196.

### Fixed
- Executive report claimed all collection was passive; it now states that the TLS and HTTP modules
  contact the target and that attack paths are assessments, not confirmed exploitation.

## [1.5.0] — Phase 5: Intelligence features

### Added
- MITRE ATT&CK mapping (Reconnaissance, TA0043): findings classified by technique with defensive
  guidance; every module declares the techniques it emulates and whether it is active or passive;
  ATT&CK Navigator layer export; ATT&CK panel in the web UI.
- STIX 2.1 export: observables with deterministic IDs, identities, CVE vulnerabilities, attack
  patterns and relationships in a TLP:AMBER report; strictly validated with the `stix2` library.
- Optional API-key modules: VirusTotal reputation, Have I Been Pwned breaches (new `breach` entity,
  T1589.001) and the Shodan host API (products and versions per port). They load only when their
  key is configured and respect each service's quota via per-host rate limits.
- Secret redaction: API keys are scrubbed from every recorded error and log message Argus stores.
- Plugin system via the `argus.modules` entry-point group: allowlist-only (`ARGUS_PLUGINS`),
  validated (no shadowing built-ins, real ATT&CK IDs only), failure-isolated, audited at startup;
  `GET /api/plugins`.
- `docs/explained/05-intelligence-features.md`; tests 147 → 178.

### Changed
- `/api/modules` reports ATT&CK techniques, active/passive, required settings, configuration
  status and origin (built-in or plugin).

## [1.4.0] — Phase 4: Engineering quality & delivery

### Added
- CI pipeline: ruff (incl. bandit security rules) + format check, mypy, pytest on Python 3.10–3.13
  with an 85 % coverage gate, clean-virtualenv package install test, pip-audit, Docker build with
  health and image-content checks.
- CodeQL security scanning (Python and JavaScript), Dependabot (pip, Actions, Docker).
- Tag-driven release workflow: version check, tests, GitHub Release with changelog notes, image
  published to `ghcr.io`.
- Alembic migrations, applied automatically at startup; pre-migration databases are adopted; a test
  fails if models and migrations drift.
- Offline parsing tests for every collector (fake HTTP session + real dnspython records) and CLI tests;
  coverage 68 % → 87 %.
- `.pre-commit-config.yaml`, `CONTRIBUTING.md`, `docs/explained/04-engineering-quality.md`.
- `requirements-dev.txt` pins ruff, mypy and other tooling so local, pre-commit and CI results match.

### Changed
- Version is single-sourced from `argus/__init__.py` (package metadata, API, User-Agent).
- Docker image rebuilt as a wheel-only multi-stage image on Python 3.12 with OCI labels and a data volume.
- Certificates are keyed by SHA-256 fingerprint; the analyzer flags expired, self-signed and
  soon-to-expire certificates.

### Fixed
- TLS analyzer extracted nothing (no SANs, issuer or dates) because `getpeercert()` returns `{}` for
  unverified certificates; certificates are now parsed from DER with `cryptography`.
- `alembic` was used but not declared as a dependency (installed packages crashed on start).
- No `.dockerignore`: `.env`, local databases and `.git` could be copied into images.
- Shodan module could send private IPs to its API (relied on a flag set by a concurrent module).
- GitHub blog URLs with paths produced invalid domain entities.
- Runtime `assert` (removed under `python -O`) replaced with an exception.

## [1.3.0] — Phase 3: Platform security

### Added
- API-key authentication (SHA-256-hashed, revocable, shown once) with viewer / analyst / admin RBAC.
- Secure-by-default bootstrap: an admin key is generated and logged once (or supplied via
  `ARGUS_BOOTSTRAP_ADMIN_KEY`, minimum 32 characters, otherwise startup fails closed).
- CLI: `--create-api-key NAME --role ROLE` for out-of-band key creation and recovery.
- SSRF egress guard: private/reserved/internal destinations blocked at seed validation, at
  connection time after DNS resolution (defeats DNS rebinding), and for raw-socket modules.
  Opt-in `ARGUS_ALLOW_PRIVATE_TARGETS` / `--allow-private` for authorised internal tests.
- Rules of engagement: scans require a purpose and explicit authorisation, stored with the
  investigation; UI confirmation dialog.
- Tamper-evident, SHA-256 hash-chained audit log (`GET /api/audit`, `GET /api/audit/verify`).
- Per-key scan rate limiting and a server-wide concurrent scan cap (HTTP 429).
- Security headers: strict CSP (`script-src 'self'`), frame denial, nosniff, no-referrer,
  `no-store` on API data, HSTS over HTTPS.
- Single-use, short-lived WebSocket tickets; authenticated exports in the UI.
- Web UI sign-in / sign-out and current-user indicator.
- `SECURITY.md` disclosure policy; `docs/explained/03-platform-security.md`.
- Tests: SSRF, authentication, RBAC, audit tampering, limits, headers, CORS (55 → 120).

### Changed
- CORS is same-origin by default (was `*` with credentials); extra origins via `ARGUS_CORS_ORIGINS`.
- WebSocket handler supervised by an anyio task group (fixes a cancellation race found by stress testing).
- Invalid API keys are audited (rate-limited per IP); anonymous page loads are not.

## [1.2.0] — Phase 2: Persistence, history & live replay

### Added
- `argus/storage/`: SQLAlchemy 2.0 async persistence (SQLite default, PostgreSQL-ready) with a
  repository layer, portable upserts, and SQLite WAL mode.
- Write-behind `InvestigationRecorder`: batched checkpoints every second plus a final snapshot.
- Crash recovery: investigations left running by a restart are marked failed on startup.
- `argus/core/settings.py`: `ARGUS_*` environment configuration via pydantic-settings.
- API: `GET /api/health`, `DELETE /api/investigation/{id}`, `GET /api/entities/search`
  (cross-investigation pivot), filtering and pagination on `GET /api/investigations`.
- WebSocket snapshot replay: late joiners and historical investigations receive all findings so far.
- Web UI: History tab (open, filter, delete), "Seen in other investigations" pivot, `?inv=` deep links.
- Docker: named data volume, `HEALTHCHECK` on `/api/health`.
- Tests: persistence, recorder checkpointing, crash recovery, replay and search (45 → 55).
- Docs: `docs/explained/02-persistence-and-history.md`.

### Changed
- Per-client bounded WebSocket send queues: slow browsers no longer stall the engine (backpressure).
- Running scans are dropped from memory once persisted; the database is the source of truth.
- Cytoscape.js is vendored (`argus/web/vendor/`) instead of loaded from a CDN — works offline and
  enables a strict Content-Security-Policy.

### Security
- Fixed stored XSS: the live activity feed rendered attacker-controlled entity labels (e.g. DNS TXT
  records) via `innerHTML` without escaping. Verified with a Playwright regression test.

## [1.1.1] — Module failure reporting

### Fixed
- Modules swallowed per-source errors, so total failures looked like empty results and never
  tripped the circuit breaker. Runs are now classified success / degraded / failed.
- DNS timeouts were recorded as "no valid MX records", inflating risk scores; now "unknown".

## [1.1.0] — Phase 1: Engine hardening

### Added
- `argus/core/http.py`: shared resilient HTTP client — retries with exponential backoff and
  full jitter, `Retry-After` support, per-host rate limiting and concurrency caps, telemetry.
- Engine worker pool for parallel recursive enrichment.
- Per-module timeouts, circuit breaker, `max_entities` cap, cooperative cancellation.
- `CANCELLED` status, `scan_cancelled` event, per-module and HTTP statistics on investigations.
- `POST /api/investigation/{id}/cancel` endpoint; richer investigation status payload.
- Proxy support (`HTTP(S)_PROXY`) via `trust_env`.
- Test suites for engine, HTTP client and API (14 → 40 tests); CI on all branches.
- Plain-English explainer: `docs/explained/01-engine-and-reliability.md`.

### Changed
- API uses the FastAPI lifespan handler (replaces deprecated `on_event`), keeps strong references
  to background scan tasks, logs failures, and cancels scans cleanly on shutdown.
- API validates input (depth/concurrency bounds, blank targets, unknown modules → HTTP 422).
- Web UI reacts to failed/cancelled scans and surfaces module errors in the live feed.

### Fixed
- Engine processed entities strictly one at a time; `concurrency_limit` and `rate_limit_delay`
  were largely unused.
- Crashed background scans stayed `running` forever and their exceptions were lost.
