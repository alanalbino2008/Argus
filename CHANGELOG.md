# Changelog

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
