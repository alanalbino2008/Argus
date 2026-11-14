# 17 — Scheduled Reports (Plain-English Guide)

> Purpose: explain how Argus sends client reports on a schedule. It's useful for "design a
> recurring job in a distributed system", "how do you handle time zones?" and "how do you
> automate safely?" questions.

## 1. What it does

A workspace admin sets up, for example, *"Every Monday at 08:00 Europe/London, send the
acme.com report to the client's CISO and to our SIEM"*. At that time Argus:

1. finds the **latest completed scan** of the target (monitors from Phase 7 keep scans fresh);
2. generates the **PDF report** from Phase 16, with the workspace's branding, the change since
   the previous scan, and a registered SHA-256 fingerprint;
3. sends it through the **notification destinations** from Phase 15:
   * **email** gets the PDF attached, a short summary and a verification link;
   * **Slack, Teams and webhooks** get the summary, the fingerprint and an *Open in Argus*
     link (chat messages shouldn't carry confidential attachments).

The schedule shows its last outcome (*Sent*, *Skipped — no new scan*, *No scan yet*,
*Failed*), the next run, and a **Run now** button.

## 2. Reusing three earlier phases

This feature is mostly composition, which is the point: well-designed parts combine.

| Need | Reused from |
|---|---|
| Fresh data | Monitors re-scan targets on a schedule (Phase 7) |
| The document | The same `issue_report` code path as on-demand reports: same branding, registry and fingerprint (Phase 16) |
| Getting it there | The notification outbox: leases, fencing, retries with backoff, the delivery log and metrics (Phase 15) |
| Exactly one sender in a cluster | The atomic "claim" used by the monitor scheduler (Phase 11) |

The report is registered, its file stored and its deliveries queued in **one database
transaction**. A report is never registered without being sent, or sent without being
registered.

## 3. Time zones: getting "08:00 every Monday" right

People schedule in **local time**. The UK is UTC+0 in winter and UTC+1 in summer, so "08:00
London" is 08:00 UTC in January but 07:00 UTC in July. A naive implementation that adds 7
days in UTC drifts by an hour twice a year.

Argus does the arithmetic in local wall-clock time (`argus/reports/schedule.py`) and converts
to UTC only at the end:

* **Daylight saving starts** (01:00 → 02:00): a 01:30 schedule doesn't exist that night, so it
  runs at 02:30.
* **Daylight saving ends** (02:00 → 01:00): 01:30 happens twice, so it runs once, at the first.
* **Monthly** schedules use days 1–28, so every month has the chosen day.
* Time zones come from the IANA database (`tzdata`), so results don't depend on the OS image.

Tests pin these cases with real 2026 UK clock-change dates.

## 4. Automating safely

* **Unattended reports are always pseudonymised.** Naming people in a report is a decision a
  person makes for one report (and it's audited). A timer never makes it every week, and the
  schedule API doesn't even accept the option.
* **Skip unchanged** (the default): if no new scan has finished since the last report, nothing
  is sent. Identical weekly emails teach people to ignore them.
* **No scan, no email**: a schedule whose target hasn't been scanned yet records *No scan yet*
  instead of sending an empty report.
* **Failures don't loop**: a failed run is recorded on the schedule and in the audit log, and
  the schedule moves on to its next slot. Delivery failures are retried separately by the
  outbox.
* **Destinations must be in the same workspace**: a schedule can't send another team's
  report, or send to another team's destinations. Foreign ids are rejected as unknown.
* **Stored files expire**: email PDFs are kept for 30 days so retries can attach them, then
  purged. The fingerprint stays in the registry for verification.

## 5. Interview talking points

* "Schedules are computed in **local wall-clock time with IANA zones**, so 08:00 stays 08:00
  across daylight saving; I tested the DST gap and fold explicitly."
* "In a cluster every replica runs the scheduler, but a due schedule is **claimed with a
  conditional UPDATE**, so exactly one sends it, and a test races two replicas."
* "Registration, file storage and the outbox writes share **one transaction**."
* "Automation never makes privacy decisions: **unattended reports are always
  pseudonymised**."
