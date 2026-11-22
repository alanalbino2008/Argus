# 79 — The brand-protection report

## Why

Brand watch, triage, takedowns and campaigns (Phases 71–77) are the work. Someone also has to show
that the work is working: how many impostor domains appeared, how many are live threats now, how
quickly they come down once reported. That is what a security lead reports upwards, and what a
contract with a takedown provider would be judged on.

## The numbers

Computed from what the brand watches recorded (nothing is looked up), over a period (90 days on the
page; 7 to 365 through the API):

| Number | Meaning |
| --- | --- |
| **Open threats** | Lookalikes now judged an active phishing page, a copy of your site, or a high-severity mail-capable domain, whose takedown has not succeeded |
| **New lookalikes** | First seen in the period (your own defensive registrations excluded) |
| **Taken down** | Takedowns that succeeded in the period |
| **Median time to takedown** | From the abuse report being marked sent to Argus seeing the domain stop resolving or its site disappear |
| **Campaigns** | Groups of lookalikes and servers sharing infrastructure |

Also: lookalikes by verdict and by technique, takedowns by status, the takedowns waiting longest, the
largest campaigns, each watched brand, and a weekly trend of new lookalikes and takedowns.

## Where

* **Monitoring → Brand watch** opens with the five numbers, and **Report (PDF)** downloads the report.
* **Scheduled reports** gain a *Brand protection* kind: weekly or monthly, to Slack, Teams, email (with
  the PDF attached) or webhooks, with the headline numbers in the message.

## The PDF

Headline numbers, the trend chart, open threats, takedowns (and those waiting longest), campaigns,
watched brands, and how to read it. Like every Argus report it is registered with its SHA-256, so
anyone can check a copy is genuine (`/api/reports/verify/<sha256>`), carries its TLP marking, and
escapes every value: domain names come from whoever registered them.

## API

```http
GET  /api/brand-protection/summary?days=90
POST /api/brand-protection/report      {"days": 90, "tlp": "AMBER", "prepared_for": "Security committee"}
POST /api/reports/schedules            {..., "options": {"kind": "brand", "period_days": 30}}
```
