# 22 — Supplier Risk (Plain-English Guide)

> Purpose: explain how Argus monitors the security of an organisation's suppliers. It's
> useful for "what is third-party / vendor risk management?", "how do you assess an
> organisation you're not allowed to test?" and "what does DORA require?" questions.

## 1. Why suppliers

Attackers often go around a well-defended organisation through a weaker supplier, the
**supply chain**: a payroll provider, an IT contractor, a SaaS platform with access to your
data. Regulation has followed. The EU's **DORA** requires financial firms to keep a register of
ICT third parties and monitor their risk; **NIS2** asks essential entities to manage supply-chain
security; ISO 27001 has supplier controls. Questionnaires once a year don't catch a supplier
that exposes a database next Tuesday.

## 2. What Argus does

* **A supplier register** per workspace: name, domain, **criticality tier**, the **data the
  supplier handles**, the internal owner, notes, and the **basis** for assessing them. Add them one
  by one, or **import** the register you already keep in a spreadsheet. The CSV columns are
  recognised by name ("Vendor", "Website", "Criticality"…), URLs are reduced to domains, and
  bad rows are reported by line.
* **Continuous, passive assessment.** Every supplier gets a monitor that re-assesses it on a
  schedule set by its tier, and each assessment produces a **security rating** (Phase 21) with its
  trend.
* **Policy by tier:**

  | Tier | Minimum grade | Re-assessed |
  |---|---|---|
  | critical | B | weekly |
  | high | C | every 2 weeks |
  | medium | D | monthly |
  | low | none | quarterly |

  A supplier can have its own minimum.
* **Risk, not just a grade.** Risk = likelihood (from the grade, A 1 … F 5) × impact
  (criticality 1–4, +1 for personal data, +2 for sensitive or special-category data, max 5), read
  on a 5×5 **risk matrix**. A D-rated canteen is a low risk; a D-rated payroll provider holding
  staff data is critical.
* **Alerts** when a supplier's grade **drops**, or a first assessment lands **below its tier's
  minimum**. They reach Slack, Teams, email or webhooks through the notification system (Phase 15).
  Critical-tier breaches are critical alerts. Supplier assessments don't raise ordinary drift
  alerts: for a third party, what matters is the grade.
* **Register export** as CSV, with current grades, status and risk, for compliance records such
  as a DORA register of information.

## 3. Assessing organisations you may not test

A supplier is a **third party that hasn't agreed to be tested**. Argus therefore:

* forces **passive-only** assessment for every supplier, whatever the user chooses: public sources
  only (DNS, certificate logs, archives, breach and threat databases), never the supplier's own
  systems. This is the same "outside-in" approach commercial rating services use;
* requires a **stated basis** ("contracted payroll provider; processes staff personal data") and a
  confirmation of legitimate interest, both stored with the supplier and in the audit log;
* refuses internal names and private addresses, as for any scan.

## 4. Interview talking points

* "Supplier risk combines **how exposed** a supplier looks with **how much it matters** to us. The
  same D grade is low risk for a canteen and critical for a payroll provider."
* "Suppliers haven't consented to testing, so assessments are **always passive**, enforced
  server-side, with a recorded **legitimate-interest basis**."
* "It's **continuous**: tier-based re-assessment frequency and alerts on grade drops or policy
  breaches, instead of an annual questionnaire."
* "It reuses the platform: monitors for scheduling, ratings for scoring, the outbox for alerts,
  workspaces for isolation. The new code is mostly **policy**."
* "The register imports from and exports to the spreadsheets compliance teams already use (DORA's
  register of information)."
