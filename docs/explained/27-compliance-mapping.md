# 27 — Compliance Mapping (Plain-English Guide)

> Purpose: explain how Argus maps its evidence to security frameworks. It's useful for questions
> like:
> * "what is Cyber Essentials / ISO 27001 / NIST CSF / DORA?"
> * "what can outside-in evidence prove, and what can't it?"
> * "how do you avoid compliance theatre?"

## 1. Why this matters

Organisations are audited against frameworks:
* UK suppliers to government need **Cyber Essentials**;
* many contracts require **ISO/IEC 27001** certification;
* US and global organisations use the **NIST Cybersecurity Framework**;
* EU financial firms must meet **DORA**.

Auditors ask for *evidence*: that vulnerabilities are found and fixed, that only intended
services are exposed, that suppliers are monitored. Argus already produces that evidence. This
phase organises it by control, so a security team can show an auditor what they have and see
where the gaps are before the audit does.

## 2. The frameworks

| Framework | What it is | Controls mapped |
|---|---|---|
| **Cyber Essentials** v3.2 | UK government-backed baseline: five technical controls | all 5 |
| **ISO/IEC 27001:2022** Annex A | international standard for an information security management system | 13 of 93 (those outside-in evidence can speak to) |
| **NIST CSF 2.0** | US framework of cybersecurity outcomes (Govern, Identify, Protect, Detect, Respond, Recover) | 10 outcomes |
| **DORA** | EU regulation on digital operational resilience in finance | 6 articles |

The control titles and objectives are **paraphrased in Argus's own words**, because the official
texts are copyrighted. Argus points to them rather than reproducing them.

## 3. How a control is judged

Each control lists three kinds of evidence.

1. **Findings that would breach it.** For example, Cyber Essentials *Firewalls* is breached by an
   exposed administrative service, and ISO 27001 *8.8 Management of technical vulnerabilities* by
   exploitable or unsupported software. Exposure findings count too: an infostealer infection is
   evidence against *User access control* and *Malware protection*.
2. **Process checks**, i.e. how security is actually run:
   * a scan of your organisation in the last 90 days;
   * continuous monitoring of every organisation;
   * an alert destination;
   * remediation deadlines met (SLA compliance);
   * every critical weakness has an owner;
   * Cyber Essentials' 14-day window for high and critical updates, checked against your
     remediation policy;
   * a supplier register, with suppliers assessed and above their minimum;
   * breach and impersonation intelligence collected.
3. **Supplier status**, for supplier controls such as ISO 27001 5.19 and DORA Article 28.

The result is one of:

* **Gap**: evidence the control isn't met, e.g. a high-severity finding nobody owns, or no
  monitoring at all.
* **Partially met**: met in part. This includes gaps that are already **owned and on a
  deadline**: an auditor treats a known, tracked weakness very differently from an unknown one.
* **Met**: assessed, and nothing against it.
* **Not assessed**: no evidence either way.

Every status lists its **reasons** and **evidence** (which scans, which dates, which numbers),
and every finding behind a gap has a *Track fix* button.

## 4. Honesty, which is the whole point

A compliance dashboard full of green ticks is easy to build and worthless. Argus avoids that in
four ways.

* **Coverage labels.** Each control says what kind of evidence Argus has:
  * **direct**: outside-in evidence can show it failing or holding, e.g. exposed services;
  * **partial**: it supports the control but can't prove it, e.g. leaked credentials say
    something about authentication, but not whether MFA is enforced;
  * **process**: the evidence is how the programme is run.
* **No evidence is never a pass.** An early version marked Cyber Essentials *Security update
  management* as "met" for a workspace that had never been scanned, because the remediation
  policy's deadlines were right. A test caught it. A good policy isn't evidence that updates are
  happening, so a pass now needs a recent scan of your own organisation. Problems are still
  reported without one.
* **Only what can be judged.** Argus maps 13 ISO 27001 controls, not 93. Pretending to assess
  physical security from the internet would discredit the rest.
* **A disclaimer on every view and export:** outside-in evidence *supports* an audit; it does
  not replace one.

A **catalogue integrity test** checks that every attack-path rule, exposure kind and process check
named in the mappings exists. Otherwise a typo would quietly make a control look met forever. The
only deliberately unmapped rule is lookalike domains: an impostor registering `acme-login.com` is
threat intelligence, not a failure of your controls.

## 5. Exports

* **CSV per framework**: control, title, status, coverage, reasons, evidence and findings. A
  starting point for audit preparation or a *statement of applicability* (ISO 27001's list of
  which controls apply and how they are met).
* **JSON evidence pack**: every framework with its evidence, for GRC platforms or archiving.

Both are recorded in the audit log, and people named in findings are masked.

## 6. What a reviewer can check

* `argus/intel/compliance.py`: the catalogue, the process checks and the evaluation, all pure
  functions.
* `argus/api/compliance_service.py`: gathers the workspace's evidence.
* `tests/test_compliance.py`:
  * catalogue integrity;
  * a well-run estate meeting Cyber Essentials;
  * no evidence never passing;
  * owners and severity deciding the status;
  * stale evidence;
  * exposure and supplier controls;
  * tracking gaps turning "gap" into "partially met";
  * exports, audit and isolation.
