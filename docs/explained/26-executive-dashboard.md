# 26 — Executive Dashboard & Board Report (Plain-English Guide)

> Purpose: explain how Argus summarises everything it knows for directors. It's useful for
> questions like:
> * "how do you report cyber risk to a board?"
> * "what is RAG status?"
> * "how do you keep a summary honest?"

## 1. Why this matters

Boards are now accountable for cyber risk. UK guidance (the NCSC's *Cyber Security Toolkit for
Boards*, the Cyber Governance Code of Practice) and regulation (DORA, NIS2) expect directors to
understand and oversee it. But a director doesn't read attack paths. They ask:
* how exposed are we?
* are we fixing things fast enough?
* is anything new or dangerous?
* is it getting better or worse?

The executive view answers exactly those questions, from the numbers the other modules already
produce. The person who signs the budget sees value without learning the tool.

## 2. Five areas, red / amber / green

**RAG** (red, amber, green) is the standard board-reporting shorthand. Argus adds **grey**,
"not measured", because a missing measurement is not good news.

| Area | Red when… | Amber when… |
|---|---|---|
| **Attack surface** | an organisation of yours is rated D or F, or critical issues are open | the weakest is rated C |
| **Remediation** | a critical fix is overdue, critical attack paths have **no owner**, or under 70% of fixes are on time | anything is overdue, or under the 90% target |
| **Breach & dark-web exposure** | infostealer infections, or your name on a ransomware leak site | staff accounts in breaches, or a breach of the organisation |
| **Supplier risk** | a critical supplier is below its minimum, or a supplier is on a leak site | any supplier is below its minimum, or was breached |
| **Threat activity** | critical alerts in the period | high alerts |

**Every status carries its reason** ("Weakest: acme.com at F (59); 5 critical issues open").
Nothing is red without a sentence saying why, and each area links to the page with the detail.
The **overall** status is the worst measured area, with a one-line verdict ("Action needed:
Attack surface, Remediation.").

One design decision came from a test. With no data at all, "0 alerts" first made the overall
status *green*. Silence from a system that isn't watching anything isn't reassurance, so threat
activity is grey until something is monitored.

## 3. Key messages: honest, and not only bad news

Up to seven plain-English sentences, ranked by importance, worst first:
* "Your organisation was named on a ransomware group's leak site."
* "1 critical fix is past its deadline."
* "4 critical attack paths have no owner: nobody is tracking a fix."
* "acme.com's security rating improved from C to B (+9 points)."
* "95% of fixes were verified within their deadline (target 90%)."

Good news is included on purpose. A report that only ever says things are bad gets ignored, and
so does one that only ever says they're fine. The rules are deterministic functions of the
numbers (`argus/intel/executive.py`), so the same data always produces the same report and
anyone can check why a message appeared.

## 4. Risks to act on

Directors approve resources, so the list shows **who owns each risk and its deadline**:
* overdue and critical remediation work comes first;
* then critical attack paths **nobody owns**, a governance gap boards care about.

One click (*Track fix*) gives an unowned path a task and a deadline.

## 5. The board report

**Board report (PDF)** produces two A4 pages in the workspace's branding:

1. **"How exposed are we, and are we fixing it fast enough?"**: the overall status and verdict,
   the key messages, and the five areas with their reasons.
2. **The evidence**: ratings and their change, the risks to act on with owners and deadlines,
   five performance figures (overdue, % on time, median days to fix a critical issue, infostealer
   infections, suppliers below minimum), and how to read the report.

Like the assessment reports, it is:
* marked with its TLP classification;
* **fingerprinted** (SHA-256) and registered, so a recipient can check a copy is genuine and
  unaltered at `/api/reports/verify/<sha256>`;
* audited.

**Privacy.** The report names the **owners** of work, because accountability is the point. It
**never names the people findings are about**:
* exposure appears only as counts;
* email addresses inside finding titles (e.g. "Leaked credentials for d•••d@acme.com") are masked.

A test reads the generated PDF's text to check this.

**Scheduled.** A report schedule can now be a *board report for the whole workspace*, e.g.
"monthly, on the 1st at 08:00, covering 90 days, to the CISO's email". Email gets the PDF.
Slack, Teams and webhooks get the overall status and the key messages. Ticket systems (Jira,
ServiceNow) are refused as destinations, since they open tickets for alerts, not for reports.

## 6. What a reviewer can check

* `argus/intel/executive.py`: the area rules, messages, ranking, redaction (all pure functions).
* `argus/api/executive_service.py`: collects each module's numbers. It is shared by the API and
  the scheduler, so the page and the PDF can't disagree.
* `argus/reports/board.py`: the two-page PDF, escaping every scanned value.
* `tests/test_executive.py`:
  * grey, green and red scenarios with their messages;
  * thresholds;
  * redaction;
  * the demo overview;
  * the PDF's text (including what it must not contain);
  * verification;
  * a scheduled board report queued with the right summary.
