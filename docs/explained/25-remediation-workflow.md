# 25 — Remediation Workflow (Plain-English Guide)

> Purpose: explain how Argus turns findings into tracked work with owners, deadlines and proof.
> It's useful for questions like:
> * "what is vulnerability management, beyond scanning?"
> * "what are SLAs and MTTR?"
> * "how do you know a fix really worked?"
> * "what does risk acceptance mean?"

## 1. Why this matters

Finding problems is the easy half. The hard half is getting them fixed and being able to prove
it. Security teams are judged on questions like:
* how many critical issues are open?
* how many are overdue?
* how long do fixes take?
* did anything we fixed come back?

That's **vulnerability management**, and auditors (ISO 27001, Cyber Essentials Plus, PCI DSS,
DORA) ask for its evidence. Until now Argus found and alerted. This phase closes the loop.

## 2. Tasks

A **task** is one piece of remediation work. It can come from:

| Source | Created from | Verified when |
|---|---|---|
| **Attack path** | *Track fix* on any path | a comparable scan no longer finds the path |
| **Exposure** | *Track fix* on a breached account, infostealer infection… | the finding is resolved |
| **Supplier** | *Track fix* on a supplier below its minimum grade | its next assessment meets the minimum |
| **Manual** | *New task* (e.g. from a pentest report) | a person confirms it |

Each finding has at most one task. Tracking it again returns the same task, with its history.
Tasks snapshot what they're about: the narrative, evidence and "how to fix" steps. They stay
readable even after the scan that found them is deleted.

Staff addresses stay masked in tasks (`r•••n@acme.com`), as on the Exposure page.

## 3. The lifecycle

```
open ──► in progress ──► fixed ──► verified
   └──────────┴────────────┴──► accepted (until a date) ──► reopens when it expires
```

* **Deadlines (SLAs)** come from the workspace policy by severity. The defaults are critical 7
  days, high 30, medium 90 and low 180, a common shape for vulnerability-management policies.
  Admins can change them. Each task can have its own date.
* **Overdue tasks are announced once**, in one alert per workspace per check, through the normal
  notification channels (Slack, Teams, Jira…). Each task is claimed with a conditional UPDATE, so
  several replicas never announce the same one twice.
* **Risk acceptance** is a legitimate decision ("legacy system, decommissioned in Q1"), but it
  needs a **reason** and an **end date within a year**. When the date passes, the task reopens and
  someone has to decide again. Otherwise "accepted" becomes where findings go to be forgotten.
* **Every change is on the timeline:** who assigned it, who marked it fixed and why, comments,
  and what each scan concluded.

## 4. Proof, not promises: verification by scans

"Fixed" is a claim. For attack paths Argus **checks the claim**. After every completed scan of a
target, each task for that target is re-examined:
* if the path is **absent**, the task is **verified**, with the scan's ID as proof;
* if the path is **present** but was marked fixed, the task is **reopened** ("still present");
* if a verified path **comes back**, the task is reopened as a **regression**, and counted.

The subtle part is **when absence counts as evidence**. A path can disappear from a scan simply
because the scan looked less hard. So a scan is only **comparable** if it:
* went at least as **deep** as the scan that found the path;
* was not **more passive** (a passive scan never touches the target, so it can't see an open port);
* ran **every module** the original ran;
* was **not cut short** (scans stop at an entity limit).

Absence in a lighter scan proves nothing. But **presence in any scan** proves the path is still
there, so it can still reopen a task.

People can't mark an attack-path task "verified" themselves. They mark it *fixed*, and either wait
for the next scheduled scan or press **Rescan to verify**. That reruns the scan with the original
scan's exact configuration and authorisation, subject to the usual rate limits and concurrency
caps.

The same idea applies elsewhere:
* a supplier task closes when the supplier's next passive assessment meets its minimum grade;
* exposure tasks and findings stay in step both ways (closing the task resolves the finding, and
  resolving the finding verifies the task).

## 5. Automation

The workspace policy can **open tasks automatically** for new critical, or critical and high,
findings:
* attack paths on **watched** targets;
* exposure findings;
* suppliers falling below their minimum.

Automatic tasks are created by "Argus automation" and appear in the timeline like any other.
One-off scans never open tasks automatically, since they may be exploratory.

## 6. Metrics

The Remediation page reports the numbers vulnerability-management programmes are measured by:

* **Overdue** (by severity), **due this week**, **awaiting verification**.
* **SLA compliance**: of the tasks verified in the last 90 days, the share closed by their due
  date.
* **MTTR (mean time to remediate)**: reported as the **median** days from opening to *verified*
  fix, by severity. The median is used because a few very old tasks would distort an average. The
  clock stops at verification, not at the "fixed" claim.
* **Regressions**: fixes that came back.
* **By owner**: open and overdue tasks per person.
* A 12-week opened-versus-closed trend.

Everything exports to CSV for reports and audits.

## 7. What a reviewer can check

* `argus/intel/remediation.py`: the lifecycle, deadlines, the comparable-scan rule, verification
  decisions and metrics. These are pure functions, tested exhaustively.
* `argus/storage/remediation_repo.py`: one task per finding, the timeline written in the same
  transaction as every change, scan verification, acceptance expiry, and overdue claims committed
  with their alert.
* `argus/api/remediation_hooks.py`: how scans, supplier assessments and exposure checks feed
  remediation.
* `tests/test_remediation.py`:
  * the rules;
  * verification and regression using the demo's two real scans;
  * a light scan not counting as proof;
  * acceptance expiry;
  * overdue alerts announced exactly once;
  * automation without duplicates;
  * exposure and supplier syncing;
  * rescans with the original scope;
  * roles, isolation and export.
