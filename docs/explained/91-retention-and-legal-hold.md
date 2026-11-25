# 91. Retention policies and legal hold

Keeping intelligence forever is a liability. GDPR's storage-limitation principle, client contracts
and internal policy all ask for data to be deleted once it is no longer needed. A case that is
subject to litigation must not be deleted at all, whatever the policy says. Argus now does both.

## Retention periods

Settings → **Data retention** (or `PUT /api/retention`), per workspace, in days; 0 (the default)
keeps data forever, and a non-zero period must be at least 7 days:

| Data | Deleted when | Always kept |
| --- | --- | --- |
| Investigations | finished (completed, failed or cancelled) longer ago than the period | the latest scan of each target, scans a case, monitor, fingerprint watch or open alert uses, and anything running |
| Alerts | resolved or false-positive longer ago than the period | open and investigating alerts |
| Cases | closed or archived and untouched for the period | open cases, and cases on **legal hold** |

A purge runs every 6 hours, on one replica at a time, and on demand (`POST /api/retention/run`, or
**Purge now**). `GET /api/retention` shows what a purge would delete now, without deleting anything.

## Legal hold

An administrator puts a case on hold from its page (**Legal hold**) or with
`PUT /api/cases/{id}/legal-hold` `{"hold": true, "note": "Matter 2026-114"}`. The note is stored
encrypted. A held case shows **Legal hold**; it cannot be deleted by hand (`409`) or by retention.

## With two-person approval

If the workspace protects `case.delete` (Phase 90), then:

* deleting cases sooner (a shorter case period, or a first one) needs approval;
* releasing a legal hold needs approval.

## The audit trail

Retention never touches the audit log, so its hash chain stays complete and `GET /api/audit/verify`
stays valid. Each purge adds one `retention.purge` entry with what was deleted and what was kept
back; policy changes and holds are audited (`retention.policy`, `case.legal_hold`,
`case.legal_hold_release`).

Python client: `retention()`, `set_retention()`, `legal_hold()`.
