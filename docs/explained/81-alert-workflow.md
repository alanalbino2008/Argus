# 81 — Alert workflow

## Why

An alert used to have one action, *Acknowledge*. A security team needs more: who owns this one, is
someone on it, was it real, what was done, and how long do we take. Without that, alerts are tracked
in a spreadsheet or a ticketing tool beside Argus, and the history of each one is lost.

## Status

| Status | Meaning |
| --- | --- |
| **Open** | New; nobody has looked yet |
| **Investigating** | Someone is on it (acknowledging an alert moves it here) |
| **Resolved** | Dealt with |
| **False positive** | Not a real problem (counted separately, so noisy checks show up) |

An alert can be reopened. Moving it to resolved or false positive records who closed it and when.

## Owner and activity

An alert can be assigned to a member of the workspace (or to yourself; API keys can assign to
themselves). Every change is kept in the alert's **activity**, with who did it, when, and the reason
given: status changes, assignments, acknowledgements, and the team's comments. Comments and activity
are encrypted at rest; every change is also in the audit log.

## On the page

**Monitoring → Alerts** filters by *Open*, *Mine*, *Unassigned* and *Closed*, shows each alert's status,
owner and number of comments, and opens an alert to change its status, assign it, and comment. The
header shows how many alerts are open and unassigned, and the median time to resolve over 30 days.

## Response times

`GET /api/alerts/stats?days=30`:

* `open` and `open_by_severity`, `unassigned`;
* `raised` and `resolved` in the period, and the `false_positive_rate`;
* `median_hours_to_acknowledge` and `median_hours_to_resolve` (from when the alert was raised).

## Upgrading

Alerts acknowledged before this version were treated as dealt with, so they become *resolved*
(migration 0033); unacknowledged ones are *open*.
