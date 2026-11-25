# 100. Per-workspace quotas

A server shared by several teams is only as reliable as its busiest team, or a script gone wrong, or
a stolen key in one workspace. Quotas keep one workspace from exhausting the server for everyone.

## What can be limited

| Quota | Counts |
| --- | --- |
| `scans_per_day` | Scans started in the last 24 hours, whatever started them: people, scheduled monitors, playbooks |
| `evidence_mb` | Megabytes of evidence stored (captures and uploads) |
| `watches` | Brand and fingerprint watches |
| `api_keys` | Active API keys (revoked and expired ones do not count) |

## Setting them

* **Server defaults** apply to every workspace: `ARGUS_QUOTA_SCANS_PER_DAY`, `ARGUS_QUOTA_EVIDENCE_MB`,
  `ARGUS_QUOTA_WATCHES` and `ARGUS_QUOTA_API_KEYS`. `0` (the default) means no limit.
* A **platform administrator** sets a workspace's own limits with `PUT /api/quota`, acting in that
  workspace. `null` returns a value to the server's default, and `0` removes the limit. Audited
  (`quota.set`).

## When a limit is reached

The action is refused with `403` and a body naming the quota, its limit and what is used, for example
"This workspace has reached its limit of 3 active API keys". A refused scan gets `429` with
`Retry-After`: the time until the oldest scan of the last 24 hours stops counting. A scheduled monitor
that meets the limit waits and tries again on a later tick, with one warning in the log rather than
an error.

Everyone in the workspace sees its usage in Settings → **Workspace usage** (`GET /api/quota`), shown
in red from 80%. Refusals are counted in `argus_quota_refusals_total{resource}`.
