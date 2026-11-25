# 87. Watch health: telling the team that owns the watch

Phase 84 shows failing watches to the people who run the platform. But the fix is usually with the
team that set the watch up: their Shodan key expired or ran out of credits, the anonymising route the
watch uses was removed, their egress changed. Until now that team saw only a red status in
Monitoring, if they looked.

## What happens

| When | What the workspace gets |
| --- | --- |
| 3 runs in a row fail | One **medium** alert: "Fingerprint watch … has failed 3 runs in a row", with the last error and what to do about it |
| Every run has failed for 7 days | The watch is **paused** (it stops spending credits on a search that cannot work) and a **high** alert says so |
| The first run that works after an alert | A **low** alert: "… is working again" |

The alerts go through the usual notification channels and appear in Monitoring → Alerts, where they
can be assigned and resolved like any other. Each is audited (`brand_watch.health`,
`fingerprint_watch.health`).

A brand-watch run where one Certificate Transparency source failed and the other worked is a
success: the watch still finds lookalikes.

## The advice

The alert reads the error and suggests the fix: add or replace an API key, wait for a quota to reset
(or use a paid key or a longer interval), choose another route, or check the outbound network. When
the error is unfamiliar it says where to see it.

## Resuming

A paused watch shows **Paused** and the reason in Monitoring. Fix the cause, then **Run now**: the
watch is enabled again and has a fresh week before it can be paused again. Watches report
`failures`, `failing_since` and `paused_reason` in the API.
