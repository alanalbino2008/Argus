# 84. Watching the watchers

Brand watches and fingerprint watches run in the background. When one stops working, because crt.sh
is overloaded, a Shodan key expired or the watcher loop died, nothing visibly breaks: new lookalike
domains and attacker servers simply stop arriving. This phase makes that visible to operators.

## Metrics

| Metric | Labels | Meaning |
| --- | --- | --- |
| `argus_watch_runs_total` | `kind` (brand, fingerprint), `status` (ok, partial, error) | Finished watch runs |
| `argus_watch_run_duration_seconds` | `kind` | How long a run took |
| `argus_watch_last_success_timestamp_seconds` | `kind` | When this replica last finished a run that was ok or partial |
| `argus_watch_source_errors_total` | `source` (crt.sh, Cert Spotter, Shodan, Censys) | Failed look-ups at a source |
| `argus_lookalikes_found_total` | `severity` | New lookalike domains recorded (not your own) |
| `argus_takedown_events_total` | `event` (drafted, reported, down, closed) | Takedown steps |
| `argus_rate_limited_total` | `limit` | Now also counts the Phase 83 limits (`taxii`, `takedown_lookup`, `campaign_read`, `brand_watch_cooldown`, …) |

A brand-watch run is *partial* when one of its two Certificate Transparency sources failed and the
other worked.

## Alerts

| Alert | When | Severity |
| --- | --- | --- |
| `ArgusWatchesFailing` | 3 or more runs of a kind failed in 6 hours and none succeeded | warning |
| `ArgusWatchesStalled` | No replica has finished a run of a kind successfully for 2 days | warning |
| `ArgusCertificateTransparencyDegraded` | crt.sh or Cert Spotter failed 5 or more times in 6 hours | info |
| `ArgusTakedownBacklog` | More than 20 more takedowns reported than resolved in 7 days | info |

The last-success timestamp lives in each replica's memory, so it starts empty after a restart.
`ArgusWatchesStalled` takes the latest value across replicas; a deployment that restarts every replica
will not report a stall until the first successful run sets it again. `ArgusWatchesFailing` covers
that gap.

Each rule has a `promtool` unit test in `deploy/helm/argus/files/alerts.test.yaml`.

## Dashboard

A new **Brand protection & watches** row shows runs by outcome, hours since the last success, run
time, source failures, new lookalikes by severity and takedown steps.
