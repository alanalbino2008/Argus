# 86. Rate limits that hold across replicas

Argus limits how often one caller can do something expensive or sensitive: sign in, unlock the
vault, accept a team invitation, start a scan, run a Shodan-spending watch, render a PDF. Until now
each replica counted on its own, so a deployment with three replicas behind a load balancer allowed
three times every limit. For brute-force protection (sign-in, vault unlock, password resets) that is
the difference between 5 guesses a minute and 15.

## How it works

Named limiters now count in the `rate_limit_counters` table (migration 0035), shared by every
replica. For each limiter, caller and fixed window (one minute, one hour…) there is one row with a
count. The sliding window is estimated from the current and previous windows:

    previous count × (share of the previous window still inside the last `window` seconds) + current count

An attempt is added first (one upsert that returns the new count) and taken back if it went over the
limit, so two replicas cannot both let the last attempt through. The caller's key (an API-key id or
client address) is stored as a SHA-256 prefix, not in clear. Old windows are deleted as new ones are
written.

If the database cannot be reached, a limiter counts that attempt in memory instead: neither locking
everyone out nor letting everyone in.

## What stays in memory

* the per-request API budget (`ARGUS_API_REQUESTS_PER_MINUTE`): it runs on every request and protects
  each replica's own capacity;
* the de-duplication of `auth.failed` audit entries.

## Settings

`ARGUS_SHARED_RATE_LIMITS` (default `true`) turns the shared counters off, for a single replica that
does not want the extra writes. Refusals are still counted in `argus_rate_limited_total{limit}`, now
with a name for every limiter (`login`, `vault_unlock`, `team_joins`, `scans_per_minute`, …).
