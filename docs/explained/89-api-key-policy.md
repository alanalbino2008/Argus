# 89. API keys: expiry, allowed networks and rotation

API keys are how SIEMs, scripts and TAXII clients reach Argus. Until now a key worked forever, from
anywhere, and replacing it meant downtime for whatever used it. A key copied from a CI log or a
laptop stayed useful to whoever found it.

## Expiry

A key can be created with `expires_in_days`; the web page offers 30 days, 90 days (the default
there), a year or never. `ARGUS_API_KEY_MAX_LIFETIME_DAYS` makes expiry mandatory: new keys get at
most that lifetime, and a key asked for without one gets exactly that.

`ARGUS_API_KEY_EXPIRY_WARNING_DAYS` (default 14) before a key expires, its workspace gets one alert
naming the key and how to rotate it. A platform key's warning goes to the audit log.

## Allowed networks

`allowed_networks` lists the addresses or CIDRs (IPv4 or IPv6, at most 20) a key may be used from;
empty means anywhere. It can be changed later (`PATCH /api/keys/{id}`), taking effect on the key's
next request. Behind a reverse proxy, run uvicorn with `--proxy-headers` so Argus sees the real client
address.

A key used from elsewhere is refused exactly like a wrong key: the caller learns nothing. The audit
log records `auth.failed` with the address, `argus_auth_failures_total{reason="key_network"}` counts
it, and the `ArgusApiKeyUsedOutsideItsNetworks` alert fires: a valid key presented from an unknown
network has probably leaked.

## Rotation without downtime

`POST /api/keys/{id}/rotate` (or **Rotate** in Settings) creates a new key with the same name, role,
networks and lifetime, and gives the old one an expiry `overlap_hours` away (default 24, up to 168;
0 ends it at once). Both work during the overlap, so the integration can be switched over at leisure.
A key can be rotated once; rotate the new one next time.

## Report

`GET /api/keys/report` lists the workspace's keys that need attention: expiring soon, unused for 90
days (also marked **unused** in Settings), set never to expire, or usable from anywhere.

## Existing keys

Keys created before this phase keep working as before: no expiry and no network restriction. The
report lists them, so they can be rotated into keys with both.
