# 83 — Limits on the recent features

Phases 68 to 82 added endpoints that, per request, spend a workspace's third-party credits, ask
external services, run a browser, or read every lookalike the workspace has. Each was reviewed for
what one caller (a script, a misconfigured integration, or a stolen key) could do with it.

| What | Limit | Why |
| --- | --- | --- |
| **Run now** on a brand or fingerprint watch | Once per 10 minutes per watch (`ARGUS_WATCH_RUN_COOLDOWN_SECONDS`) | Each run spends Shodan, Censys or Cert Spotter queries |
| Takedown draft | 10 a minute per key | RDAP: the registrar and up to three networks |
| Campaign takedown | 3 a minute per key | Up to 30 domains' RDAP each |
| Case from a lookalike (with a capture) | The capture limit: 20 a minute per key, checked before anything is created | A browser render |
| Campaigns, brand-protection summary | 60 a minute per key | They read every lookalike of the workspace |
| Brand-protection PDF | 10 a minute per key | PDF rendering |
| Report verification | 30 a minute per key, files up to 16 MB | Reads and hashes the upload |
| TAXII 2.1 | 120 a minute per key | Every page recomputes the collection |
| Annotations | 20,000 entities per workspace (editing an existing one is always allowed) | Every query, hunt and feed reads them all |

Every refusal is a `429 Too Many Requests` with a `Retry-After` header saying when to try again.

What the review checked and found sound: domain names from Certificate Transparency (written by
whoever registers them) are validated as plain host names before any look-up and escaped in every
page, PDF, email and webhook; websites of lookalikes are only ever visited through the guard proxy,
which refuses private and internal addresses; every change is audited.

The limits are per process: with several replicas, each replica counts on its own.
