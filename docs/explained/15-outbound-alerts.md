# 15 — Outbound Alerts (Plain-English Guide)

> Purpose: explain how Argus tells people when something important changes, and the
> security decisions behind it. It's useful for "design a reliable notification system",
> "how do you secure webhooks?" and "what is SSRF?" questions.

## 1. What it does

Monitoring re-scans targets and raises an **alert** when the attack surface changes in a way
that matters. An alert nobody sees is useless, so each workspace can now send its alerts to:

| Destination | What arrives |
|---|---|
| **Slack** | A formatted message with severity, the change, the worst new attack paths and an *Open in Argus* button |
| **Microsoft Teams** | The same, as an Adaptive Card (Teams *Workflows* webhook) |
| **Email** | Plain-text and HTML email through the organisation's SMTP server |
| **Webhook** | A signed JSON event for a SIEM, SOAR, ticketing system or any custom tool |

Each destination has a **severity threshold** (e.g. only *high* and *critical*), a **Send test**
button, and a **delivery log** that shows what was sent, what failed and why.

## 2. Never losing an alert: the transactional outbox

The naive design — "after saving the alert, call Slack" — has two failure modes. If Argus
crashes between the two steps, the notification is lost. And if Slack is slow or down, alert
creation is slow or fails.

Argus uses the **transactional outbox** pattern instead:

1. When the alert is saved, the same database **transaction** also writes one *delivery* row
   per matching destination. Both are saved or neither is.
2. A **dispatcher** on every replica picks up due deliveries and sends them.
3. Failures are **retried with exponential backoff and jitter**: 30 s, 2 min, 10 min, 30 min,
   1 h, 2 h, 4 h. That covers about 7 hours, so a receiver that's down for a while still gets
   every alert. Jitter stops many deliveries retrying at the same instant.
4. Errors that won't fix themselves aren't retried: a *404/410* (webhook deleted), a refused
   recipient or a redirect. The delivery is marked **failed**, the destination shows
   *Failing*, and an administrator can fix it and press **Retry**.

### Several replicas, no duplicates

Every replica runs a dispatcher. A delivery is **claimed** with a conditional `UPDATE`, so only
one replica can take it, and the claim carries a **lease** (a time limit). If that replica
crashes mid-send, the lease expires and another replica takes over. If the "dead" replica was
only frozen and wakes up later, it can no longer record a result, because it no longer holds
the claim. This is **fencing**.

The result is **at-least-once** delivery. In the rare takeover case a receiver could see a
message twice, so every webhook carries a stable `webhook-id` (the delivery id) that receivers
use to drop duplicates.

## 3. Security decisions

### 3.1 SSRF: a URL field is an attack surface

A destination makes the **server** send a request to a URL that a user typed. Without care,
someone could enter `http://169.254.169.254/` (cloud credentials), an internal admin panel or a
database port. This is **Server-Side Request Forgery**. Defences:

* **Slack and Teams types only accept their own hosts** (`hooks.slack.com`, Microsoft's
  Workflows hosts), so they can't point anywhere else.
* **Generic webhooks**: HTTPS only, no `user:pass@` in the URL, and no private, loopback,
  link-local or internal host names.
* **At send time the resolved IP address is checked again** (the guarded resolver from
  Phase 3). This defeats **DNS rebinding**, where a public name later resolves to `10.0.0.5`.
* **Redirects are not followed.** A redirect to an internal address can't bypass the checks.
* **Response bodies are never stored or shown.** The feature can't be used to *read* internal
  pages, only to get a status code.
* On Kubernetes the NetworkPolicy blocks private ranges as an independent second layer.

### 3.2 Secrets at rest: encrypt what you must read back

API keys and passwords are **hashed**, because Argus only compares them. A Slack webhook URL is
different: the URL *is* the credential (anyone holding it can post to the channel), and Argus
must use it again. So it's **encrypted** (`argus/security/crypto.py`):

* **AES-256-GCM**, authenticated encryption: a modified value fails to decrypt instead of
  producing attacker-chosen data.
* The key is derived with **HKDF-SHA256** from `ARGUS_ENCRYPTION_KEY`, which lives in a
  Kubernetes Secret, not in the database. A stolen database dump or backup contains no usable
  webhook URL.
* **Associated data binds each value to its row and workspace**: copying an encrypted blob into
  another workspace's row makes it undecryptable.
* **Key rotation**: each value records which key sealed it. Move the old key to
  `ARGUS_ENCRYPTION_PREVIOUS_KEYS`, set a new one, and values are re-encrypted with the new key
  as they're used.
* After creation, the API and UI only ever show a **masked hint** such as
  `https://hooks.slack.com/…mnop`.

### 3.3 Signed webhooks: proving a request came from Argus

Anyone can POST to a receiver's URL, so the receiver must be able to tell a real Argus event
from a forged one. Argus signs every webhook in the open
[Standard Webhooks](https://www.standardwebhooks.com/) format:

```
webhook-id:        dlv_3f9c…                      (stable across retries: deduplicate on it)
webhook-timestamp: 1794682890                     (reject if more than 5 minutes old: replay protection)
webhook-signature: v1,<base64 HMAC-SHA256(secret, "<id>.<timestamp>.<body>")>
```

* The secret (`whsec_…`) is shown **once**, at creation.
* **Rotation without downtime**: after *Rotate secret*, requests carry *two* signatures (new
  and old) for 24 hours, so the receiver can switch whenever it's ready.
* A test pins the implementation to the specification's published test vector, so the official
  libraries in any language verify Argus's signatures.

A receiver in Python:

```python
import base64, hashlib, hmac, time

def verify(secret: str, headers: dict, body: bytes) -> None:
    msg_id, ts = headers["webhook-id"], int(headers["webhook-timestamp"])
    if abs(time.time() - ts) > 300:
        raise ValueError("stale or replayed request")
    key = base64.b64decode(secret.removeprefix("whsec_"))
    mac = hmac.new(key, f"{msg_id}.{ts}.".encode() + body, hashlib.sha256).digest()
    expected = "v1," + base64.b64encode(mac).decode()
    if not any(hmac.compare_digest(expected, s) for s in headers["webhook-signature"].split()):
        raise ValueError("bad signature")
```

### 3.4 Injection into messages

Alert text includes things scans **found on the internet**: host names and attack-path titles.
An attacker who controls a scanned domain controls some of that text. Each format escapes it:

| Format | Attack prevented |
|---|---|
| Slack | `<!channel>` mass pings and disguised links (`<https://evil|Click>`): `&`, `<`, `>` are escaped |
| Teams | Markdown links and formatting: control characters are escaped |
| Email (HTML part) | HTML/script injection: HTML-escaped |
| Email subject | **Header injection** (adding a `Bcc:`): line breaks are removed |

### 3.5 Isolation and accountability

* Destinations and their delivery logs belong to one **workspace**. Other workspaces get
  **404** for their ids, and only workspace **admins** can manage them.
* Creating, changing, testing, deleting and rotating are **audit-logged**, and the audit entry
  for each alert records how many notifications were queued.

## 4. Operating it

* Metrics: `argus_notifications_total{channel_type,outcome}`,
  `argus_notification_delivery_seconds` and `argus_notifications_pending`, plus a *Notifications*
  row on the Grafana dashboard.
* Alerts: **ArgusNotificationsFailing** (a delivery gave up) and **ArgusNotificationBacklog**
  (more than 50 waiting for 15 minutes), both unit-tested with `promtool`.
* Delivered and failed records are purged after 30 days.

## 5. Interview talking points

* "I used a **transactional outbox**, so an alert and its notifications are committed atomically;
  delivery is asynchronous, retried with backoff and jitter, and at-least-once with an
  idempotency key."
* "Multiple replicas coordinate through **leases and fencing** in PostgreSQL. No message broker
  was needed."
* "A user-supplied URL is an **SSRF** vector, so destinations are validated, the resolved IP is
  re-checked at connect time against DNS rebinding, redirects aren't followed and bodies are
  never returned."
* "Secrets that must be read back are **encrypted with AES-GCM**, with associated data binding
  each value to its row, and versioned keys so they can be rotated."
* "Webhooks follow the **Standard Webhooks** spec: HMAC-SHA256 over id, timestamp and body,
  replay protection, and dual signatures during secret rotation."
