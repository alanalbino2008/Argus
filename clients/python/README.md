# argus-client

The official Python client for the [Argus](../../docs/API.md) API.

```bash
pip install ./clients/python
```

```python
import os

from argus_client import ArgusClient, NotFound

with ArgusClient("https://argus.example.com", api_key=os.environ["ARGUS_API_KEY"]) as argus:
    scan = argus.scan("example.com", purpose="Annual external assessment, ticket SEC-42")
    investigation = argus.wait(scan["investigation_id"])  # blocks until it finishes
    rating = argus.rating(investigation["id"])
    print(rating["grade"], rating["score"])

    open("report.pdf", "wb").write(argus.report_pdf(investigation["id"], tlp="AMBER"))

    red_team = argus.in_workspace("red-team")  # same key, another workspace
    print(len(red_team.investigations()))
```

* **Rate limits**: a `429` or `503` is retried after the server's `Retry-After`, up to
  `max_retries` times (default 3). After that, `RateLimited` is raised.
* **Errors**: each error raises a subclass of `ArgusError` carrying `status_code` and the server's
  human-readable `detail`:
  * `AuthenticationError` (401);
  * `PermissionDenied` (403);
  * `NotFound` (404, also for anything in another workspace);
  * `ValidationError` (422);
  * `RateLimited` (429).
* **Anything else**: `argus.get(path, **params)`, `argus.post(path, body)`, `argus.patch(…)`, `argus.put(…)` and
  `argus.delete(…)` call any endpoint in the [reference](../../docs/API.md).

* **Cheap polling**: answers that carry an `ETag` (campaigns, TAXII) are remembered and asked for
  again with `If-None-Match`. While nothing changed, the server answers `304` and the remembered
  answer is returned; `argus.not_modified` counts how often.

## Reading the TAXII feed

```python
last_seen = None
for obj in argus.taxii_objects("lookalikes", added_after=last_seen):  # follows every page
    print(obj["type"], obj.get("name"))
```

Collections: `tagged`, `lookalikes`, `fingerprint-servers` and `campaigns`. A TAXII client such as
OpenCTI or MISP can read the same feed at `/taxii2/<workspace>/` with the same API key.

## Researching a person from what is known

```python
person = argus.add_person(
    case_id,
    "Jane Doe",
    names=["Jane Doe"],
    usernames=["jdoe"],
    emails=["jane@example.org"],
    city="Leeds",
    employer="Acme Logistics",
)
argus.person_photo(case_id, person["id"], open("jane.jpg", "rb").read())  # only a fingerprint is kept
argus.search_person(case_id, person["id"], rounds=2)  # follows very good matches one step further
person = argus.wait_for_person(case_id, person["id"])
for c in argus.candidates(case_id, person["id"], verdicts=("likely", "possible")):
    print(c["score"], c["verdict"], c["label"], "; ".join(c["agree"]), "; ".join(c["conflict"]))
argus.confirm_candidate(case_id, person["id"], candidate_id, search=True, note="Same photo, checked")
argus.reject_candidate(case_id, person["id"], other_id)  # never suggested again
argus.add_known(case_id, person["id"], phones="+44 7700 900123")  # adds to what is known
argus.watch_person(case_id, person["id"])  # searches again every week, alerts on new candidates
```

Adding a person and searching confirm a legitimate purpose for researching them. Scores are
possibilities, never identifications: confirm only what you have checked.

## Watch health

```python
for watch in argus.watch_health():  # failing or paused watches, paused first
    print(watch["kind"], watch["name"], watch["failures"], watch["paused_reason"] or watch["last_message"])
argus.run_watch("brand", watch_id)  # runs it now; resumes a watch Argus paused
```

## Verifying webhooks

```python
from argus_client import verify_webhook, WebhookVerificationError


def receive(request):
    try:
        verify_webhook(SIGNING_SECRET, request.headers, request.body)  # the raw body
    except WebhookVerificationError:
        return 401
    event = json.loads(request.body)
```
