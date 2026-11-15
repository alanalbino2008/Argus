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
* **Anything else**: `argus.get(path, **params)`, `argus.post(path, body)`, `argus.patch(…)` and
  `argus.delete(…)` call any endpoint in the [reference](../../docs/API.md).

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
