# 90. Two-person approval for sensitive actions

Some actions cannot be undone, or carry the most sensitive data Argus holds: deleting a case,
exporting a case's whole evidence bundle, showing leaked email addresses in clear, and creating
another administrator key. Until now one administrator, or one stolen admin key, could do any of
them alone. A workspace can now require a second administrator to agree first.

## Choosing what to protect

Settings → **Two-person approval** (or `PUT /api/approval-policy` with `{"actions": [...]}`):

| Action | What it guards |
| --- | --- |
| `case.delete` | `DELETE /api/cases/{id}` |
| `case.export` | `GET /api/cases/{id}/export` (the evidence ZIP) |
| `exposure.reveal` | `GET /api/exposure?reveal=true` (leaked addresses in clear) |
| `key.create_admin` | `POST /api/keys` with role `admin` |

Adding an action takes effect at once. **Removing** one needs an approval itself, so the person the
policy protects against cannot simply switch it off.

## The flow

1. The protected call is made as usual. Argus records a request (or reuses the caller's open one for
   the same thing), notifies the workspace's alert channels ("Approval needed: carol asks to delete a
   case"), and answers **`202 Accepted`** with the request; nothing happens yet. An optional
   `X-Argus-Reason` header is shown to the approver.
2. Another workspace administrator approves or rejects it in Settings, or with
   `POST /api/approvals/{id}/approve` (or `/reject`), optionally with a note.
3. The requester repeats the call with **`X-Argus-Approval: <id>`**. The web interface does this
   step itself: it remembers the pending request and sends the approval the next time the same action
   is done.

## The rules

* Nobody approves their own request: not with another key or session of theirs, and not under the same
  name. Analysts and viewers cannot approve.
* An approval is for one action on one resource, by the person who asked. It works **once** and
  lapses 24 hours after the request.
* Each step is audited: `approval.request`, `approval.approve` or `approval.reject`, `approval.used`,
  and `approval.refused` / `approval.self_approve` for attempts that failed.

A workspace with a single administrator should not protect actions it needs: nobody could approve
them. A platform administrator can approve in any workspace.

The Python client: `approvals()`, `approve(id)`, `reject(id)`, and `request(..., approval=id)`.
