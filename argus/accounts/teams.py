"""Team plans: one owner pays for seats; members sign in with their own accounts.

* **What a member may do comes from the team.** While someone is on a team, their licence shows
  the team's plan, status and paid-until date, not their own. If the team's subscription ends,
  lapses or is put on hold, every member goes read-only with it (their cases stay readable and
  exportable). Someone removed from a team goes back to their own account as it was.
* **Credits are shared.** The team has one pool: each seat adds the plan's monthly credits, and
  credit packs the owner buys go into it. Every lookup records which member used it, so the owner
  can see who used how much, never what was looked up or anything about anyone's cases.
* **Seats.** The owner holds one seat. Invitations can't exceed the free seats, and nobody can join
  a full team.
"""

from __future__ import annotations

from typing import Any

from argus.accounts.licence import PLANS

TEAM_PLAN = "business"


def is_owner(account: dict[str, Any]) -> bool:
    return account.get("plan") == TEAM_PLAN and not account.get("team_id")


def pool_id(account: dict[str, Any]) -> str:
    """Whose credits an account spends: its team's, or its own."""
    return str(account.get("team_id") or account["id"])


def device_limit(account: dict[str, Any]) -> int | None:
    """Members get the team plan's computers, whatever their own account allows."""
    return int(PLANS[TEAM_PLAN]["max_devices"]) if account.get("team_id") else None


async def effective(repo: Any, account: dict[str, Any]) -> dict[str, Any]:
    """The account as its licence should see it: a member takes the team's plan, status and dates."""
    team_id = account.get("team_id")
    if not team_id:
        return account
    owner = await repo.get(team_id)
    if owner is None or owner.get("plan") != TEAM_PLAN:  # the team plan ended or changed: no seat to sit in
        return {**account, "plan": TEAM_PLAN, "plan_label": PLANS[TEAM_PLAN]["label"], "status": "cancelled",
                "valid_until": (owner or account)["valid_until"], "team": None}  # fmt: skip
    status = owner["status"]
    if account["status"] == "suspended":  # a member's own hold still applies
        status = "suspended"
    return {**account, "plan": TEAM_PLAN, "plan_label": PLANS[TEAM_PLAN]["label"], "status": status,
            "valid_until": owner["valid_until"],
            "team": {"id": owner["id"], "owner": owner.get("name") or owner["email"]}}  # fmt: skip
