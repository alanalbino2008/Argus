"""Team plans on the account service: the team, invitations, joining, removing and leaving.

The owner and members act from Argus Personal, which sends the computer's licence:

* ``POST /api/teams/status``: the team as the caller sees it (owner: seats, members, invitations
  and the credits each member used this month; member: whose team it is);
* ``POST /api/teams/invite`` / ``cancel-invite`` / ``remove``: the owner's tools;
* ``POST /api/teams/leave``: a member leaves.

Someone invited follows the emailed link to ``/join-team`` on the account service, and joins
with their existing Argus account or a new one (``POST /api/teams/join``). Owning the inbox the
invitation went to is what proves who they are.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from argus.accounts import teams
from argus.accounts.licence import FULL_STATUSES
from argus.accounts.passwords import DUMMY_HASH, hash_password, verify_password, weakness
from argus.api.account_routes import EMAIL, SERVICE, _issuer, _licence_account, _limit, _service
from argus.api.deps import audit, client_ip
from argus.security.ratelimit import SlidingWindowLimiter

router = APIRouter(prefix="/api/teams", tags=["teams"])
INVITE_TTL = timedelta(days=7)
_invites = SlidingWindowLimiter(limit=30, window=3600)  # invitations per team an hour
_joins = SlidingWindowLimiter(limit=10, window=3600)  # join attempts per address an hour


class LicenceBody(BaseModel):
    licence: str = Field(max_length=8192)


class InviteBody(LicenceBody):
    email: str = Field(max_length=320)


class RemoveBody(LicenceBody):
    member_id: str = Field(max_length=40)


class JoinInfo(BaseModel):
    token: str = Field(min_length=20, max_length=128)


class JoinBody(JoinInfo):
    password: str = Field(max_length=256)
    name: str = Field(default="", max_length=255)


def _team_name(owner: dict[str, Any]) -> str:
    return owner.get("name") or owner["email"]


async def _owner(request: Request, licence: str) -> dict[str, Any]:
    _payload, account, _private = await _licence_account(request, licence)
    if not teams.is_owner(account):
        raise HTTPException(status_code=403, detail="Only the owner of a team plan can do this")
    return account


@router.post("/status")
async def team_status(body: LicenceBody, request: Request):
    """The team as the caller sees it."""
    repo, _private = _service(request)
    _payload, account, _p = await _licence_account(request, body.licence)
    if account.get("team_id"):
        owner = await repo.get(account["team_id"])
        return {"role": "member", "team": _team_name(owner) if owner else None,
                "owner_email": owner["email"] if owner else None, "active": bool(owner and teams.is_owner(owner))}  # fmt: skip
    if not teams.is_owner(account):
        return {"role": "none"}
    members = await request.app.state.teams.members(account["id"])
    start = datetime.now(timezone.utc).replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    used = await request.app.state.credits.used_by_member(account["id"], start)
    people = [{"id": account["id"], "email": account["email"], "name": account["name"], "owner": True,
               "credits_this_month": used.get(account["id"], 0), "last_login_at": account["last_login_at"]}]  # fmt: skip
    people += [{"id": m["id"], "email": m["email"], "name": m["name"], "owner": False,
                "credits_this_month": used.get(m["id"], 0), "last_login_at": m["last_login_at"]} for m in members]  # fmt: skip
    invites = await request.app.state.teams.invites(account["id"])
    return {"role": "owner", "seats": account["seats"], "used": len(people), "pending": len(invites),
            "members": people, "invites": invites, "status": account["status"]}  # fmt: skip


@router.post("/invite")
async def team_invite(body: InviteBody, request: Request):
    """Email an invitation to join the team (a seat must be free)."""
    _service(request)
    owner = await _owner(request, body.licence)
    if owner["status"] not in FULL_STATUSES:
        raise HTTPException(status_code=402, detail="Your team plan isn't active: renew it before inviting anyone")
    email = body.email.strip().lower()
    if not EMAIL.match(email):
        raise HTTPException(status_code=422, detail="Enter a valid email address")
    team = request.app.state.teams
    members = await team.members(owner["id"])
    if email == owner["email"] or any(m["email"] == email for m in members):
        raise HTTPException(status_code=409, detail="That person is already on your team")
    open_invites = [i for i in await team.invites(owner["id"]) if i["email"] != email]
    if 1 + len(members) + len(open_invites) >= owner["seats"]:
        raise HTTPException(status_code=409, detail=f"All {owner['seats']} seats are taken or invited: add seats under "
                                                    "Manage billing, or remove someone first")  # fmt: skip
    if not request.app.state.mailer.enabled:
        raise HTTPException(
            status_code=503, detail="Invitations are sent by email, which isn't set up: contact support"
        )
    if not _invites.hit(owner["id"]):
        raise HTTPException(status_code=429, detail="Too many invitations this hour; try later")
    token = await team.invite(owner["id"], email, INVITE_TTL)
    link = f"{_issuer(request)}/join-team#token={token}"
    await request.app.state.mailer.notify({**owner, "email": email, "name": ""}, "team_invite", token[:16],
                                          team=_team_name(owner), link=link, days=INVITE_TTL.days)  # fmt: skip
    await audit(request, SERVICE, "team.invite", owner["id"], details={"email": email})
    return {"detail": f"Invitation sent to {email}", "invites": await team.invites(owner["id"])}


@router.post("/cancel-invite")
async def team_cancel_invite(body: InviteBody, request: Request):
    _service(request)
    owner = await _owner(request, body.licence)
    if not await request.app.state.teams.cancel_invite(owner["id"], body.email.strip()):
        raise HTTPException(status_code=404, detail="No open invitation for that email")
    await audit(request, SERVICE, "team.cancel_invite", owner["id"], details={"email": body.email.strip().lower()})
    return {"detail": "Invitation cancelled"}


@router.post("/remove")
async def team_remove(body: RemoveBody, request: Request):
    """Take someone off the team. Their account and their cases are theirs; only the seat is freed."""
    repo, _private = _service(request)
    owner = await _owner(request, body.licence)
    member = await repo.get(body.member_id)
    if member is None or member.get("team_id") != owner["id"]:
        raise HTTPException(status_code=404, detail="That person isn't on your team")
    await request.app.state.teams.leave(member["id"])
    await audit(
        request, SERVICE, "team.remove", owner["id"], details={"member": member["id"], "email": member["email"]}
    )
    await request.app.state.mailer.notify(member, "team_removed", f"{owner['id']}:{datetime.now(timezone.utc):%Y%m%d%H%M%S}",
                                          team=_team_name(owner))  # fmt: skip
    return {"detail": f"{member['email']} is no longer on your team"}


@router.post("/leave")
async def team_leave(body: LicenceBody, request: Request):
    """A member leaves their team."""
    repo, _private = _service(request)
    _payload, account, _p = await _licence_account(request, body.licence)
    team_id = await request.app.state.teams.leave(account["id"])
    if team_id is None:
        raise HTTPException(status_code=404, detail="You're not on a team")
    await audit(request, SERVICE, "team.leave", team_id, details={"member": account["id"]})
    owner = await repo.get(team_id)
    if owner:
        await request.app.state.mailer.notify(owner, "team_left", f"{account['id']}:{datetime.now(timezone.utc):%Y%m%d%H%M%S}",
                                              member=account.get("name") or account["email"])  # fmt: skip
    return {"detail": "You've left the team"}


# ---------------------------------------------------------------------------- joining (from the emailed link)
async def _invitation(request: Request, token: str) -> tuple[dict[str, Any], dict[str, Any]]:
    repo, _private = _service(request)
    invite = await request.app.state.teams.find_invite(token)
    owner = await repo.get(invite["team_id"]) if invite else None
    if invite is None or owner is None:
        raise HTTPException(status_code=400, detail="This invitation has expired, was cancelled or was already used: "
                                                    "ask for a new one")  # fmt: skip
    if not teams.is_owner(owner) or owner["status"] not in FULL_STATUSES:
        raise HTTPException(status_code=409, detail="This team's plan isn't active at the moment: ask its owner")
    return invite, owner


@router.post("/join/info")
async def team_join_info(body: JoinInfo, request: Request):
    """What the join page shows: whose team, and whether the invited email already has an account."""
    _limit(request)
    invite, owner = await _invitation(request, body.token)
    exists = await request.app.state.subscribers.by_email(invite["email"]) is not None
    return {"team": _team_name(owner), "email": invite["email"], "has_account": exists}


@router.post("/join")
async def team_join(body: JoinBody, request: Request):
    """Join with the invited email: its password if it has an account, or a new account."""
    repo, _private = _service(request)
    _limit(request)
    if not _joins.hit(client_ip(request) or "unknown"):
        raise HTTPException(status_code=429, detail="Too many attempts; try later")
    invite, owner = await _invitation(request, body.token)
    found = await repo.by_email(invite["email"])
    if found is None:
        problem = weakness(body.password, invite["email"])
        if problem:
            raise HTTPException(status_code=422, detail=problem)
        hashed = await asyncio.to_thread(hash_password, body.password)
        # their own account starts with no trial of its own: the team's plan is what they use
        account = await repo.create(email=invite["email"], name=body.name.strip(), password_hash=hashed, plan="trial",
                                    status="trialing", valid_until=datetime.now(timezone.utc))  # fmt: skip
        if account is None:
            raise HTTPException(status_code=409, detail="An account was just created for this email: try again")
        await audit(request, SERVICE, "account.signup", account["id"], details={"plan": "team member"})
    else:
        account, stored, locked_until = found
        ok = await asyncio.to_thread(verify_password, body.password, stored or DUMMY_HASH)
        if locked_until and locked_until > datetime.now(timezone.utc):
            raise HTTPException(status_code=423, detail="Too many failed sign-ins: try again in 15 minutes")
        if not ok:
            await repo.login_failed(account["id"])
            raise HTTPException(status_code=401, detail="Wrong password for that account")
        if account["status"] == "suspended":
            raise HTTPException(status_code=403, detail="This account is suspended: contact support")
        if account.get("team_id") and account["team_id"] != owner["id"]:
            raise HTTPException(status_code=409, detail="You're on another team: leave it first")
        if teams.is_owner(account) or (account["plan"] != "trial" and account["status"] in ("active", "past_due")):
            raise HTTPException(status_code=409, detail="You have your own subscription: cancel it under Manage "
                                                        "billing first, so you don't pay twice")  # fmt: skip
    if not await request.app.state.teams.join(account["id"], owner["id"], owner["seats"]):
        raise HTTPException(status_code=409, detail="The team is full: ask its owner to add a seat")
    await request.app.state.teams.accept_invite(body.token)
    members = await request.app.state.teams.members(owner["id"])
    await audit(
        request, SERVICE, "team.join", owner["id"], details={"member": account["id"], "email": account["email"]}
    )
    await request.app.state.mailer.notify(owner, "team_joined", account["id"], member=account.get("name") or account["email"],
                                          used=len(members) + 1, seats=owner["seats"])  # fmt: skip
    return {"detail": f"You're on {_team_name(owner)}'s team. Sign in to Argus Personal with {account['email']}."}
