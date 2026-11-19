"""The emails Argus sends to account holders, in plain words.

Two kinds:

* **Account emails**: always sent, because they are about the account itself: welcome, payment
  received, payment failed, plan changed, cancellation confirmed, subscription ended, credits
  added, password reset and password changed.
* **Reminders**: the trial is ending, or has ended. Every reminder has a one-click unsubscribe
  link (and a ``List-Unsubscribe`` header), and switching them off is remembered.

Emails hold only account details (name, plan, dates, credits): never anything about cases, which
the account service never has.
"""

from __future__ import annotations

import hashlib
import hmac
from datetime import datetime
from html import escape
from typing import Any

REMINDERS = {"trial_ending", "trial_ended"}
SETTINGS_PATH = "Settings → Your Argus subscription"


def _day(value: Any) -> str:
    if not value:
        return ""
    when = value if isinstance(value, datetime) else datetime.fromisoformat(str(value))
    return f"{when.day} {when:%B %Y}"


def unsubscribe_token(secret: str, account_id: str) -> str:
    return hmac.new(f"argus-reminders:{secret}".encode(), account_id.encode(), hashlib.sha256).hexdigest()[:32]


def unsubscribe_ok(secret: str, account_id: str, token: str) -> bool:
    return hmac.compare_digest(unsubscribe_token(secret, account_id), token or "")


def _content(kind: str, a: dict[str, Any], ctx: dict[str, Any]) -> tuple[str, list[str]]:
    """Subject and paragraphs."""
    plan = ctx.get("plan_label") or a.get("plan_label") or a.get("plan", "")
    until = _day(ctx.get("valid_until") or a.get("valid_until"))
    if kind == "welcome":
        return "Welcome to Argus", [
            f"Your Argus account is ready, with a free trial until {until}.",
            "Your cases stay on your own computer: the account only unlocks Argus there. Sign in from Argus "
            "Personal with this email address.",
            f"When you're ready to subscribe, open Argus and go to {SETTINGS_PATH}."]  # fmt: skip
    if kind == "trial_ending":
        return "Your Argus trial ends soon", [
            f"Your free trial ends on {until}.",
            f"To keep starting new work, choose a plan in Argus under {SETTINGS_PATH}. If you don't, nothing is "
            "lost: your cases stay readable and exportable."]  # fmt: skip
    if kind == "trial_ended":
        return "Your Argus trial has ended", [
            f"Your free trial ended on {until}. Your cases are still on your computer, readable and exportable.",
            f"Subscribe any time in Argus under {SETTINGS_PATH} to carry on where you left off."]  # fmt: skip
    if kind == "subscription_started":
        return f"Thank you: your Argus {plan} plan is active", [
            f"Your payment went through and your {plan} plan is active, paid until {until}. It renews "
            "automatically.",
            f"Invoices, your card and cancelling are under Manage billing in {SETTINGS_PATH}."]  # fmt: skip
    if kind == "plan_changed":
        return f"Your Argus plan is now {plan}", [
            f"Your plan has changed to {plan}. Its monthly credits are available straight away.",
            f"Invoices and billing details are under Manage billing in {SETTINGS_PATH}."]  # fmt: skip
    if kind == "payment_failed":
        return "Action needed: your Argus payment didn't go through", [
            "We couldn't take your latest Argus payment. Your bank may have declined it, or the card may have "
            "expired.",
            f"Argus keeps working while the payment is retried (at least until {until}). Please update your card "
            f"under Manage billing in {SETTINGS_PATH}."]  # fmt: skip
    if kind == "payment_recovered":
        return "Your Argus payment went through", [f"Thank you: your payment went through. You're paid until {until}."]
    if kind == "cancellation_scheduled":
        return "Your Argus subscription is cancelled", [
            f"Your subscription won't renew. Argus keeps working until {until}, the end of the period you've paid "
            "for.",
            f"Changed your mind? Renew under Manage billing in {SETTINGS_PATH} before then."]  # fmt: skip
    if kind == "subscription_ended":
        return "Your Argus subscription has ended", [
            "Your subscription has ended. Your cases are still on your computer, readable and exportable; only new "
            "work waits.",
            f"Subscribe again any time in Argus under {SETTINGS_PATH}."]  # fmt: skip
    if kind == "credits_added":
        credits = int(ctx.get("credits") or 0)
        return f"{credits} Argus credits added", [
            f"Thank you: {credits} credits have been added to your account. Bought credits never expire.",
            "They're used for premium sources and the AI analyst once your monthly allowance runs out."]  # fmt: skip
    if kind == "password_reset":
        return "Reset your Argus password", [
            "Someone (hopefully you) asked to reset the password of your Argus account.",
            f"Choose a new password here (the link works once, for {ctx.get('minutes', 60)} minutes):",
            f"LINK:{ctx['link']}",
            "If you didn't ask for this, ignore this email: your password stays as it is."]  # fmt: skip
    if kind == "password_changed":
        return "Your Argus password was changed", [
            "The password of your Argus account was just changed, and every computer was signed out. Sign in again "
            "with the new password.",
            "If this wasn't you, reset your password straight away and contact support."]  # fmt: skip
    raise ValueError(f"Unknown email {kind!r}")


def render(kind: str, account: dict[str, Any], *, support: str = "", unsubscribe: str = "",
           **ctx: Any) -> tuple[str, str, str]:  # fmt: skip
    """(subject, plain text, HTML) for one email."""
    subject, paragraphs = _content(kind, account, ctx)
    hello = f"Hello {account['name']}," if account.get("name") else "Hello,"
    footer = ["You're receiving this because you have an Argus account."]
    if support:
        footer.append(f"Questions? Write to {support}.")
    text_parts, html_parts = [hello], [f"<p>{escape(hello)}</p>"]
    for p in paragraphs:
        if p.startswith("LINK:"):
            url = p[5:]
            text_parts.append(url)
            html_parts.append(f'<p><a href="{escape(url, quote=True)}" style="display:inline-block;padding:10px 18px;'
                              f'background:#4f5bd5;color:#fff;border-radius:6px;text-decoration:none">'
                              f"Choose a new password</a></p>"
                              f'<p style="font-size:12px;color:#666">Or paste this into your browser: {escape(url)}</p>')  # fmt: skip
        else:
            text_parts.append(p)
            html_parts.append(f"<p>{escape(p)}</p>")
    text_parts.append("— Argus")
    html_parts.append("<p>— Argus</p>")
    if unsubscribe:
        footer.append(f"Don't want reminders like this? Unsubscribe: {unsubscribe}")
    text = "\n\n".join(text_parts) + "\n\n--\n" + "\n".join(footer) + "\n"
    foot_html = "<br>".join(escape(f) for f in footer[:2])
    if unsubscribe:
        foot_html += (
            f'<br><a href="{escape(unsubscribe, quote=True)}" style="color:#888">Unsubscribe from reminders</a>'
        )
    html = ('<!doctype html><html><body style="font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif;'
            'font-size:15px;line-height:1.5;color:#1d1f24;max-width:560px;margin:0 auto;padding:24px">'
            + "".join(html_parts)
            + f'<hr style="border:none;border-top:1px solid #e3e5ea;margin:24px 0">'
            f'<p style="font-size:12px;color:#888">{foot_html}</p></body></html>')  # fmt: skip
    return subject, text, html
