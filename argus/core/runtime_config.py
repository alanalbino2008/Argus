"""Settings the owner changes from the owner console, without touching files or the terminal.

* **What can be changed** is a fixed list (``FIELDS``): payments, email, accounts and trials,
  the paid data sources' keys, plan allowances, and who may administer the server. Each has a
  label, help text and a check, so a typo is caught before it is saved.
* **Where it is kept**: in the database. Secrets (API keys, passwords) are encrypted with the
  owner's encryption, and are never shown back: only whether they are set and their last four
  characters.
* **Precedence**: a value set in the console wins over the deployment's own configuration
  (environment variables, Helm). Clearing it in the console goes back to the deployment's value.
* **Live**: every setting here is read when it is used, so a change applies at once, with no
  restart. Other servers of the same deployment pick it up within 30 seconds.
"""

from __future__ import annotations

import logging
import re
import weakref
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from pydantic import SecretStr, TypeAdapter, ValidationError

from argus.accounts.licence import PLANS
from argus.core.settings import Settings

logger = logging.getLogger(__name__)
STATE_KEY = "runtime_config"
CONTEXT = "runtime-config"


@dataclass(frozen=True)
class Setting:
    name: str
    section: str
    label: str
    help: str = ""
    kind: str = "text"  # text | secret | bool | int | choice | email | url
    choices: tuple[str, ...] = ()
    pattern: str = ""
    low: int | None = None
    high: int | None = None
    placeholder: str = ""
    extra: dict[str, Any] = field(default_factory=dict)


SECTIONS = {
    "payments": "Payments (Stripe)",
    "email": "Email",
    "accounts": "Accounts and trials",
    "sources": "Paid data sources",
    "legal": "Legal",
    "alerts": "Alerts",
    "desktop": "Desktop app",
    "security": "Security",
}
PRICE = r"^(price_[A-Za-z0-9]+)?$"
FIELDS: list[Setting] = [
    Setting(
        "stripe_secret_key",
        "payments",
        "Stripe secret key",
        "Stripe dashboard → Developers → API keys. Starts with sk_live_ (real money) or sk_test_ (trying it out).",
        "secret",
        pattern=r"^(sk|rk)_(live|test)_\S+$",
    ),
    Setting(
        "stripe_webhook_secret",
        "payments",
        "Webhook signing secret",
        "Stripe → Developers → Webhooks → your endpoint → Signing secret (whsec_...).",
        "secret",
        pattern=r"^whsec_\S+$",
    ),
    Setting(
        "stripe_price_byok",
        "payments",
        "Price: Bring your own keys",
        "The plan's recurring price id (price_...). Leave empty not to sell this plan.",
        pattern=PRICE,
        placeholder="price_...",
    ),
    Setting("stripe_price_personal", "payments", "Price: Personal", pattern=PRICE, placeholder="price_..."),
    Setting("stripe_price_professional", "payments", "Price: Professional", pattern=PRICE, placeholder="price_..."),
    Setting(
        "stripe_price_business",
        "payments",
        "Price: Business (per seat)",
        "A recurring per-seat price.",
        pattern=PRICE,
        placeholder="price_...",
    ),
    Setting(
        "stripe_price_business_setup",
        "payments",
        "Price: Business one-off set-up fee",
        "Optional, a one-off price.",
        pattern=PRICE,
        placeholder="price_...",
    ),
    Setting(
        "stripe_credit_packs",
        "payments",
        "Credit packs",
        "Credits and their one-off price, e.g. 500=price_abc,2000=price_def.",
        pattern=r"^(\s*\d+\s*=\s*price_[A-Za-z0-9]+\s*)?(,\s*\d+\s*=\s*price_[A-Za-z0-9]+\s*)*$",
        placeholder="500=price_...,2000=price_...",
    ),
    Setting(
        "smtp_host",
        "email",
        "Mail server (SMTP host)",
        "From your email provider, e.g. smtp.postmarkapp.com.",
        pattern=r"^[A-Za-z0-9.\-]*$",
    ),
    Setting("smtp_port", "email", "Port", "587 for STARTTLS (most providers), 465 for TLS.", "int", low=1, high=65535),
    Setting("smtp_security", "email", "Security", "", "choice", choices=("starttls", "tls", "none")),
    Setting("smtp_username", "email", "Username"),
    Setting("smtp_password", "email", "Password", "", "secret"),
    Setting("smtp_from", "email", "Sender", "e.g. Argus <hello@yourdomain.com>. Set up SPF and DKIM for its domain."),
    Setting("account_email_from", "email", "Sender of customer emails", "Leave empty to use the sender above."),
    Setting("support_email", "email", "Support address", "Shown in customer emails; replies go here.", "email"),
    Setting("account_emails_enabled", "email", "Send customer emails", "Welcome, payments, reminders, resets.", "bool"),
    Setting(
        "account_signup_enabled", "accounts", "Anyone can create an account", "Off: only accounts you create.", "bool"
    ),
    Setting("trial_days", "accounts", "Free trial length (days)", "", "int", low=0, high=90),
    Setting("licence_offline_days", "accounts", "Days Argus Personal works offline", "", "int", low=1, high=90),
    Setting(
        "companies_house_api_key",
        "sources",
        "UK Companies House API key",
        "Pays for customers' Companies House lookups (Argus Connect).",
        "secret",
        pattern=r"^\S{8,256}$",
    ),
    Setting(
        "web_search_api_key",
        "sources",
        "Brave Search API key",
        "Pays for customers' web searches.",
        "secret",
        pattern=r"^\S{8,256}$",
    ),
    Setting(
        "anthropic_api_key",
        "sources",
        "Claude (Anthropic) API key",
        "Pays for customers' AI analyst requests.",
        "secret",
        pattern=r"^sk-ant-\S+$",
    ),
    Setting(
        "opencorporates_api_key",
        "sources",
        "OpenCorporates API token",
        "Pays for customers' lookups in company registers of about 140 countries.",
        "secret",
        pattern=r"^\S{8,256}$",
    ),
    Setting(
        "courtlistener_api_key",
        "sources",
        "CourtListener API token",
        "Pays for customers' US court record searches (a free CourtListener account gives one).",
        "secret",
        pattern=r"^\S{8,256}$",
    ),
    Setting(
        "tineye_api_key",
        "sources",
        "TinEye API key",
        "Pays for customers' reverse image searches.",
        "secret",
        pattern=r"^\S{8,256}$",
    ),
    Setting("legal_company_name", "legal", "Business legal name", "As registered, e.g. Argus Intelligence Ltd."),
    Setting("legal_company_number", "legal", "Company number", "If registered (e.g. at Companies House)."),
    Setting("legal_company_address", "legal", "Registered address", "One line."),
    Setting("legal_contact_email", "legal", "Contact email", "For questions, refunds and reports of misuse.", "email"),
    Setting("legal_privacy_email", "legal", "Privacy contact", "Leave empty to use the contact email.", "email"),
    Setting("legal_governing_law", "legal", "Governing law", "e.g. England and Wales, Scotland, Ireland."),
    Setting(
        "legal_supervisory_authority",
        "legal",
        "Data protection regulator",
        "Where customers can complain, e.g. the Information Commissioner's Office (ico.org.uk).",
    ),
    Setting(
        "legal_hosting_provider",
        "legal",
        "Hosting provider | location",
        "e.g. Amazon Web Services | Ireland (EU). Listed in Subprocessors.",
    ),
    Setting("legal_email_provider", "legal", "Email provider | location", "e.g. Postmark | United States."),
    Setting(
        "legal_terms_version",
        "legal",
        "Published version",
        "Set a date (YYYY-MM-DD) to publish. Change it when the documents change: customers are asked to accept again.",
        pattern=r"^(\d{4}-\d{2}-\d{2})?$",
        placeholder="e.g. 2026-11-20",
    ),
    Setting("legal_reviewed", "legal", "A lawyer has reviewed these documents", "", "bool"),
    Setting(
        "owner_alerts_enabled",
        "alerts",
        "Email me when something needs attention",
        "Problems (and when they're fixed): payments, email, database, backups, disk space, background work.",
        "bool",
    ),
    Setting("owner_alert_email", "alerts", "Send alerts to", "Leave empty to use your owner email.", "email"),
    Setting("owner_alert_payments", "alerts", "Disputes and failed payments", "", "bool"),
    Setting("owner_alert_new_customers", "alerts", "Each new paying customer", "", "bool"),
    Setting(
        "owner_daily_summary",
        "alerts",
        "Daily summary",
        "Sign-ups, customers, payments and health, once a day.",
        "bool",
    ),
    Setting("owner_summary_hour", "alerts", "Summary hour (UTC)", "0 to 23.", "int", low=0, high=23),
    Setting(
        "desktop_latest_version",
        "desktop",
        "Newest desktop version",
        "When you publish a new installer, enter its version: installed copies then offer the update.",
        pattern=r"^(\d{1,4}\.\d{1,4}\.\d{1,4})?$",
        placeholder="e.g. 1.55.0",
    ),
    Setting(
        "desktop_download_url",
        "desktop",
        "Download page",
        "Where the update button takes investigators (for example your GitHub Releases page).",
        "url",
        pattern=r"^(https://\S+)?$",
        placeholder="https://…",
    ),
    Setting(
        "admin_keys_allowed",
        "security",
        "API keys and other admins may administer the server",
        "Off: only you, signed in here, can manage accounts, the Business page and server settings.",
        "bool",
    ),
]
BY_NAME = {f.name: f for f in FIELDS}
PLAN_LIMITS = {"monthly_credits": (0, 1_000_000), "max_devices": (1, 20)}
# each server's own (deployment) values, to go back to; the weak reference makes sure a new
# settings object never inherits the values of an old one that happened to share its id
_defaults_by: dict[int, tuple[weakref.ref[Settings], dict[str, Any]]] = {}
_plan_defaults: dict[str, dict[str, int]] = {}
_version: str = ""


class ConfigError(ValueError):
    pass


def _raw(value: Any) -> Any:
    return value.get_secret_value() if isinstance(value, SecretStr) else value


def validate(name: str, value: Any) -> Any:
    """The value as the setting stores it; raises ConfigError with a plain explanation."""
    spec = BY_NAME.get(name)
    if spec is None:
        raise ConfigError(f"{name} can't be changed here")
    if spec.kind == "bool":
        if not isinstance(value, bool):
            raise ConfigError(f"{spec.label}: choose on or off")
        return value
    if spec.kind == "int":
        try:
            number = int(value)
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"{spec.label}: enter a whole number") from exc
        if (spec.low is not None and number < spec.low) or (spec.high is not None and number > spec.high):
            raise ConfigError(f"{spec.label}: between {spec.low} and {spec.high}")
        return number
    text = str(value if value is not None else "").strip()
    if len(text) > 1000 or any(ord(ch) < 32 for ch in text):
        raise ConfigError(f"{spec.label}: that doesn't look right")
    if spec.kind == "choice" and text not in spec.choices:
        raise ConfigError(f"{spec.label}: one of {', '.join(spec.choices)}")
    if spec.kind == "email" and text and not re.match(r"^[^@\s]{1,64}@[^@\s]{1,255}\.[A-Za-z]{2,}$", text):
        raise ConfigError(f"{spec.label}: enter an email address")
    if spec.pattern and text and not re.match(spec.pattern, text):
        raise ConfigError(f"{spec.label}: that doesn't look right ({spec.placeholder or 'check the format'})")
    return text


def _apply_one(settings: Settings, name: str, value: Any) -> None:
    annotation = Settings.model_fields[name].annotation
    if annotation is None:
        raise ValueError(f"{name} has no type")
    if value in ("", None) and BY_NAME[name].kind in ("secret", "text", "email", "url"):
        value = "" if annotation is str else None
    object.__setattr__(settings, name, TypeAdapter(annotation).validate_python(value))


def _apply_safely(settings: Settings, name: str, value: Any) -> None:
    try:
        _apply_one(settings, name, value)
    except (ValidationError, ValueError):  # a value that no longer fits: the deployment's stays
        object.__setattr__(settings, name, _defaults(settings)[name])


def _defaults(settings: Settings) -> dict[str, Any]:
    known = _defaults_by.get(id(settings))
    if known is None or known[0]() is not settings:
        for key in [k for k, (ref, _v) in _defaults_by.items() if ref() is None]:
            del _defaults_by[key]
        known = (weakref.ref(settings), {f.name: getattr(settings, f.name) for f in FIELDS})
        _defaults_by[id(settings)] = known
    return known[1]


def remember_defaults(settings: Settings) -> None:
    """The deployment's own values (taken once, before any console value is applied)."""
    _defaults(settings)
    if not _plan_defaults:
        _plan_defaults.update({p: {k: int(v.get(k, 0)) for k in PLAN_LIMITS} for p, v in PLANS.items()})


def apply(settings: Settings, stored: dict[str, Any] | None, box: Any) -> None:
    """Put the stored console values into effect (the deployment's values where none is set)."""
    global _version
    remember_defaults(settings)
    stored = stored or {}
    values = dict(stored.get("values") or {})
    if stored.get("sealed") and box.available:
        try:
            values.update(box.open(stored["sealed"], CONTEXT))
        except Exception:  # noqa: BLE001 - unreadable secrets (a lost key): the deployment's values stay
            logger.warning("The owner console's saved secrets could not be read; using the deployment's")
    for spec in FIELDS:
        _apply_safely(settings, spec.name, values[spec.name] if spec.name in values else _defaults(settings)[spec.name])
    for plan, limits in _plan_defaults.items():
        override = (stored.get("plans") or {}).get(plan) or {}
        for key, default in limits.items():
            PLANS[plan][key] = int(override.get(key, default))
    _version = str(stored.get("version") or "")


def version() -> str:
    return _version


def describe(settings: Settings, stored: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Every setting for the console: current value (never a secret's), and where it comes from."""
    stored = stored or {}
    console = set((stored.get("values") or {}).keys()) | set(stored.get("secret_names") or [])
    out = []
    for spec in FIELDS:
        value = _raw(getattr(settings, spec.name))
        row: dict[str, Any] = {"name": spec.name, "section": spec.section, "label": spec.label, "help": spec.help,
                               "kind": spec.kind, "choices": list(spec.choices), "placeholder": spec.placeholder,
                               "source": "console" if spec.name in console else
                               ("deployment" if _raw(_defaults(settings).get(spec.name)) not in (None, "") else "default")}  # fmt: skip
        if spec.kind == "secret":
            row.update(set=bool(value), ends_with=str(value)[-4:] if value else None)
        else:
            row["value"] = value
        out.append(row)
    return out


def plans_view() -> list[dict[str, Any]]:
    return [{"plan": p, "label": v["label"], "monthly_credits": int(v.get("monthly_credits", 0)),
             "max_devices": int(v.get("max_devices", 1)), "per_seat": bool(v.get("per_seat")),
             "features": list(v.get("features", []))} for p, v in PLANS.items()]  # fmt: skip


def updated(stored: dict[str, Any] | None, changes: dict[str, Any], box: Any) -> dict[str, Any]:
    """The stored document with ``changes`` (``None`` = back to the deployment's value)."""
    stored = dict(stored or {})
    values = dict(stored.get("values") or {})
    secrets: dict[str, Any] = {}
    if stored.get("sealed") and box.available:
        try:
            secrets = dict(box.open(stored["sealed"], CONTEXT))
        except Exception:  # noqa: BLE001
            secrets = {}
    for name, value in changes.items():
        spec = BY_NAME.get(name)
        if spec is None:
            raise ConfigError(f"{name} can't be changed here")
        target = secrets if spec.kind == "secret" else values
        if value is None:
            target.pop(name, None)
        else:
            target[name] = validate(name, value)
    if secrets and not box.available:
        raise ConfigError("Secrets need this server's encryption key")
    stored["values"] = values
    stored["sealed"] = box.seal(secrets, CONTEXT) if secrets else ""
    stored["secret_names"] = sorted(secrets)
    stored["version"] = datetime.now(timezone.utc).isoformat()
    return stored


def updated_plans(stored: dict[str, Any] | None, plans: dict[str, dict[str, Any]]) -> dict[str, Any]:
    stored = dict(stored or {})
    current = dict(stored.get("plans") or {})
    for plan, limits in plans.items():
        if plan not in PLANS:
            raise ConfigError(f"Unknown plan {plan}")
        entry = dict(current.get(plan) or {})
        for key, value in (limits or {}).items():
            if key not in PLAN_LIMITS:
                raise ConfigError(f"{key} can't be changed here")
            low, high = PLAN_LIMITS[key]
            try:
                number = int(value)
            except (TypeError, ValueError) as exc:
                raise ConfigError(f"{PLANS[plan]['label']}: {key.replace('_', ' ')} must be a whole number") from exc
            if not low <= number <= high:
                raise ConfigError(f"{PLANS[plan]['label']}: {key.replace('_', ' ')} between {low} and {high}")
            entry[key] = number
        current[plan] = entry
    stored["plans"] = current
    stored["version"] = datetime.now(timezone.utc).isoformat()
    return stored
