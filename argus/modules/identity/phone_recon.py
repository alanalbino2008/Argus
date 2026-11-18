"""What a phone number itself says: whether it is real, where it is from, and what kind of line it is.

Uses Google's libphonenumber (the ``phonenumbers`` package), the same rules Android uses to format
and check numbers. It covers every country, and works entirely offline: nothing is sent anywhere,
so it is safe in passive scans and anonymous cases.

For a number it records:

* whether it is **valid** (a real, allocated range) or merely possible (the right length). Some
  ranges are reserved for TV and film, such as the UK's 07700 900xxx, and are never valid;
* the **country**, and for landlines the **area** (for example "London");
* the **type of line**: mobile, landline, VoIP, toll-free, premium-rate, pager, personal number...
  VoIP and personal numbers are often used to hide who is behind them;
* the **original carrier** of mobile numbers (numbers can be moved to another network since);
* the **time zones**, which help when a contact's working hours are in question;
* the number written the ways people write it (international, national, digits only), which is
  what the web-mentions search looks for.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any, ClassVar

import phonenumbers
from phonenumbers import PhoneNumberFormat, PhoneNumberType, carrier, geocoder, timezone

from argus.core.http import HttpClient
from argus.core.models import Entity, EntityType, Relation, ScanConfig
from argus.modules.base import BaseModule

LINE_TYPES = {
    PhoneNumberType.MOBILE: "mobile",
    PhoneNumberType.FIXED_LINE: "landline",
    PhoneNumberType.FIXED_LINE_OR_MOBILE: "landline or mobile",
    PhoneNumberType.VOIP: "VoIP (internet phone)",
    PhoneNumberType.TOLL_FREE: "toll-free",
    PhoneNumberType.PREMIUM_RATE: "premium-rate",
    PhoneNumberType.SHARED_COST: "shared-cost",
    PhoneNumberType.PERSONAL_NUMBER: "personal number (forwards to another phone)",
    PhoneNumberType.PAGER: "pager",
    PhoneNumberType.UAN: "company number (UAN)",
    PhoneNumberType.VOICEMAIL: "voicemail",
}
# Line types often chosen to keep the real owner or location out of sight.
CONCEALING = {PhoneNumberType.VOIP, PhoneNumberType.PERSONAL_NUMBER}


def describe(raw: str, default_region: str | None = None) -> dict[str, Any] | None:
    """Everything libphonenumber knows about a number; None if it cannot be read as one."""
    try:
        number = phonenumbers.parse(raw, default_region)
    except phonenumbers.NumberParseException:
        return None
    if not phonenumbers.is_possible_number(number):
        return None
    valid = phonenumbers.is_valid_number(number)
    kind = phonenumbers.number_type(number)
    region = phonenumbers.region_code_for_number(number)
    e164 = phonenumbers.format_number(number, PhoneNumberFormat.E164)
    national = phonenumbers.format_number(number, PhoneNumberFormat.NATIONAL)
    zones = [z for z in timezone.time_zones_for_number(number) if z != "Etc/Unknown"]
    facts: dict[str, Any] = {
        "valid": valid,
        "e164": e164,
        "international": phonenumbers.format_number(number, PhoneNumberFormat.INTERNATIONAL),
        "national": national,
        "dial_code": f"+{number.country_code}",
        "country_code": region if region and region != "ZZ" else None,
        "country": geocoder.country_name_for_number(number, "en") or None,
        "area": (geocoder.description_for_number(number, "en") or None) if valid else None,
        "line_type": LINE_TYPES.get(kind) if valid else None,
        "carrier": (carrier.name_for_number(number, "en") or None) if valid else None,
        "time_zones": zones[:5],
        "concealing_line": valid and kind in CONCEALING,
    }
    written = {e164, e164.lstrip("+"), facts["international"], national, "".join(c for c in national if c.isdigit())}
    facts["written_as"] = sorted(w for w in written if w and len("".join(c for c in w if c.isdigit())) >= 7)
    return {k: v for k, v in facts.items() if v not in (None, "", [])} | {"valid": valid}


class PhoneReconModule(BaseModule):
    name = "phone_recon"
    description = "Phone numbers: valid or not, country and area, line type (mobile, VoIP...), carrier, time zone"
    supported_entity_types: ClassVar[list[EntityType]] = [EntityType.PHONE]
    attack_techniques = ("T1589",)
    enrichment = True  # offline facts about the number itself; also runs on numbers found at the depth limit
    third_party_safe = True  # contacts nobody

    async def run(self, entity: Entity, session: HttpClient, config: ScanConfig) -> AsyncIterator[Entity | Relation]:
        facts = describe(entity.value)
        if facts is None:
            entity.metadata["phone_valid"] = False
            return
        valid = facts.pop("valid")
        entity.metadata["phone_valid"] = valid
        entity.metadata["phone"] = facts
        if not valid:
            entity.metadata["phone"]["note"] = (
                "Not an allocated number range: possibly mistyped, invented, or reserved for TV and film"
            )
        return
        yield  # pragma: no cover - this module only enriches
