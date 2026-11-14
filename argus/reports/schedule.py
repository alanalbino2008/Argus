"""When a scheduled report runs next.

Schedules are expressed the way people think about them, "every Monday at 08:00 in
London", so the arithmetic is done in **local wall-clock time** and converted to UTC
afterwards. A report set for 08:00 stays at 08:00 when the clocks change for daylight
saving; doing the arithmetic in UTC would shift it to 07:00 or 09:00 for half the year.

* A time that does not exist (inside the hour skipped when clocks go forward) runs one hour
  later, e.g. 01:30 becomes 02:30; a time that occurs twice (clocks going back) runs once, at
  the first occurrence.
* Monthly schedules use days 1-28, so every month has the chosen day.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import date, datetime, time, timedelta, timezone
from typing import Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError, available_timezones

Frequency = Literal["weekly", "monthly"]
WEEKDAYS = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")


class ScheduleError(ValueError):
    """Invalid schedule; the message is safe to show."""


def zone(name: str) -> ZoneInfo:
    try:
        if name not in available_timezones() and name != "UTC":
            raise ZoneInfoNotFoundError(name)
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ScheduleError(f"Unknown time zone {name!r} (use a name like Europe/London)") from exc


def validate(frequency: str, weekday: int | None, day_of_month: int | None, hour: int, minute: int, tz: str) -> None:
    zone(tz)
    if frequency == "weekly" and (weekday is None or not 0 <= weekday <= 6):
        raise ScheduleError("Choose the day of the week")
    if frequency == "monthly" and (day_of_month is None or not 1 <= day_of_month <= 28):
        raise ScheduleError("Choose a day of the month between 1 and 28")
    if frequency not in ("weekly", "monthly"):
        raise ScheduleError("Frequency must be weekly or monthly")
    if not (0 <= hour <= 23 and 0 <= minute <= 59):
        raise ScheduleError("Invalid time of day")


def _localise(day: date, at: time, tz: ZoneInfo) -> datetime:
    """Local wall time -> aware datetime: DST gaps shift one hour later, folds use the first occurrence."""
    local = datetime.combine(day, at, tzinfo=tz).replace(fold=0)
    roundtrip = local.astimezone(timezone.utc).astimezone(tz)
    if roundtrip.replace(tzinfo=None) != local.replace(tzinfo=None):  # in a gap: move to the gap's end
        return roundtrip
    return local


def _candidates(frequency: str, weekday: int | None, day_of_month: int | None, start: date) -> Iterator[date]:
    if frequency == "weekly":
        if weekday is None:
            raise ScheduleError("Choose the day of the week")
        day = start + timedelta(days=(weekday - start.weekday()) % 7)
        while True:
            yield day
            day += timedelta(days=7)
    else:
        if day_of_month is None:
            raise ScheduleError("Choose a day of the month between 1 and 28")
        year, month = start.year, start.month
        while True:
            yield date(year, month, day_of_month)
            year, month = (year + 1, 1) if month == 12 else (year, month + 1)


def next_run(
    frequency: str,
    weekday: int | None,
    day_of_month: int | None,
    hour: int,
    minute: int,
    tz_name: str,
    after: datetime,
) -> datetime:
    """The first scheduled moment strictly after ``after``, in UTC."""
    tz = zone(tz_name)
    local_after = after.astimezone(tz)
    at = time(hour, minute)
    for day in _candidates(frequency, weekday, day_of_month, local_after.date() - timedelta(days=1)):
        moment = _localise(day, at, tz)
        if moment > after:
            return moment.astimezone(timezone.utc)
    raise ScheduleError("No run time could be computed")  # pragma: no cover - the candidates never end


def describe(frequency: str, weekday: int | None, day_of_month: int | None, hour: int, minute: int, tz: str) -> str:
    when = f"{hour:02d}:{minute:02d} {tz}"
    if frequency == "weekly" and weekday is not None:
        return f"Every {WEEKDAYS[weekday]} at {when}"
    suffix = "th" if day_of_month in (11, 12, 13) else {1: "st", 2: "nd", 3: "rd"}.get((day_of_month or 0) % 10, "th")
    return f"Monthly on the {day_of_month}{suffix} at {when}"
