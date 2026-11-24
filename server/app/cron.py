"""Cron schedules for schedulers: validation, the next run times (in the scheduler's time zone) and a plain-English
description, via cronsim. Standard 5-field expressions plus @hourly / @daily / @weekly / @monthly / @yearly."""
from __future__ import annotations

from datetime import datetime, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from cronsim import CronSim, CronSimError

MIN_GAP_SECONDS = 15 * 60          # a scan can't be scheduled more often than every 15 minutes
_ALIASES = {"@hourly": "0 * * * *", "@daily": "0 0 * * *", "@midnight": "0 0 * * *", "@weekly": "0 0 * * 0",
            "@monthly": "0 0 1 * *", "@yearly": "0 0 1 1 *", "@annually": "0 0 1 1 *"}


class CronError(ValueError):
    """A schedule that can't be used; the message is user-facing."""


def normalize(expr: str) -> str:
    e = " ".join((expr or "").split())
    return _ALIASES.get(e.lower(), e)


def zone(tz: str) -> ZoneInfo:
    try:
        return ZoneInfo(tz or "UTC")
    except (ZoneInfoNotFoundError, ValueError):
        raise CronError(f"unknown time zone '{tz}'")


def next_runs(expr: str, tz: str = "UTC", n: int = 1, after: datetime | None = None) -> list[datetime]:
    """The next `n` run times (UTC, timezone-aware) after `after` (default: now)."""
    e = normalize(expr)
    z = zone(tz)
    start = (after or datetime.now(timezone.utc)).astimezone(z).replace(second=0, microsecond=0)
    try:
        it = CronSim(e, start)
        return [next(it).astimezone(timezone.utc) for _ in range(n)]
    except CronSimError as exc:
        raise CronError(f"invalid cron expression: {exc}")
    except StopIteration:
        raise CronError("this schedule never runs")


def describe(expr: str) -> str:
    try:
        text = CronSim(normalize(expr), datetime.now()).explain()
        return text[:1].upper() + text[1:]
    except Exception:  # noqa: BLE001
        return normalize(expr)


def validate(expr: str, tz: str = "UTC") -> str:
    """Return the normalized expression, or raise CronError (bad syntax, unknown zone, or more often than every
    15 minutes)."""
    e = normalize(expr)
    if len(e.split()) != 5:
        raise CronError("use 5 fields: minute hour day-of-month month day-of-week (e.g. 0 3 * * *)")
    runs = next_runs(e, tz, 4)
    gaps = [(b - a).total_seconds() for a, b in zip(runs, runs[1:])]
    if gaps and min(gaps) < MIN_GAP_SECONDS:
        raise CronError("that runs more often than every 15 minutes — pick a less frequent schedule")
    return e
