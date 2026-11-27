"""Scan windows (business hours): the hours of the week a scan may run, in one time zone.

Stored on a scan / scheduler as JSON ``{"tz": "Europe/Berlin", "grid": ["000000000111111111000000", ...]}`` -
seven strings (Monday first) of 24 characters, '1' = that hour is open. An empty value means any time.

The queue only hands out a scan's jobs while its window is open. Jobs already running when it closes finish;
nothing new starts until it opens again."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from .cron import CronError, zone

DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]


class WindowError(ValueError):
    """An unusable window. The message is user-facing."""


def parse(raw) -> dict | None:
    """The window as {tz, grid} or None (any time). Never raises: a broken value means 'any time'."""
    if not raw:
        return None
    try:
        w = json.loads(raw) if isinstance(raw, str) else raw
        grid = w.get("grid")
        if not (isinstance(grid, list) and len(grid) == 7 and all(isinstance(g, str) and len(g) == 24 for g in grid)):
            return None
        if all(set(g) == {"1"} for g in grid):
            return None
        return {"tz": str(w.get("tz") or "UTC"), "grid": grid}
    except Exception:  # noqa: BLE001
        return None


def normalize(w) -> str:
    """Validate a window from the UI and return what to store ('' = any time). Raises WindowError."""
    if not w:
        return ""
    if not isinstance(w, dict):
        raise WindowError("the scan window is malformed")
    grid = w.get("grid")
    if not (isinstance(grid, list) and len(grid) == 7):
        raise WindowError("the scan window needs all seven days")
    rows = []
    for g in grid:
        if isinstance(g, list):
            g = "".join("1" if x else "0" for x in g)
        g = str(g)
        if len(g) != 24 or set(g) - {"0", "1"}:
            raise WindowError("the scan window needs 24 hours per day")
        rows.append(g)
    if not any("1" in g for g in rows):
        raise WindowError("the scan window has no open hours — pick at least one, or choose “Any time”")
    tz = str(w.get("tz") or "UTC")
    try:
        zone(tz)
    except CronError as e:
        raise WindowError(str(e))
    if all(set(g) == {"1"} for g in rows):
        return ""
    return json.dumps({"tz": tz, "grid": rows})


def _local(w: dict, at: datetime) -> datetime:
    return at.astimezone(zone(w["tz"]))


def is_open(w: dict | None, at: datetime | None = None) -> bool:
    if not w:
        return True
    t = _local(w, at or datetime.now(timezone.utc))
    return w["grid"][t.weekday()][t.hour] == "1"


def next_change(w: dict | None, at: datetime | None = None) -> datetime | None:
    """When the window next opens (if closed now) or closes (if open now), at hour precision; None if never."""
    if not w:
        return None
    at = at or datetime.now(timezone.utc)
    now_open = is_open(w, at)
    z = zone(w["tz"])
    # step in absolute hours (UTC) from the start of the current local hour, so DST shifts are handled
    u = _local(w, at).replace(minute=0, second=0, microsecond=0).astimezone(timezone.utc)
    for _ in range(24 * 8):
        u = u + timedelta(hours=1)
        t = u.astimezone(z)
        if (w["grid"][t.weekday()][t.hour] == "1") != now_open:
            return u
    return None


def _ranges(row: str) -> list[str]:
    out, h = [], 0
    while h < 24:
        if row[h] == "1":
            s = h
            while h < 24 and row[h] == "1":
                h += 1
            out.append(f"{s:02d}:00–{h:02d}:00")
        else:
            h += 1
    return out


def describe(w: dict | None) -> str:
    """'Mon–Fri 09:00–18:00 (Europe/Berlin)'; 'Any time' when there is no window."""
    if not w:
        return "Any time"
    per_day = [", ".join(_ranges(g)) for g in w["grid"]]
    groups: list[list] = []                       # [[first_day, last_day, text]]
    for d, text in enumerate(per_day):
        if groups and groups[-1][2] == text and groups[-1][1] == d - 1:
            groups[-1][1] = d
        else:
            groups.append([d, d, text])
    parts = []
    for a, b, text in groups:
        if not text:
            continue
        days = DAYS[a] if a == b else (f"{DAYS[a]}–{DAYS[b]}" if b > a + 1 else f"{DAYS[a]}, {DAYS[b]}")
        if a == 0 and b == 6:
            days = "Every day"
        parts.append(f"{days} {text}")
    return " · ".join(parts) + f" ({w['tz']})"


def info(raw, at: datetime | None = None) -> dict:
    """What the UI shows for a stored window."""
    w = parse(raw)
    return {"window": w, "window_text": describe(w), "window_open": is_open(w, at),
            "window_next": next_change(w, at)}
