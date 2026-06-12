"""JSON envelope output - the Python port of the ``JsonOutput`` PHP trait.

Every tool returns the same shape::

    {"success": <bool>, "data": <list>, "error": <str|null>}

``success`` is ``True`` exactly when ``error`` is ``None``. The envelope is
written to ``--output`` when given, otherwise to stdout. Diagnostic/debug
chatter never touches stdout (it goes to stderr via :func:`debug_logger`) so
stdout always stays parseable JSON.
"""

from __future__ import annotations

import json
import re
import sys
from typing import Any, Callable, Iterable

# When True, stdout output is rendered as a text table instead of JSON. Set once
# by the CLI from the --table flag. It only affects stdout: writes to a file
# (--output, and the temp files tools pass to each other) always stay JSON.
_TABLE_MODE = False

# The kind of payload the current tool/workflow emits: one of "findings", "urls",
# "items". Set by the CLI/runner from the tool's KIND before it runs, so every
# envelope is self-describing and consumers know the data shape up front.
_OUTPUT_KIND = "items"
KINDS = ("findings", "urls", "items")


def set_table_mode(enabled: bool) -> None:
    global _TABLE_MODE
    _TABLE_MODE = enabled


def set_output_kind(kind: str) -> None:
    global _OUTPUT_KIND
    _OUTPUT_KIND = kind if kind in KINDS else "items"


# Severity ordering for findings output: worst first.
_SEVERITY_RANK = {
    "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "informational": 4,
}

# The set of severities to keep in findings output, or None for "report all".
# Set once by the CLI from the --severity flag. Only ever consulted for the
# "findings" kind (it is meaningless for urls/items), so non-findings output is
# never touched by it.
_SEVERITY_FILTER: set[str] | None = None

# Canonical severity levels a finding can carry. "informational" is an accepted
# spelling of "info"; everything else is normalised to one of these or left
# unclassified.
VALID_SEVERITIES = ("critical", "high", "medium", "low", "info")


def _normalize_severity(raw: Any) -> str | None:
    """Canonicalise a severity token to one of :data:`VALID_SEVERITIES`.

    Returns ``None`` when the value is empty or unrecognised, so callers can
    treat "couldn't classify this" distinctly from "classified as info".
    """
    text = str(raw).strip().lower()
    if text in ("informational", "information"):
        text = "info"
    return text if text in VALID_SEVERITIES else None


def set_severity_filter(spec: str | None) -> None:
    """Set the findings severity filter from a ``--severity`` spec.

    ``spec`` is a comma/space-separated list like ``"critical,high"``. An empty
    or ``None`` spec disables filtering (report everything). Unrecognised levels
    are skipped with a stderr warning rather than aborting.
    """
    global _SEVERITY_FILTER
    if not spec:
        _SEVERITY_FILTER = None
        return
    levels: set[str] = set()
    for token in re.split(r"[,\s]+", str(spec).strip()):
        if not token:
            continue
        level = _normalize_severity(token)
        if level is None:
            debug_print(
                f"boxcutter: ignoring unknown --severity value '{token}' "
                f"(expected one of: {', '.join(VALID_SEVERITIES)})"
            )
        else:
            levels.add(level)
    _SEVERITY_FILTER = levels or None


def _filter_by_severity(data: list[Any]) -> list[Any]:
    """Keep only findings whose severity is in the active filter set.

    Conservative by design: an item is dropped only when its severity can be
    positively classified and falls outside the requested set. Anything we can't
    classify (non-dict items, a missing or unrecognised ``severity``) is kept, so
    the filter never silently hides a finding it didn't understand.
    """
    if _SEVERITY_FILTER is None or not isinstance(data, list):
        return data
    kept: list[Any] = []
    for item in data:
        level = _normalize_severity(item.get("severity")) if isinstance(item, dict) else None
        if level is None or level in _SEVERITY_FILTER:
            kept.append(item)
    return kept


def _sort_by_severity(data: list[Any]) -> list[Any]:
    """Stable-sort findings worst-first (critical/high on top). Leaves the list
    untouched unless every item is a dict carrying a ``severity``."""
    if not isinstance(data, list) or not data:
        return data
    if not all(isinstance(item, dict) and "severity" in item for item in data):
        return data
    return sorted(data, key=lambda f: _SEVERITY_RANK.get(str(f.get("severity", "")).lower(), 5))


def _dedup_findings(data: list[Any]) -> list[Any]:
    """Drop duplicate findings, keeping the first (highest-severity after sorting).
    Two findings are the same when their (title, url) match - the same issue at the
    same location, however many tools/passes surfaced it."""
    if not isinstance(data, list) or not data:
        return data
    seen: set = set()
    out: list[Any] = []
    for item in data:
        if isinstance(item, dict):
            key = (str(item.get("title", "")).strip().lower(), str(item.get("url", "")).strip())
        else:
            key = ("", str(item))
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def output_result(
    data: list[Any],
    output_file: str | None = None,
    error: str | None = None,
    *,
    extra: dict[str, Any] | None = None,
    pretty: bool = False,
) -> None:
    """Emit the standard ``{success, data, error}`` envelope.

    ``extra`` injects additional top-level keys (e.g. ``sources`` for
    git-extract). ``pretty`` switches to indented JSON. Findings are sorted
    worst-first (critical/high on top), deduplicated by (title, url), and - when
    a ``--severity`` filter is active - reduced to the requested severities.
    """
    if _OUTPUT_KIND == "findings":
        data = _filter_by_severity(_dedup_findings(_sort_by_severity(data)))
    payload: dict[str, Any] = {
        "success": error is None,
        "kind": _OUTPUT_KIND,
        "data": data,
        "error": error,
    }
    if extra:
        payload.update(extra)

    if output_file:
        text = json.dumps(payload, ensure_ascii=False, indent=2) if pretty else \
            json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        with open(output_file, "w", encoding="utf-8") as fh:
            fh.write(text)
        return

    if _TABLE_MODE:
        sys.stdout.write(render_table(data, error) + "\n")
        sys.stdout.flush()
        return

    # ensure_ascii=False keeps unicode/slashes intact, matching PHP's
    # JSON_UNESCAPED_SLASHES. Compact separators mirror PHP's fwrite output.
    text = json.dumps(payload, ensure_ascii=False, indent=2) if pretty else \
        json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    sys.stdout.write(text + "\n")
    sys.stdout.flush()


_MAX_CELL = 70


def render_table(data: list[Any], error: str | None = None) -> str:
    """Render the envelope's ``data`` list as a plain text table."""
    if error:
        return f"error: {error}"
    if not data:
        return "(no results)"

    if all(isinstance(row, dict) for row in data):
        columns: list[str] = []
        for row in data:
            for key in row:
                if key not in columns:
                    columns.append(key)
        rows = [[_cell(row.get(col, "")) for col in columns] for row in data]
        return _grid(columns, rows)

    return _grid(["value"], [[_cell(item)] for item in data])


def _cell(value: Any) -> str:
    if isinstance(value, str):
        text = value
    elif isinstance(value, (dict, list)):
        text = json.dumps(value, ensure_ascii=False)
    else:
        text = str(value)
    text = text.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    if len(text) > _MAX_CELL:
        text = text[: _MAX_CELL - 3] + "..."
    return text


def _grid(columns: list[str], rows: list[list[str]]) -> str:
    widths = [len(col) for col in columns]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))

    def line(cells: list[str]) -> str:
        return "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(cells))

    out = [line(columns), "  ".join("-" * w for w in widths)]
    out.extend(line(row) for row in rows)
    return "\n".join(out)


def debug_print(message: str) -> None:
    """Write a diagnostic line to stderr (keeps stdout pure JSON)."""
    sys.stderr.write(str(message) + "\n")
    sys.stderr.flush()


def debug_logger(enabled: bool) -> Callable[[str], None]:
    """Return a logging closure that only emits when ``enabled`` is true.

    Mirrors the ``if ($debug) $this->info(...)`` pattern littered through the
    PHP commands.
    """

    def _log(message: str) -> None:
        if enabled:
            debug_print(message)

    return _log


def read_envelope(path: str) -> dict[str, Any]:
    """Read and JSON-decode an envelope file, tolerating missing/empty files."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = fh.read()
    except OSError:
        return {}
    raw = raw.strip()
    if not raw:
        return {}
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return decoded if isinstance(decoded, dict) else {}


def dedupe(items: Iterable[str]) -> list[str]:
    """Order-preserving de-duplication of a string iterable."""
    seen: dict[str, bool] = {}
    for item in items:
        if item not in seen:
            seen[item] = True
    return list(seen.keys())
