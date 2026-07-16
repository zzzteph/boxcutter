"""JSON envelope output - the Python port of the ``JsonOutput`` PHP trait.

Every tool returns the same shape::

    {"success": <bool>, "data": <list>, "error": <str|null>}

``success`` is ``True`` exactly when ``error`` is ``None``. The envelope is
written to ``--output`` when given, otherwise to stdout. Diagnostic/debug
chatter never touches stdout (it goes to stderr via :func:`debug_logger`) so
stdout always stays parseable JSON.
"""

from __future__ import annotations

import base64
import json
import os
import re
import sys
from typing import Any, Callable, Iterable

# When True, stdout output is rendered as a text table instead of JSON. Set once
# by the CLI from the --table flag. It only affects stdout: writes to a file
# (--output, and the temp files tools pass to each other) always stay JSON.
_TABLE_MODE = False

# When True, a file sink (--output) is written as the machine-readable JSON
# envelope rather than a table. The workflow engine sets this around every inner
# tool/sub-workflow run so steps hand JSON to each other; a user's --output (the
# outermost call) leaves it False and gets a readable table.
_FORCE_JSON_FILE = False

# Optional --jsonl path: the data list is also written here as JSON Lines (one
# record per line). Only the outermost, user-facing result writes it.
_JSONL_FILE: str | None = None

# The kind of payload the current tool/workflow emits: one of "findings", "urls",
# "items". Set by the CLI/runner from the tool's KIND before it runs, so every
# envelope is self-describing and consumers know the data shape up front.
_OUTPUT_KIND = "items"
KINDS = ("findings", "urls", "items")


def set_table_mode(enabled: bool) -> None:
    global _TABLE_MODE
    _TABLE_MODE = enabled


def set_force_json_file(enabled: bool) -> bool:
    """Toggle machine-JSON file output; returns the previous value (for restore)."""
    global _FORCE_JSON_FILE
    prev = _FORCE_JSON_FILE
    _FORCE_JSON_FILE = enabled
    return prev


def set_jsonl_file(path: str | None) -> None:
    global _JSONL_FILE
    _JSONL_FILE = path or None


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

    # ensure_ascii=False keeps unicode/slashes intact, matching PHP's
    # JSON_UNESCAPED_SLASHES; compact separators mirror its fwrite output.
    def _json(obj: Any) -> str:
        return json.dumps(obj, ensure_ascii=False, indent=2) if pretty else \
            json.dumps(obj, ensure_ascii=False, separators=(",", ":"))

    # Internal capture for the workflow engine: a JSON envelope to the file, always.
    # Steps read each other's output back as JSON, so this must never be a table.
    if _FORCE_JSON_FILE and output_file is not None:
        with open(output_file, "w", encoding="utf-8") as fh:
            fh.write(_json(payload))
        return

    # --jsonl: also write the data as JSON Lines (one compact record per line). A
    # machine sink alongside the primary output; skipped on error / internal captures.
    if _JSONL_FILE and error is None:
        with open(_JSONL_FILE, "w", encoding="utf-8") as fh:
            for item in data:
                fh.write(json.dumps(item, ensure_ascii=False, separators=(",", ":")) + "\n")

    # --output FILE: a readable table, always (machine output goes to --jsonl/stdout).
    if output_file is not None:
        with open(output_file, "w", encoding="utf-8") as fh:
            fh.write(render_table(data, error) + "\n")
        return

    # No file sink: stdout - table with --table, else the JSON envelope.
    if _TABLE_MODE:
        sys.stdout.write(render_table(data, error) + "\n")
    else:
        sys.stdout.write(_json(payload) + "\n")
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


def print_live_findings(findings: list[Any]) -> None:
    """Stream findings to stderr as a workflow step produces them - the
    ``--show-findings`` live view.

    Honours the active ``--severity`` filter so what scrolls by matches the final
    report, and truncates long titles/URLs the same way the table does. stdout is
    never touched: it still carries only the final envelope (or ``--table``).
    """
    for f in _filter_by_severity(findings):
        if not isinstance(f, dict):
            continue
        sev = str(f.get("severity", "info"))
        source = str(f.get("source", "")).strip()
        prefix = f"{source}: " if source else ""
        debug_print(f"    [{sev}] {prefix}{_cell(f.get('title', ''))}".rstrip())
        url = _cell(f.get("url", ""))
        if url:
            debug_print(f"        {url}")


def debug_print(message: str) -> None:
    """Write a diagnostic line to stderr (keeps stdout pure JSON)."""
    sys.stderr.write(str(message) + "\n")
    sys.stderr.flush()


def write_report(path: str | None, text: str) -> None:
    """Write a human-readable markdown report to ``path`` - the shared ``--report`` flag every ai agent takes.
    No-op when ``path`` is falsy; best-effort (a write failure goes to stderr, never raised)."""
    if not path:
        return
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text.rstrip("\n") + "\n")
        debug_print(f"report written to {path}")
    except OSError as exc:
        sys.stderr.write(f"could not write report to {path}: {exc}\n")


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


def harvest_images(out: str, max_images: int = 8, max_bytes: int = 6_000_000) -> tuple[str, list]:
    """Pull screenshots a tool emitted (as short ``image_path`` values) OUT of its JSON envelope text and
    return ``(clean_text, images)`` - ``images`` being base64 PNG blocks the provider forwards as REAL vision.

    ORDER IS THE CONTRACT. An agent is told it gets exactly ONE image per ``screen`` action, in order, so the
    images we return MUST match that, and nothing extra - otherwise the model maps a screenshot to the wrong
    action and judges (e.g.) "the login form opened" from a STALE picture. Therefore:

    * every explicit ``screen`` capture - an ``image_path`` reached THROUGH a ``results`` list - is forwarded in
      document order, and its text placeholder is NUMBERED (#1, #2, ...) so the text and the images line up;
    * a record's OWN top-level ``image_path`` (the tool's trailing whole-call state screenshot) is NOT shown
      when explicit screens exist: it is redundant with the last ``screen`` and, delivered out of order, is
      exactly what makes an agent read the wrong frame. It is forwarded only as a FALLBACK when the call
      produced no ``screen`` at all, so the model is never left blind.

    Consumed temp PNGs are unlinked (tools run in-process, the files are local). Best-effort: any parse/read
    failure yields no images and the untouched text.
    """
    try:
        env = json.loads(out)
    except Exception:  # noqa: BLE001
        return out, []
    if not isinstance(env, dict) or not isinstance(env.get("data"), list):
        return out, []

    def _read(path: str) -> bytes | None:
        try:
            with open(path, "rb") as fh:
                raw = fh.read()
            os.unlink(path)                          # the capture is ephemeral - consume it
        except OSError:
            return None
        return raw if raw and len(raw) <= max_bytes else None

    def _block(raw: bytes) -> dict:
        return {"media_type": "image/png", "data": base64.b64encode(raw).decode("ascii")}

    images: list = []
    finals: list = []          # (node, path) trailing per-call state screenshots - fallback only

    def _walk(node: Any, in_results: bool) -> None:
        if isinstance(node, dict):
            path = node.get("image_path")
            if isinstance(path, str) and path and not path.startswith("<"):
                if in_results:                       # an explicit `screen` -> forward it, in order, numbered
                    if len(images) < max_images:
                        raw = _read(path)
                        if raw:
                            images.append(_block(raw))
                            node["image_path"] = f"<screenshot #{len(images)} - the image below, in order>"
                        else:
                            node["image_path"] = "<screenshot unavailable>"
                    else:
                        try:
                            os.unlink(path)
                        except OSError:
                            pass
                        node["image_path"] = "<screenshot omitted - too many in one call; take fewer `screen`s>"
                else:
                    finals.append((node, path))      # trailing state shot - decided after the walk
            for key, val in node.items():
                if key != "image_path":
                    _walk(val, in_results or key == "results")
        elif isinstance(node, list):
            for val in node:
                _walk(val, in_results)

    _walk(env["data"], False)

    if images:                                       # explicit screens shown -> drop the redundant trailing shot
        for node, path in finals:
            try:
                os.unlink(path)
            except OSError:
                pass
            node["image_path"] = "<final-state screenshot saved to trace; take a `screen` to view the live page>"
    else:                                            # no `screen` this call -> show the state shot so it isn't blind
        for node, path in finals:
            if len(images) >= max_images:
                break
            raw = _read(path)
            if raw:
                images.append(_block(raw))
                node["image_path"] = f"<screenshot #{len(images)} - the image below>"
            else:
                node["image_path"] = "<screenshot unavailable>"

    return (json.dumps(env, ensure_ascii=False), images) if images else (out, [])


def dedupe(items: Iterable[str]) -> list[str]:
    """Order-preserving de-duplication of a string iterable."""
    seen: dict[str, bool] = {}
    for item in items:
        if item not in seen:
            seen[item] = True
    return list(seen.keys())
