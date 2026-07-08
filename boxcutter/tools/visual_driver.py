"""visual-driver - drive a headless browser PURELY BY SCREEN COORDINATES, like a human at the keyboard.

A dumb, fully manual tool: you give it a start URL and a chain of coordinate ACTIONS from the console; it
executes each with REAL, trusted, human-like mouse motion (a curved, eased path to the target, never a
teleport) and per-key typing, and saves a screenshot whenever you ask. No credentials, no login concept - to
type a value (a username, a password) you just `put:` the literal text as an action. Runs at a fixed viewport
with deviceScaleFactor=1, so 1 screenshot pixel == the exact x,y you click. The grid overlaid on each
screenshot is labeled every 100px so you can read an element's coordinates straight off it. Captures the
request/response flows the actions trigger. Driven via CDP over the system chromium (core.cdp).

Actions (ordered) via --action "verb:args":
  goto:URL · click:X,Y · dblclick:X,Y · move:X,Y · put:TEXT (alias type; reports `landed` - whether the value
  actually entered the focused field) · clear (empty focused field) ·
  drag:X1,Y1->X2,Y2 · key:Enter|Tab|... · scroll:down|up|PIXELS · wait:SECONDS (bare `wait` = 5s) ·
  find:TEXT (locate a control/field by text/name) · click_text:TEXT / tap:TEXT (find it by text, then click) ·
  fill_text:LABEL=TEXT (find a field by its name/placeholder, click it, and type - e.g. fill_text:email=...) ·
  probe:X,Y (report what's at X,Y without clicking) · requests[:api|all|HOST] (proxy view of all requests) ·
  captcha[:SECONDS] (idle human mouse drift to warm up a behaviour check) · screen (save a screenshot now)
A click/dblclick/move/probe reports WHAT element it hit (e.g. `button "Accept all"`) in its result, so you can
verify aim instead of guessing. Coordinates take a comma OR a colon: click:10,20 and click:10:20 are the same.
They are viewport pixels as labeled on the grid and change after a scroll/navigation, so drop a `screen` and
re-read it before the next aim.
"""

from __future__ import annotations

import os
import re

from ..core import fsutil
from ..core.args import add_common_args, add_header_arg
from ..core.cdp import CDPError, Chrome, get_session
from ..core.envelope import debug_logger, output_result
from ..core.validators import is_valid_url

NAME = "visual-driver"
KIND = "items"
HELP = ("Drive a browser by SCREEN COORDINATES with human-like mouse motion + typing; returns a "
        "coordinate-grid screenshot each call.")

VIEWPORT = (1280, 800)
_TOKEN_JS = ("() => { try { for (const k of Object.keys(localStorage)) { const v = localStorage.getItem(k); "
             "if (v && /eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+/.test(v)) return v; } } catch (e) {} return ''; }")


def add_arguments(parser) -> None:
    parser.add_argument("target", help="Start URL")
    parser.add_argument("--action", action="append", default=[], metavar="VERB:ARGS",
                        help="A coordinate action; repeatable, run in order: click:X,Y | dblclick:X,Y | "
                             "move:X,Y | put:TEXT (type) | clear | drag:X1,Y1->X2,Y2 | key:Enter | "
                             "scroll:down|up|PIXELS | wait:SECONDS (bare wait = 5s) | find:TEXT | "
                             "click_text:TEXT (find control by text, click it) | fill_text:LABEL=TEXT (find a "
                             "field by name, type into it) | probe:X,Y | requests[:api|all|HOST] | captcha | "
                             "screen | goto:URL. click/probe/find report what they hit. Coords take comma or colon")
    parser.add_argument("--session", dest="session", default=None, metavar="ID",
                        help="Persistent session id (stays logged in / keeps page state across calls). On "
                             "attach the start URL is NOT re-navigated - use goto to move.")
    parser.add_argument("--grid", dest="grid", type=int, default=50, metavar="PX",
                        help="Coordinate-grid spacing in px on the saved screenshots (0 = no grid)")
    parser.add_argument("--trace", dest="trace", default="trace", metavar="DIR",
                        help="Directory the screenshots are written to (numbered NNN_verb.png) - a `screen` "
                             "action, plus the final state, land here. Default ./trace (a trace/ folder under "
                             "the current directory, not the repo root); in Docker pass --trace /trace and "
                             "mount -v \"$PWD/trace:/trace\". Set '' to disable saving")
    parser.add_argument("--trace-each", dest="trace_each", action="store_true",
                        help="Also save a screenshot after EVERY action (not only on a `screen` action)")
    parser.add_argument("--dump-storage", dest="dump_storage", action="store_true",
                        help="Include the page's full localStorage + sessionStorage in the final state (for "
                             "capturing an authenticated session's client-side auth state for reuse)")
    add_header_arg(parser)
    parser.add_argument("--timeout", type=int, default=45, help="Per-step timeout (seconds)")
    add_common_args(parser)


def _xy(rest: str) -> tuple:
    a, _, b = rest.replace(":", ",").partition(",")    # accept click:10,20 OR click:10:20
    return int(float(a.strip())), int(float(b.strip()))


def _describe(el) -> str:
    """One-line label for an element descriptor from Chrome.element_at - e.g. `button "Accept all"`."""
    if not isinstance(el, dict):
        return "nothing"
    parts = [el.get("tag", "?")]
    if el.get("type") and el.get("type") != el.get("tag"):   # skip redundant e.g. button[button]
        parts.append(f"[{el['type']}]")
    if el.get("id"):
        parts.append(f"#{el['id']}")
    if el.get("role"):
        parts.append(f"role={el['role']}")
    if el.get("text"):
        parts.append(f'"{el["text"]}"')
    return " ".join(parts)


def _do(page, action: str):
    """Perform one action. Returns a small payload for actions that report something (what a click hit, what a
    probe found), else None."""
    verb, _, rest = action.partition(":")
    verb, rest = verb.strip().lower(), rest.strip()
    if verb == "goto":
        page.navigate(rest, wait="networkidle")
    elif verb in ("click", "dblclick"):
        x, y = _xy(rest)
        hit = _describe(page.element_at(x, y))          # what's there BEFORE the click (it may navigate away)
        page.human_click(x, y, clicks=2 if verb == "dblclick" else 1)
        return {"hit": hit}
    elif verb == "move":
        x, y = _xy(rest)
        page.human_move(x, y)
        return {"over": _describe(page.element_at(x, y))}
    elif verb == "probe":
        x, y = _xy(rest)
        return {"at": _describe(page.element_at(x, y))}  # report what's at x,y WITHOUT clicking
    elif verb == "find":
        el = page.find_text(rest)                        # locate a control by its visible text, report coords
        return {"found": el} if el else {"found": None, "note": f"no visible control matching '{rest}'"}
    elif verb in ("click_text", "tap"):
        el = page.find_text(rest)                        # find a control by text, then human-click its centre
        if not el:
            return {"clicked": None, "note": f"no visible control matching '{rest}' - read coords off the grid instead"}
        page.human_click(el["x"], el["y"])
        return {"clicked": {"at": [el["x"], el["y"]], "text": el.get("text"), "tag": el.get("tag")}}
    elif verb == "fill_text":                            # find a FIELD by name/placeholder, click it, type - no coord guessing
        label, _, val = rest.partition("=")
        el = page.find_text(label.strip())
        if not el:
            return {"filled": None, "note": f"no field matching '{label.strip()}' - read coords off the grid instead"}
        page.human_click(el["x"], el["y"])
        page.human_type(val)
        return {"filled": {"label": label.strip(), "at": [el["x"], el["y"]], "tag": el.get("tag"), "type": el.get("type")}}
    elif verb in ("requests", "req"):
        return page.request_summary(rest)                # proxy-like view of every request the page made
    elif verb in ("captcha", "wander", "humanize"):
        page.wander(float(rest) if rest.strip() else 3.0)   # idle human mouse drift to warm up a behaviour check
    elif verb in ("type", "put"):
        page.human_type(rest)
        val = page.focused_value()                       # VERIFY it actually landed in the focused field
        landed = bool(rest) and bool(val) and rest in val
        out = {"typed_chars": len(rest), "field_chars": len(val), "landed": landed}
        if not landed:                                   # e.g. the click hit a label, so nothing was focused
            out["note"] = ("the value did NOT enter a field - the focused element held no text; your click "
                           "missed the input (a label click does not focus it). Click the input BOX, then put again")
        return out                                       # NB: never the raw value - only length + landed
    elif verb == "clear":
        page.clear_field()
    elif verb == "drag":
        src, _, dst = rest.partition("->")
        if not dst.strip():
            raise ValueError("drag needs X1,Y1->X2,Y2")
        x1, y1 = _xy(src)
        x2, y2 = _xy(dst)
        page.human_drag(x1, y1, x2, y2)
    elif verb == "key":
        page.press(rest)
    elif verb == "scroll":
        if rest in ("down", ""):
            page.wheel(400)
        elif rest == "up":
            page.wheel(-400)
        else:
            page.wheel(int(float(rest)))
    elif verb == "wait":
        secs = float(rest) if rest.strip() else 5.0     # seconds; bare `wait` = 5s, wait:2 = 2s, wait:0.5 = 500ms
        page.wait(int(max(0.0, secs) * 1000))
    else:
        raise ValueError(f"unknown action '{verb}'")


def _shoot(page, grid: int) -> bytes:
    """PNG bytes of the current page with the coordinate grid drawn on, then removed."""
    drew = False
    if grid and grid > 0:
        try:
            page.add_grid(minor=grid, major=max(grid * 2, 100))
            drew = True
        except CDPError:
            drew = False
    png = page.screenshot()
    if drew:
        page.remove_grid()
    return png


def _grid_shot(page, grid: int) -> str:
    """The grid screenshot written to a temp PNG; returns its path ('' on failure). The path (not base64) rides
    in the envelope - the executor loop reads it and forwards it to the model as a real vision block."""
    png = _shoot(page, grid)
    if not png:
        return ""
    path = fsutil.temp_file("bc_visor_")
    with open(path, "wb") as fh:
        fh.write(png)
    return path


def _save_png(trace_dir: str, label: str, png: bytes) -> str:
    """Write PNG bytes as the next numbered screenshot in trace_dir (so a human can flip through the run).
    Numbered by how many PNGs already sit there, so calls chain into one ordered trace. '' on failure."""
    try:
        os.makedirs(trace_dir, exist_ok=True)
        idx = len([f for f in os.listdir(trace_dir) if f.endswith(".png")]) + 1
        slug = re.sub(r"[^A-Za-z0-9]+", "_", label)[:40].strip("_") or "step"
        path = os.path.join(trace_dir, f"{idx:03d}_{slug}.png")
        with open(path, "wb") as fh:
            fh.write(png)
        return path
    except Exception:  # noqa: BLE001 - a trace is a debugging aid; never let it break the run
        return ""


def _trace_shot(page, trace_dir: str, label: str, grid: int) -> str:
    png = _shoot(page, grid)
    return _save_png(trace_dir, label, png) if png else ""


def _drive(page, target, actions, grid, fresh, trace_dir=None, each=False, dump_storage=False):
    marker = page.flow_marker()
    if fresh:
        page.navigate(target, wait="networkidle")
    trace = []

    def _cap(label):
        if trace_dir:
            trace.append(_trace_shot(page, trace_dir, label, grid))

    if each:
        _cap("start")
    results = []
    for action in actions:
        verb = action.partition(":")[0].strip().lower()
        if verb in ("screen", "screenshot"):        # explicit, on-demand screenshot -> SHOWN to the model
            png = _shoot(page, grid)
            rec = {"action": action, "ok": True}
            if png:
                p = fsutil.temp_file("bc_visor_")    # the model reads this one and sees it as a vision block
                with open(p, "wb") as fh:
                    fh.write(png)
                rec["image_path"] = p
                if trace_dir:
                    trace.append(_save_png(trace_dir, "screen", png))   # also keep a copy for the human trace
            results.append(rec)
            continue
        try:
            payload = _do(page, action)
            page.wait(150)
            rec = {"action": action, "ok": True}
            if payload:
                rec.update(payload)                      # e.g. what a click hit / a probe found
            results.append(rec)
        except Exception as exc:  # noqa: BLE001 - record the failed step and keep going
            results.append({"action": action, "ok": False, "error": str(exc)[:120]})
        if each:
            _cap(verb)
    _cap("final")                                    # always save the end state when a trace dir is set
    try:
        token = page.eval_fn(_TOKEN_JS) or ""
    except CDPError:
        token = ""
    state = {"type": "state", "url": page.current_url(), "title": page.title(), "cookie": page.cookies(),
             "token": token, "viewport": list(VIEWPORT), "cursor": list(page._cursor or ()),
             "actions_ok": sum(1 for r in results if r["ok"]),
             "actions_failed": sum(1 for r in results if not r["ok"]), "results": results}
    if dump_storage:
        state["storage"] = page.storage_dump()           # full localStorage + sessionStorage for session reuse
    shot = _grid_shot(page, grid)
    if shot:
        state["image_path"] = shot
    trace = [t for t in trace if t]
    if trace:
        state["trace"] = trace
    return state, page.flows(since=marker)


def run(args) -> int:
    target = args.target.strip()
    dbg = debug_logger(args.debug)
    if not is_valid_url(target):
        output_result([], args.output, "Invalid URL.")
        return 1

    headers = {}
    for raw in args.header or []:
        if ":" in raw:
            k, v = raw.split(":", 1)
            headers[k.strip()] = v.strip()

    sid = (getattr(args, "session", None) or "").strip()
    trace_dir = getattr(args, "trace", None) or None
    each = bool(getattr(args, "trace_each", False))
    dump_storage = bool(getattr(args, "dump_storage", False))
    try:
        if sid:
            page, fresh = get_session(sid, headers=headers, timeout=args.timeout, debug=dbg, viewport=VIEWPORT)
            state, flows = _drive(page, target, args.action or [], args.grid, fresh, trace_dir, each, dump_storage)
        else:
            with Chrome(headers=headers, timeout=args.timeout, debug=dbg, viewport=VIEWPORT) as page:
                state, flows = _drive(page, target, args.action or [], args.grid, True, trace_dir, each, dump_storage)
    except CDPError as exc:
        output_result([], args.output, f"visual-driver unavailable: {exc}")
        return 1
    except Exception as exc:  # noqa: BLE001
        output_result([], args.output, f"visual-driver failed: {exc}")
        return 1

    dbg(f"visual-driver: {state['actions_ok']} ok / {state['actions_failed']} failed, {len(flows)} api flow(s)")
    output_result([state] + flows, args.output)
    return 0
