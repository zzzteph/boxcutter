"""browser-actions - drive a real headless browser through a scripted sequence of actions.

Like a human (or a Gherkin script): click, type, select, press keys, hover, scroll, wait, eval - to reach
multi-step flows, submit forms, and trigger SPA behaviour the auto-crawler can't. Captures the full
request+response of every XHR/fetch along the way (method/url/status + request & response bodies for API
content types) plus the final page state (url, title, cookies, any bearer token). With --session it drives a
PERSISTENT browser that stays logged in and keeps its SPA state across calls, so an agent can explore the app
like a real user. Driven via CDP over the system chromium (core.cdp). Full-image tool: needs chromium +
websocket-client.

Actions (repeatable, ordered) via --action "verb:args":
  goto:URL · click:SEL · dblclick:SEL · fill:SEL=VALUE · type:SEL=VALUE · press:SEL=KEY · press:KEY
  select:SEL=VALUE · check:SEL · uncheck:SEL · hover:SEL · scroll:bottom|top|X,Y · wait:MS · waitfor:SEL · eval:JS
  describe (no args) - snapshot the CURRENT page's visible inputs/buttons/links (tag/type/name/id/placeholder/
  aria-label/text + a ready-to-use css selector for each) into this action's "result". Use it FIRST when a
  form's fields have no clear id/name (obfuscated themes) or the flow is multi-step (e.g. an identifier-first
  login) - read the result, then issue a SEPARATE browser-actions call using the css selectors it gave you;
  they stay valid across a fresh reload of the same URL.
  screenshot (no args) - capture the CURRENT page as a PNG; the agent SEES the rendered page (the real login
  form, an unexpected consent/MFA/error screen) as an image, not just its DOM. Pair with describe when a
  form's structure is unclear: describe gives the exact selectors, screenshot shows what's actually there.
  requests[:api|all|HOST] - proxy-like view of EVERY request the page has made (not just the XHR/fetch this
  call triggered): bare/`surface` = host->count map of the whole backend+third-party surface; `api` = the
  xhr/fetch calls; `all` = include static assets; a HOST substring = list that host's requests.
SEL shorthands: id=foo -> #foo · name=foo -> [name="foo"] · text=Foo -> text match · css=... or raw CSS.
"""

from __future__ import annotations

from urllib.parse import urlparse

from ..core import fsutil
from ..core.args import add_common_args, add_header_arg
from ..core.cdp import CDPError, Chrome, get_session
from ..core.envelope import debug_logger, output_result
from ..core.validators import is_valid_url

NAME = "browser-actions"
KIND = "items"
HELP = "Drive a headless browser through scripted actions (click/type/select/...) and capture the result."

_TOKEN_JS = ("() => { try { for (const k of Object.keys(localStorage)) { const v = localStorage.getItem(k); "
             "if (v && /eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+/.test(v)) return v; } } catch (e) {} return ''; }")


def add_arguments(parser) -> None:
    parser.add_argument("target", help="Start URL")
    parser.add_argument("--action", action="append", default=[], metavar="VERB:ARGS",
                        help="A browser action; repeatable, run in order (e.g. fill:#user=admin, click:text=Log in)")
    parser.add_argument("--actions-file", dest="actions_file", default=None, metavar="FILE",
                        help="Read actions from a file (one 'verb:args' per line; # comments and blank lines ignored)")
    parser.add_argument("--session", dest="session", default=None, metavar="ID",
                        help="Attach to a PERSISTENT browser session by id (stays logged in / keeps SPA state "
                             "across calls) instead of a fresh browser; on attach the start URL is NOT "
                             "re-navigated - use a goto action to move. Omit for the default one-shot browser.")
    add_header_arg(parser)
    parser.add_argument("--timeout", type=int, default=45, help="Per-step timeout (seconds)")
    add_common_args(parser)


def _sel(s):
    s = s.strip()
    if s.startswith("id="):
        return "#" + s[3:]
    if s.startswith("name="):
        return f'[name="{s[5:]}"]'
    if s.startswith("text="):
        return "text=" + s[5:]
    if s.startswith("css="):
        return s[4:]
    return s


def _do(page, action):
    """Perform one action; returns a result payload for actions that produce data (currently just
    'describe'), or None for actions that only cause a side effect."""
    verb, _, rest = action.partition(":")
    verb = verb.strip().lower()
    if verb == "goto":
        page.navigate(rest.strip(), wait="networkidle")
    elif verb == "describe":
        return page.describe_form()
    elif verb in ("requests", "req"):
        return page.request_summary(rest.strip())        # proxy-like view of every request the page made
    elif verb in ("captcha", "wander", "humanize"):
        page.wander(float(rest) if rest.strip() else 3.0)   # idle human mouse drift to warm up a behaviour check
    elif verb == "screenshot":
        png = page.screenshot()
        if not png:
            return {"type": "screenshot", "image_path": "", "error": "empty screenshot"}
        # write the PNG to a temp file and hand back only the PATH (not base64): the executor loop reads it
        # back in-process and forwards it to the model as a real vision block, so a huge base64 blob never
        # bloats (or gets truncated in) the JSON envelope.
        path = fsutil.temp_file("bc_shot_")
        with open(path, "wb") as fh:
            fh.write(png)
        return {"type": "screenshot", "image_path": path, "bytes": len(png)}
    elif verb in ("fill", "type"):
        sel, _, val = rest.partition("=")
        page.fill(_sel(sel), val)
    elif verb == "select":
        sel, _, val = rest.partition("=")
        page.select(_sel(sel), val)
    elif verb == "press":
        if "=" in rest:
            sel, _, key = rest.partition("=")
            page.press(key, _sel(sel))
        else:
            page.press(rest.strip())
    elif verb == "click":
        page.click(_sel(rest))
    elif verb == "dblclick":
        page.dblclick(_sel(rest))
    elif verb == "hover":
        page.hover(_sel(rest))
    elif verb == "check":
        page.set_checked(_sel(rest), True)
    elif verb == "uncheck":
        page.set_checked(_sel(rest), False)
    elif verb == "waitfor":
        page.waitfor(_sel(rest))
    elif verb == "wait":
        page.wait(int(rest.strip() or "1000"))
    elif verb == "scroll":
        page.scroll(rest)
    elif verb == "eval":
        page.eval(rest)
    else:
        raise ValueError(f"unknown action '{verb}'")


def _drive(page, target, actions, fresh):
    """Run the action sequence on `page` and return (state, flows). `fresh` navigates to the start URL first
    (a brand-new browser or a just-opened session); an ATTACHED persistent session continues from wherever it
    already is (move with a goto action). Flows captured are only those THIS call produced."""
    marker = page.flow_marker()
    if fresh:
        page.navigate(target, wait="networkidle")
    results = []
    for action in actions:
        try:
            payload = _do(page, action)
            page.wait(200)
            rec = {"action": action, "ok": True}
            if payload is not None:
                rec["result"] = payload
            results.append(rec)
        except Exception as exc:  # noqa: BLE001 - record the failed step and keep going
            results.append({"action": action, "ok": False, "error": str(exc)[:120]})
    try:
        token = page.eval_fn(_TOKEN_JS) or ""
    except CDPError:
        token = ""
    state = {"type": "state", "url": page.current_url(), "title": page.title(), "cookie": page.cookies(),
             "token": token, "actions_ok": sum(1 for r in results if r["ok"]),
             "actions_failed": sum(1 for r in results if not r["ok"]), "results": results}
    return state, page.flows(since=marker)


def run(args) -> int:
    target = args.target.strip()
    dbg = debug_logger(args.debug)
    if not is_valid_url(target):
        output_result([], args.output, "Invalid URL.")
        return 1

    actions = list(args.action or [])
    if args.actions_file:
        try:
            with open(args.actions_file, "r", encoding="utf-8", errors="replace") as fh:
                actions += [ln.strip() for ln in fh if ln.strip() and not ln.lstrip().startswith("#")]
        except OSError as exc:
            output_result([], args.output, f"cannot read actions file: {exc}")
            return 1

    headers = {}
    for raw in args.header or []:
        if ":" in raw:
            k, v = raw.split(":", 1)
            headers[k.strip()] = v.strip()

    sid = (getattr(args, "session", None) or "").strip()
    try:
        if sid:
            # persistent session: attach to (or open) the live browser and LEAVE IT OPEN for the next call
            page, fresh = get_session(sid, headers=headers, timeout=args.timeout, debug=dbg)
            state, flows = _drive(page, target, actions, fresh)
        else:
            with Chrome(headers=headers, timeout=args.timeout, debug=dbg) as page:
                state, flows = _drive(page, target, actions, True)
    except CDPError as exc:
        output_result([], args.output, f"browser-actions unavailable: {exc}")
        return 1
    except Exception as exc:  # noqa: BLE001
        output_result([], args.output, f"browser-actions failed: {exc}")
        return 1

    data = [state] + flows
    dbg(f"browser-actions: {state['actions_ok']} ok / {state['actions_failed']} failed, {len(flows)} api flow(s)")
    output_result(data, args.output)
    return 0
