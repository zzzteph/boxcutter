"""browser-actions - drive a real headless browser through a scripted sequence of actions.

Like a human (or a Gherkin script): click, type, select, press keys, hover, scroll, wait, eval - to reach
multi-step flows, submit forms, and trigger SPA behaviour the auto-crawler can't. Captures every XHR/fetch
along the way plus the final page state (url, title, cookies, any bearer token). Capability-gated: Playwright.

Actions (repeatable, ordered) via --action "verb:args":
  goto:URL · click:SEL · dblclick:SEL · fill:SEL=VALUE · type:SEL=VALUE · press:SEL=KEY · press:KEY
  select:SEL=VALUE · check:SEL · uncheck:SEL · hover:SEL · scroll:bottom|top|X,Y · wait:MS · waitfor:SEL · eval:JS
SEL shorthands: id=foo -> #foo · name=foo -> [name="foo"] · text=Foo -> text engine · css=... or raw CSS.
"""

from __future__ import annotations

import os
import shutil
from urllib.parse import urlparse

from ..core.args import add_common_args
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
    parser.add_argument("--header", action="append", default=[], metavar="NAME: VALUE",
                        help="Request header, e.g. an auth token (repeatable)")
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
    verb, _, rest = action.partition(":")
    verb = verb.strip().lower()
    if verb == "goto":
        page.goto(rest.strip(), wait_until="networkidle")
    elif verb in ("fill", "type"):
        sel, _, val = rest.partition("=")
        page.fill(_sel(sel), val)
    elif verb == "select":
        sel, _, val = rest.partition("=")
        page.select_option(_sel(sel), val)
    elif verb == "press":
        if "=" in rest:
            sel, _, key = rest.partition("=")
            page.press(_sel(sel), key)
        else:
            page.keyboard.press(rest.strip())
    elif verb == "click":
        page.click(_sel(rest))
    elif verb == "dblclick":
        page.dblclick(_sel(rest))
    elif verb == "hover":
        page.hover(_sel(rest))
    elif verb == "check":
        page.check(_sel(rest))
    elif verb == "uncheck":
        page.uncheck(_sel(rest))
    elif verb == "waitfor":
        page.wait_for_selector(_sel(rest))
    elif verb == "wait":
        page.wait_for_timeout(int(rest.strip() or "1000"))
    elif verb == "scroll":
        r = rest.strip().lower()
        if r == "bottom":
            page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
        elif r == "top":
            page.evaluate("window.scrollTo(0, 0)")
        elif "," in r:
            x, y = r.split(",", 1)
            page.evaluate(f"window.scrollTo({int(x)}, {int(y)})")
    elif verb == "eval":
        page.evaluate(rest)
    else:
        raise ValueError(f"unknown action '{verb}'")


def run(args) -> int:
    target = args.target.strip()
    dbg = debug_logger(args.debug)
    if not is_valid_url(target):
        output_result([], args.output, "Invalid URL.")
        return 1
    try:
        from playwright.sync_api import sync_playwright
    except Exception:  # noqa: BLE001
        output_result([], args.output, "playwright is not installed (browser-actions is a full-image tool)")
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
    base_host = urlparse(target).hostname or ""
    captured = {}
    results = []
    exe = os.environ.get("CHROMIUM_PATH") or shutil.which("chromium-browser") or shutil.which("chromium")

    def on_request(req):
        if req.resource_type in ("xhr", "fetch") and (urlparse(req.url).hostname or "") == base_host:
            captured[(req.method, req.url.split("#")[0])] = True

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True, **({"executable_path": exe} if exe else {}))
            ctx = browser.new_context(extra_http_headers=headers, ignore_https_errors=True)
            page = ctx.new_page()
            page.on("request", on_request)
            page.goto(target, wait_until="networkidle", timeout=args.timeout * 1000)
            for action in actions:
                try:
                    _do(page, action)
                    page.wait_for_timeout(200)
                    results.append({"action": action, "ok": True})
                except Exception as exc:  # noqa: BLE001 - record the failed step and keep going
                    results.append({"action": action, "ok": False, "error": str(exc)[:120]})
            title, final_url = page.title(), page.url
            cookie = "; ".join(f"{c['name']}={c['value']}" for c in ctx.cookies())
            try:
                token = page.evaluate(_TOKEN_JS) or ""
            except Exception:  # noqa: BLE001
                token = ""
            browser.close()
    except Exception as exc:  # noqa: BLE001
        output_result([], args.output, f"browser-actions failed: {exc}")
        return 1

    data = [{"type": "state", "url": final_url, "title": title, "cookie": cookie, "token": token,
             "actions_ok": sum(1 for r in results if r["ok"]),
             "actions_failed": sum(1 for r in results if not r["ok"]), "results": results}]
    data += [{"url": u, "method": m, "type": "xhr"} for (m, u) in sorted(captured)]
    dbg(f"browser-actions: {data[0]['actions_ok']} ok / {data[0]['actions_failed']} failed, {len(captured)} api calls")
    output_result(data, args.output)
    return 0
