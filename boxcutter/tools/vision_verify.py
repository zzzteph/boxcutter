"""vision-verify - did my XSS payload actually EXECUTE, or is it only reflected in the HTML?

Static reflection ("my string appears in the response") is NOT proof of XSS - the browser may encode it, or it may
land in a context that never runs. vision-verify loads the URL in a REAL headless chromium and reports whether
JavaScript actually ran: it installs a hook (before any page script) that captures alert/confirm/prompt calls,
console output, and a `window.__bcvvfire()` canary, then reads back what fired. A dialog/console/canary event only
happens if your payload EXECUTED - so it turns "maybe reflected" into a yes/no, and screenshots the proof.

Put your payload in the URL so that, if it runs, it produces one of those signals, e.g.:
  https://host/search?q=<svg onload=window.__bcvvfire(1)>
  https://host/p?name=<script>alert('BCVV')</script>          (alert is auto-captured, never hangs)
  https://host/#<img src=x onerror=console.log('BCVV')>       (DOM sink)
Pass --marker BCVV to also distinguish EXECUTED from merely-reflected-in-raw-HTML. Needs system chromium.
"""
from __future__ import annotations

import base64
import json
import time

from ..core import cdp, http
from ..core.args import add_common_args, add_header_arg
from ..core.envelope import debug_logger, output_result
from ..core.validators import is_valid_url

NAME = "vision-verify"
KIND = "findings"
HELP = ("Load a URL in headless chromium and report whether JS actually EXECUTED (alert/console/canary captured) vs "
        "merely reflected - confirms reflected/DOM XSS and screenshots the proof.")

# runs on every new document BEFORE the page's own scripts: neutralises blocking dialogs (so alert() never hangs)
# while RECORDING that they fired, plus console and an explicit canary. Everything lands in window.__bcvv.
_HOOK = r"""(function(){
  try{ window.__bcvv = []; }catch(e){ return; }
  function rec(k,v){ try{ window.__bcvv.push(k+': '+String(v===undefined?'(fired)':v).slice(0,140)); }catch(e){} }
  ['alert','confirm','prompt'].forEach(function(f){
    try{ window[f]=function(x){ rec('dialog.'+f, x); return f==='confirm'?true:(f==='prompt'?'':undefined); }; }catch(e){}
  });
  try{ var _l=console.log; console.log=function(){ rec('console.log',[].join.call(arguments,' ')); return _l.apply(console,arguments); }; }catch(e){}
  try{ var _e=console.error; console.error=function(){ rec('console.error',[].join.call(arguments,' ')); return _e.apply(console,arguments); }; }catch(e){}
  try{ window.__bcvvfire=function(x){ rec('canary', x); }; }catch(e){}
})();"""


def add_arguments(parser) -> None:
    parser.add_argument("target", help="URL carrying your payload (e.g. https://x/s?q=<svg onload=window.__bcvvfire(1)>)")
    parser.add_argument("--marker", default=None,
                        help="a unique string in your payload; lets the tool tell EXECUTED from merely-reflected")
    parser.add_argument("--wait", type=int, default=2500, help="ms to wait for JS after load (default 2500)")
    parser.add_argument("--save", default=None, help="write the proof screenshot PNG to this path")
    add_header_arg(parser)
    add_common_args(parser)


def _hdrs(args):
    h = {}
    for x in (getattr(args, "header", None) or []):
        if ":" in x:
            k, v = x.split(":", 1)
            h[k.strip()] = v.strip()
    return h


def run(args) -> int:
    dbg = debug_logger(args.debug)
    target = (args.target or "").strip()
    # accept http(s) targets and also data: URLs (verify an XSS payload PoC in isolation)
    if not (target.startswith("data:") or is_valid_url(target)):
        output_result([], args.output, "Invalid URL (expected http(s):// or data:).")
        return 1
    hdrs = _hdrs(args)

    events, shot = [], b""
    try:
        with cdp.Chrome(headers=hdrs, timeout=45, debug=dbg) as page:
            page._cmd("Page.addScriptToEvaluateOnNewDocument", {"source": _HOOK})   # hook BEFORE page scripts run
            page.navigate(target, wait="networkidle")
            page.wait(max(200, min(args.wait, 8000)))
            raw = page.eval("JSON.stringify(window.__bcvv||[])")
            try:
                events = json.loads(raw) if raw else []
            except Exception:  # noqa: BLE001
                events = []
            try:
                shot = page.screenshot()
            except Exception:  # noqa: BLE001
                shot = b""
    except Exception as exc:  # noqa: BLE001
        output_result([], args.output, f"browser error: {exc}")
        return 1

    # reflection check (raw HTML, no JS) to separate EXECUTED from merely-reflected
    reflected = None
    if args.marker:
        try:
            r = http.session(extra_headers=hdrs)
            resp = http.send("GET", target, sess=r, timeout=15, allow_redirects=True)
            reflected = args.marker in (resp.get("body") or "")
        except Exception:  # noqa: BLE001
            reflected = None

    # a page's OWN JS console-logs constantly, so raw console noise is NOT proof. Count only signals a benign app
    # almost never emits: a JS DIALOG, the explicit `__bcvvfire` canary, or a console line carrying YOUR marker.
    fired = [e for e in events if e.startswith(("dialog.", "canary")) or (args.marker and args.marker in e)]
    executed = len(fired) > 0
    if executed:
        sev, verdict = "high", "XSS CONFIRMED - your payload executed"
    elif reflected:
        sev, verdict = "medium", "payload REFLECTED but did NOT execute (wrong context / encoded) - try another payload"
    else:
        sev, verdict = "info", "no execution signal (payload did not run; check reflection/context)"

    info = verdict + (f"; fired: {', '.join(fired[:6])}" if fired else "")
    finding_events = fired or events[:6]
    if reflected is not None:
        info += f"; raw-HTML reflected={reflected}"
    finding = {"severity": sev, "title": verdict, "url": target, "info": info, "events": finding_events}
    if shot:
        finding["screenshot"] = base64.b64encode(shot).decode()      # multimodal agents SEE this; humans use --save
        if args.save:
            try:
                open(args.save, "wb").write(shot)
                finding["screenshot_path"] = args.save
                dbg(f"screenshot -> {args.save}")
            except OSError as e:
                dbg(f"could not save screenshot: {e}")

    dbg(f"vision-verify: executed={executed} reflected={reflected} events={len(events)}")
    output_result([finding], args.output)
    return 0
