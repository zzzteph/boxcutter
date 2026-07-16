"""logio - a STANDALONE agentic login tool. One job: LOG IN to a target with the supplied credentials.

Completely separate from IRVIN - its own small agent loop, its own prompt, and a single tool (visual-driver).
Everything is driven by analysing the gridded screenshot - a tiny action set (move, click, put, probe, wait,
screen). You call it directly instead of running the whole pipeline:

  boxcutter logio https://app.example.com --creds "user@example.com:pass" \
    --provider litellm --model "openai/gpt-5.1" --api-key ... --base-url https://gateway.example.com

The login runs as FIVE GATED STAGES - (1) find the login form, (2) enter the details, (3) click the necessary
fields, (4) bypass the captcha, (5) submit & confirm. Each stage must PASS its own on-screen gate before the
next begins; the run STOPS at the first stage that fails, so a failure tells you exactly where the flow broke.

The password is never shown to the model: it types __USER__/__PASS__ tokens that are substituted with the real
values only at dispatch. It records the screenshots the agent takes (each `screen`, plus every call's final
state) into a per-run trace subdir (logio-<timestamp>/) so you can flip through what happened without drowning
in files - use --trace-each for a shot after every action - and ends with a verdict: authenticated yes/no
(judged by ANALYSING THE SCREEN - the account/personal page), the FLOW of actions that logs in, and a REUSABLE
session written to session.json - the full client-side auth state (cookies + localStorage + sessionStorage +
bearer token) needed to re-enter the app as this logged-in user.
"""

from __future__ import annotations

import io
import json
import os
import re
import sys
import time
from urllib.parse import urlparse

from ..core import agentlog
from ..core.envelope import debug_logger, debug_print, harvest_images, output_result, write_report
from ..irvin import briefing                 # reused (read-only) to parse creds/headers out of --context
from ..irvin.provider import PROVIDERS, add_agent_args   # generic LLM client + shared ai-flag adder
from ..tools import toolschema

NAME = "logio"
KIND = "items"
HELP = "Standalone agentic login: an auth-only agent that logs in with supplied creds (no IRVIN pipeline)."

_TOOLS = ["visual-driver"]      # purely visual: everything is driven by analysing the gridded screenshot
_SESSION = "logio"

_SYSTEM = (
    "You are LOGIO, an AUTHENTICATION agent. GOAL: authenticate the user in the target app with the supplied "
    "credentials, then CAPTURE everything needed for further communication with it - the session cookies, the "
    "localStorage/bearer token, the auth header. Assume a common web app or SPA unless told otherwise.\n"

    "TOOL - visual-driver. Each call returns a SCREENSHOT of the app with a coordinate GRID (x across the top, "
    "y down the left, labelled every 100px). You READ the screenshot, plan the next action, and act by "
    "coordinate - like a human looking at the screen.\n"
    "FRESH EVERY CALL - THIS IS CRUCIAL: each visual-driver call runs in a BRAND-NEW, VIRGIN browser that "
    "starts on the target URL. NOTHING survives between calls - not a cookie banner you dismissed, not a modal "
    "you opened, not a field you typed; every call reloads the clean starting page. So a call is NOT 'the next "
    "step' on a live page - it is a WHOLE run from scratch. To make progress you REPLAY the entire sequence "
    "that works so far and ADD your next action on the end. You are building ONE growing SCRIPT of actions: "
    "each call = the full known-good script + the new step you are testing.\n"
    "CHAIN & SEE: put the WHOLE sequence in ONE call as a chain of --action's run in order, with a `screen` "
    "where you want to look - you receive one screenshot PER `screen`, IN ORDER. The replayed prefix is already "
    "known to work, so you don't need a `screen` after every prefix action; `screen` mainly to verify your NEW "
    "step and the FINAL state (e.g. ...prefix..., click, `wait`, `screen`).\n"

    "DEFINED ACTIONS - these SIX are all you have; use ONLY these, EXACTLY as written; do NOT invent an action, "
    "flag, or selector:\n"
    "  wait:SECONDS (bare `wait`=5s) | screen (take a screenshot) | move:X,Y (move the mouse there) | "
    "click:X,Y (click there) | put:TEXT (type into the FOCUSED field - it REPORTS BACK `landed`: true means the "
    "value entered the field, false means NOTHING was focused so your click missed the input) | probe:X,Y "
    "(report what element is at x,y - use it to CONFIRM a target before you click). Coordinates take a comma OR "
    "colon (click:600,375 == click:600:375).\n"
    "EVERYTHING you do is driven by ANALYSING THE SCREENSHOT: look at the gridded image, identify the element "
    "you need, READ its x,y off the grid, and act by coordinate - exactly like a human looking at the screen. "
    "NEVER guess a coordinate without reading it off the screenshot, and take a fresh `screen` to SEE the "
    "result of every action before deciding the next one. Pages load slowly - after any action that changes the "
    "page, `wait:10`-`wait:15` before you `screen`.\n"
    "SCREENSHOTS ARE NUMBERED & IN ORDER: each `screen` gives you EXACTLY ONE image, labelled #1, #2, ... in "
    "the order you asked for them - and NOTHING else. Always judge from the NEWEST relevant screenshot. A click "
    "WORKED only if a screenshot taken AFTER it shows the change you expected (the form opened, the field "
    "filled, the check turned green); if the newest screenshot does NOT show that change, the click MISSED - "
    "re-read the coordinate off the grid and retry. NEVER conclude an action succeeded from an EARLIER "
    "screenshot: old frames show where you WERE, not where you are now.\n"
    "WHEN YOU CAN'T HIT A CONTROL: if a click does not produce the change you expect, or you've clicked the "
    "same area twice with no result, STOP clicking blindly. `probe:X,Y` several points around the label you "
    "want (e.g. a 'Log in with Email' button) to READ what is actually there - the reply tells you whether it's "
    "a button, a link, or just text like 'OR'. Find the coordinate that reports the RIGHT element, THEN click "
    "exactly there. Never click the same spot a third time - move your aim using what probe and the grid tell "
    "you.\n"
    "GROW THE SCRIPT - because every call starts FRESH, the sequence that WORKS is your only asset: keep it "
    "intact as the PREFIX and only ever ADD to its end. When your new step succeeds on the screenshot, fold it "
    "into the script and extend; when it MISSES, fix just that one step and re-run the WHOLE script. Replay the "
    "prefix EXACTLY the same each call (same coordinates, same order) - it is known to work; changing or "
    "dropping a prefix step breaks the run. I remind you of your current SCRIPT at each stage - always start "
    "from it.\n"

    "CREDENTIALS: type the tokens __USER__ (username) and __PASS__ (password) - substituted with the real "
    "values privately at dispatch. NEVER type a real credential or invent one.\n"

    + agentlog.NARRATE +

    ">>> STAGED, GATED EXECUTION. You log in as a SEQUENCE OF GATED STAGES, in this fixed order:\n"
    "  1. FIND THE LOGIN FORM   2. ENTER THE DETAILS   3. CLICK THE NECESSARY FIELDS   4. BYPASS THE CAPTCHA   "
    "5. SUBMIT & CONFIRM LOGIN.\n"
    "Each of my messages hands you ONE stage - its GOAL and its GATE. Work ONLY on that stage; do NOT run ahead "
    "into a later one. When you judge the stage done, VERIFY it on a FRESH screenshot (wait for the page, then "
    "`screen`), then emit ONE fenced ```json block and NOTHING after it:\n"
    "  {\"stage_ok\": true|false, \"evidence\": \"what on the screenshot proves this stage's gate\", "
    "\"notes\": \"anything relevant / what blocked you\"}\n"
    "RETRY WITHIN THE STAGE: you get MANY tool calls per stage - USE them. If a step MISSES (a field stays "
    "empty, a click does nothing), adjust the coordinate and RETRY it in THIS stage until the gate holds. A "
    "single missed click is NOT a stage failure. stage_ok is true ONLY if the stage's GATE holds RIGHT NOW on "
    "the screen - confirmed by the screenshot, not assumed. Emit stage_ok:false ONLY when you have genuinely "
    "EXHAUSTED your attempts and cannot proceed: it STOPS the ENTIRE run and there is NO later stage to retry "
    "in - so never defer a fix to a 'next stage', and never bail on a first miss. When a stage passes I advance "
    "you to the next and carry your working SCRIPT forward; keep replaying it from the fresh page and extend "
    "it.\n"

    "EXAMPLE - ONE call is a WHOLE replay from the fresh page: dismiss cookies, open login, act (your "
    "coordinates differ; read them off YOUR grid):\n"
    "  visual-driver <URL> --action wait:15 --action \"click:1200,775\" --action wait:3 --action "
    "\"click:1040,40\" --action wait:5 --action screen --action \"click:600,375\" --action \"put:__USER__\" "
    "--action \"click:600,460\" --action \"put:__PASS__\" --action wait --action screen")


# The five gated stages, run in order. Each stage's on-screen GATE must hold before the next stage begins;
# the run halts at the first stage whose gate the agent cannot prove. `goal` is what to accomplish, `gate` is
# the exact on-screen condition that counts as success.
_STAGES = [
    {"key": "form", "name": "FIND THE LOGIN FORM",
     "goal": "Reach the screen that shows BOTH the email/username input field AND the password input field. "
             "FIRST dismiss any cookie/consent overlay (click its Accept/close button). Then find and click the "
             "account / log in / sign in entry (often top-RIGHT). Choose LOG IN / SIGN IN - NOT Sign up / "
             "Register / Create account; if you land on a create-account page, switch to 'Log in' / 'Already "
             "have an account'. If a method chooser appears (social buttons + email), click the EMAIL option - "
             "if clicking it does NOT reveal the fields, PROBE around its label to find the button's exact x,y "
             "(it may report as a button/link next to plain 'OR' text), then click THAT; don't keep clicking "
             "the same wrong spot. Keep going (retry in THIS stage) until the fields are actually on screen.",
     "gate": "The email/username field AND the password field are both VISIBLE on the current screenshot."},
    {"key": "enter", "name": "ENTER THE DETAILS",
     "goal": "Fill the credentials. For EACH field in order (username/email first, then password): (1) aim at "
             "the input BOX, which sits BELOW its 'Email'/'Password' LABEL - click the BOX, not the label text "
             "(clicking a label does NOT focus the input, so the value goes nowhere); (2) probe:X,Y to CONFIRM "
             "you're on an input before typing - if it reports a label or plain text, move DOWN into the box and "
             "probe again; (3) click:X,Y to focus it; (4) put:__USER__ (or put:__PASS__); (5) screen to VERIFY "
             "the value landed (password shows as dots). CHECK the put's `landed` report: if it is false (or the "
             "field stays empty), your click hit the label or missed - move the Y a little LOWER into the box "
             "and RETRY here, in this stage, until BOTH puts report landed:true. Do NOT give up after one miss.",
     "gate": "BOTH the email/username put and the password put reported landed:true and the fields VISIBLY "
             "contain their value on the screenshot (the password may show as dots)."},
    {"key": "fields", "name": "CLICK THE NECESSARY FIELDS",
     "goal": "Set any OTHER control the form needs before it will accept a submit - e.g. a required 'remember "
             "me' / terms / consent checkbox, a toggle, a radio, a country or similar select. Do NOT click the "
             "submit button in this stage. If nothing else is required, return stage_ok:true immediately.",
     "gate": "Every required non-credential control is set (or there were none), and the form is ready to "
             "submit."},
    {"key": "captcha", "name": "BYPASS THE CAPTCHA",
     "goal": "Find and HANDLE any captcha - do not skip a visible one. An 'I'm not a robot' CHECKBOX (a small "
             "square, often with a reCAPTCHA logo): move:X,Y to it, click:X,Y to check it, wait, screen (a "
             "green check = passed). An image challenge: read the tiles off the screenshot and click the "
             "matching ones. If there is NO captcha, or it is an invisible one with nothing to click, return "
             "stage_ok:true and move on.",
     "gate": "The captcha shows as passed/cleared (e.g. a green check), or there is no captcha present to "
             "solve."},
    {"key": "submit", "name": "SUBMIT & CONFIRM LOGIN",
     "goal": "Read the submit / log in button's x,y off the grid and click:X,Y it; wait:15; screen. Then VERIFY "
             "success on the screen: the login form/modal is GONE and the header now shows YOUR account (an "
             "avatar, your name/initial, a 'Log Out' / 'My Account' / 'Orders' control) instead of 'Log In'. "
             "OPEN the account/profile page (click it, screen) and confirm it shows YOUR data.",
     "gate": "The screen shows the logged-in account - the personal/account page with YOUR details, the login "
             "form gone and the header no longer offering 'Log In'."},
]

_STAGE_MSG = (
    "=== STAGE {n}/{total}: {name} ===\n"
    "GOAL: {goal}\n"
    "GATE (stage_ok is true ONLY if this holds RIGHT NOW, confirmed on the screenshot): {gate}\n"
    "Remember: every visual-driver call is a FRESH browser at the target - REPLAY your working SCRIPT first, "
    "then add THIS stage's new actions on the end.\n"
    "YOUR SCRIPT SO FAR (replay these EXACTLY, in order, before your new steps): {script}\n"
    "Work ONLY on this stage, and RETRY any miss HERE until the gate holds - a single missed click is not a "
    "failure, and there is no 'next stage' to retry in. When the gate holds, VERIFY on a fresh screenshot, then "
    "emit the single fenced json {{\"stage_ok\": true|false, \"evidence\": \"...\", \"notes\": \"...\"}} and "
    "nothing after it. Emit stage_ok:false ONLY when you've genuinely exhausted your attempts (it ENDS the "
    "whole run) - do not pretend, and do not defer a fix to a later stage.")


# Nudges when the agent misuses the verdict/turn. A stage_ok:false ENDS the whole run, but the model keeps
# emitting it as a "progress note" while it still has attempts left - so we catch that and push it to continue.
_RETRY_NUDGE = (
    "You emitted stage_ok:false but you still have attempts left and you described a NEXT step - so you have "
    "NOT given up. stage_ok:false ENDS the entire run; it is NOT a progress note. Do your described next step "
    "NOW as a visual-driver call: replay your working script, then add the new action (e.g. click 'Log in with "
    "Email' - PROBE around it first to find the exact button), then `wait`, `screen`. Only emit a verdict when "
    "the gate truly holds (stage_ok:true) or you have genuinely exhausted your options.")
_ACT_NUDGE = (
    "Don't stop to narrate - ACT. Make your next visual-driver call now (replay your working script, then the "
    "next action), or emit stage_ok only if the stage is genuinely concluded.")


def _script_text(script: list) -> str:
    """Render the known-good replay chain for a stage briefing - the exact --action sequence to replay from the
    fresh page, or a note that the agent is starting clean."""
    if not script:
        return "(none yet - you start on the fresh target page; begin building the script)"
    return "visual-driver <URL> " + " ".join(f"--action {_q(a)}" for a in script)


def add_arguments(parser) -> None:
    parser.add_argument("target", help="Target URL (the app root or its login page)")
    parser.add_argument("--creds", default=None, metavar="USER:PASS", help="Credentials to log in with")
    parser.add_argument("--grid", type=int, default=25, metavar="PX",
                        help="Coordinate-grid spacing in px - finer = more precise aim (0 = off)")
    parser.add_argument("--trace", default="trace", metavar="DIR",
                        help="Save screenshots into DIR/logio-<timestamp>/ - one per `screen` the agent takes "
                             "plus each call's final state (default ./trace, a trace/ folder under the current "
                             "directory; in Docker pass --trace /trace and mount -v \"$PWD/trace:/trace\"). "
                             "Set '' to disable")
    parser.add_argument("--trace-each", dest="trace_each", action="store_true",
                        help="Verbose trace: also save a screenshot after EVERY action (not just `screen`s). "
                             "Off by default because the replay model re-runs the whole script each call")
    parser.add_argument("--session-out", dest="session_out", default=None, metavar="FILE",
                        help="On success, write the captured REUSABLE session (cookies + localStorage + "
                             "sessionStorage + token + login flow) to FILE as JSON (default: "
                             "<trace>/logio-<timestamp>/session.json)")
    add_agent_args(parser, max_steps=14, budget=600)


def _visual_tool_spec() -> dict:
    """visual-driver's schema RESTRICTED to logio's six actions and just target+action - so the agent can only
    move/click/put/probe/screen/wait, never uses find/click_text/requests/etc, and never sets session/grid/trace
    (logio injects those). The underlying tool is untouched; only what THIS agent sees is narrowed."""
    spec = toolschema.build("visual-driver")
    schema = json.loads(json.dumps(spec["schema"]))
    schema["properties"] = {k: v for k, v in schema["properties"].items() if k in ("target", "action")}
    schema["required"] = [r for r in schema.get("required", []) if r in schema["properties"]]
    if "action" in schema["properties"]:
        schema["properties"]["action"]["description"] = (
            "A visual action; repeatable, run in order. ONLY these six exist - use nothing else: "
            "wait:SECONDS (bare wait=5s) | screen | move:X,Y | click:X,Y | put:TEXT (type into the focused "
            "field; reports `landed` true/false) | probe:X,Y (report what element is at x,y). Coordinates take "
            "a comma or colon.")
    return {"name": "visual-driver",
            "description": "Drive a browser by SCREEN COORDINATES; returns a coordinate-grid screenshot.",
            "schema": schema}


def _dispatch(argv: list, headers: list, debug: bool = False) -> str:
    """Run one boxcutter sub-command in-process and return its JSON envelope text. Header-capable tools get the
    global --header(s) appended (e.g. a Tester-Token); under --debug the sub-tool also gets --debug so its own
    diagnostics (visual-driver's ok/failed/flow counts) stream to stderr."""
    from ..cli import main as cli_main
    flag = toolschema.build(argv[0])["flag_of"].get("header") if argv else None
    if flag and headers:
        argv = argv + [x for h in headers for x in (flag, h)]
    argv = agentlog.forward_debug(argv, debug)
    out_buf, err_buf = io.StringIO(), io.StringIO()
    import contextlib
    try:
        with contextlib.redirect_stdout(out_buf), contextlib.redirect_stderr(err_buf):
            cli_main(list(argv))
    except SystemExit:
        pass
    except Exception as exc:  # noqa: BLE001
        return json.dumps({"success": False, "error": f"{argv[0]} failed: {exc}"})
    raw = out_buf.getvalue().strip()
    return raw or json.dumps({"success": True, "data": [], "error": None})


def _take_images(out: str) -> tuple:
    """Pull screenshot(s) a tool emitted out of the envelope and forward them as real vision blocks. Delegates
    to the shared ORDERED harvester: exactly one image per `screen`, in order, numbered - so the agent never
    reads a click's result off a stale/out-of-order screenshot. See envelope.harvest_images."""
    return harvest_images(out, max_images=8)


def _rewrite(name: str, args: dict, subs: dict, grid, trace, trace_each=False, dump_storage=False) -> dict:
    """Inject grid/trace and substitute the secret tokens at dispatch. (No session is injected - see below.)"""
    def sub(s):
        if not isinstance(s, str):
            return s
        for tok, val in subs.items():
            s = s.replace(tok, val)
        return s

    a = dict(args or {})
    if name == "visual-driver":
        # NO persistent session: every visual-driver call is a VIRGIN browser freshly loaded at the target -
        # nothing carries over between calls. The agent replays its whole known-good script from the clean page
        # each call and extends it (see _SYSTEM). Session capture/reuse is a later concern.
        if grid is not None:
            a["grid"] = grid
        if trace:
            a["trace"] = trace
            a["trace_each"] = trace_each     # off by default: the replay re-runs the whole script each call,
    #                                          so a per-action trace explodes; keep only `screen`s + finals
        if dump_storage:
            a["dump_storage"] = True         # capture the authenticated localStorage/sessionStorage for reuse
    if name in ("visual-driver", "browser-actions"):
        if name == "browser-actions":
            a["session"] = _SESSION
        act = a.get("action")
        if isinstance(act, list):
            a["action"] = [sub(x) for x in act]
        elif isinstance(act, str):
            a["action"] = sub(act)
    if name == "browser-login" and isinstance(a.get("creds"), str):
        a["creds"] = sub(a["creds"])
    return a


def _actions_of(argv: list) -> list:
    """The --action values from a visual-driver argv, in order (secret tokens still as __USER__/__PASS__), so
    the replayable login flow is built from what was ACTUALLY dispatched, not from the model's memory."""
    acts, it = [], iter(argv)
    for a in it:
        if a == "--action":
            v = next(it, "")
            if v:
                acts.append(v)
    return acts


def _last_state(out: str) -> dict | None:
    """The cookie/token/url from a visual-driver reply's state record - captured directly so the session we
    report is the real one, not something the model retyped."""
    try:
        env = json.loads(out)
    except Exception:  # noqa: BLE001
        return None
    data = env.get("data") if isinstance(env, dict) else None
    if not isinstance(data, list):
        return None
    for rec in data:
        if isinstance(rec, dict) and rec.get("type") == "state":
            return {"url": rec.get("url", ""), "cookie": rec.get("cookie", ""), "token": rec.get("token", ""),
                    "storage": rec.get("storage") or {}}     # localStorage+sessionStorage when dump_storage on
    return None


def _put_landings(out: str) -> list:
    """Whether each put/type in a visual-driver reply actually landed in a field. visual-driver VERIFIES every
    put (reads the focused field back) and reports `landed`; logio uses this to ENFORCE that the credentials
    were really entered - not just claimed on a screenshot."""
    try:
        env = json.loads(out)
    except Exception:  # noqa: BLE001
        return []
    data = env.get("data") if isinstance(env, dict) else None
    lands: list = []
    if isinstance(data, list):
        for rec in data:
            res = rec.get("results") if isinstance(rec, dict) else None
            if isinstance(res, list):
                for r in res:
                    if isinstance(r, dict) and str(r.get("action", "")).split(":", 1)[0].strip().lower() \
                            in ("put", "type"):
                        lands.append(bool(r.get("landed")))
    return lands


def _stage_verdict(text: str) -> dict | None:
    """Parse the model's per-stage {stage_ok:...} json out of its reply (the stage-gate signal). Returns the
    dict if found, else None (the stage did not conclude)."""
    for m in re.finditer(r"\{[^{}]*\}", text, re.S):
        try:
            obj = json.loads(m.group(0))
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and "stage_ok" in obj:
            return obj
    return None


def _q(a: str) -> str:
    """Quote an action for the printed replay line if it holds anything a shell would split."""
    return a if re.fullmatch(r"[A-Za-z0-9:,._/-]+", a or "") else '"' + a + '"'


def login(provider, base_url: str, subs: dict, grid=50, trace=None, trace_each=False,
          headers=None, max_steps: int = 14, debug: bool = False) -> dict:
    """The reusable LOGIN CORE - the gated stage loop, factored out of run() so BOTH the logio CLI and IRVIN's
    `auth` executor drive the SAME proven staged / probe-before-type / landed-verified login. `subs` maps the
    __USER__/__PASS__ tokens to the real values (substituted only at dispatch). Returns a dict with
    authenticated / failed_stage / flow / session_header / cookies / token / local_storage / session_storage /
    stages / evidence / notes. Does NOT close browser sessions or write files - the caller owns lifecycle."""
    headers = list(headers or [])
    dbg = debug_logger(debug)                   # verbose tier: full reasoning + per-call outcome, only under --debug
    tools_spec = [_visual_tool_spec()]          # restricted: only the six actions, no session/grid/trace
    messages = [{"role": "user", "content":
                 f"Log in to {base_url} with the supplied credentials, ONE GATED STAGE AT A TIME. I will hand "
                 "you each stage in turn; work only on the current stage and end it with its stage_ok verdict. "
                 "Type __USER__ / __PASS__ for the username/password. Do not run ahead of the stage I give you."}]
    script: list = []
    last_chain: list = []
    last_puts: list = []
    last_state: dict | None = None
    stage_log: list = []
    failed_stage: str | None = None
    for i, stage in enumerate(_STAGES, 1):
        messages.append({"role": "user", "content": _STAGE_MSG.format(
            n=i, total=len(_STAGES), name=stage["name"], goal=stage["goal"], gate=stage["gate"],
            script=_script_text(script))})
        verdict = None
        for step_i in range(max_steps):
            last_step = step_i >= max_steps - 1
            try:
                resp = provider.send(_SYSTEM, messages, tools_spec)
            except Exception as exc:  # noqa: BLE001
                sys.stderr.write(f"logio: provider error: {exc}\n")
                break
            text, calls = provider.parse(resp)
            messages += provider.assistant_msg(resp)
            if text.strip():
                flat = " ".join(text.split())
                if debug:
                    dbg(f"logio[{stage['key']}]: " + flat)          # the WHY, in full, under --debug
                else:
                    debug_print(f"logio[{stage['key']}]> " + flat[:300])
            v = _stage_verdict(text)
            if v is not None:
                verdict = v
                if v.get("stage_ok") or last_step:
                    break
                debug_print(f"logio[{stage['key']}]> (stage_ok:false with attempts left - continuing)")
                messages.append({"role": "user", "content": _RETRY_NUDGE})
                continue
            if not calls:
                if last_step:
                    break
                messages.append({"role": "user", "content": _ACT_NUDGE})
                continue
            results = []
            for c in calls:
                log_argv = toolschema.to_argv(c["name"], c["args"])
                real_argv = toolschema.to_argv(c["name"], _rewrite(
                    c["name"], c["args"], subs, grid, trace, trace_each,
                    dump_storage=(stage["key"] == "submit")))
                debug_print("logio> boxcutter " + " ".join(str(a) for a in log_argv))
                out = _dispatch(real_argv, headers, debug)
                out, images = _take_images(out)
                dbg(f"    <- {c['name']}: {agentlog.summarize(out)}")
                if c["name"] == "visual-driver":
                    last_chain = _actions_of(log_argv)
                    last_puts = _put_landings(out)
                st = _last_state(out)
                if st:
                    last_state = st
                results.append({"id": c["id"], "output": out, "images": images})
            messages += provider.tool_results(results)

        ok = bool(verdict and verdict.get("stage_ok"))
        note = (verdict or {}).get("notes") or ("" if verdict else "stage did not conclude")
        if ok and stage["key"] == "enter" and last_puts and not all(last_puts):
            ok = False
            note = ("tool verification: a credential did NOT land in its field (put reported empty) - the "
                    "fields were not actually filled" + (f" [agent claimed: {note}]" if note else ""))
        stage_log.append({"stage": stage["key"], "ok": ok,
                          "evidence": (verdict or {}).get("evidence", ""), "notes": note})
        debug_print(f"logio :: stage {i}/{len(_STAGES)} {stage['name']} -> {'PASS' if ok else 'FAIL'}"
                    + (f" ({note})" if note else ""))
        if not ok:
            failed_stage = stage["key"]
            break
        if len(last_chain) >= len(script):
            script = last_chain

    authenticated = failed_stage is None
    cookie = (last_state or {}).get("cookie", "")
    token = (last_state or {}).get("token", "")
    storage = (last_state or {}).get("storage") or {}
    session_header = (f"Authorization: Bearer {token}" if token
                      else f"Cookie: {cookie}" if cookie else "")
    return {"authenticated": authenticated, "failed_stage": failed_stage, "flow": script,
            "session_header": session_header, "cookies": cookie, "token": token,
            "local_storage": storage.get("local") or {}, "session_storage": storage.get("session") or {},
            "stages": stage_log, "evidence": stage_log[-1]["evidence"] if stage_log else "",
            "notes": "; ".join(f"{s['stage']}: {s['notes']}" for s in stage_log if s["notes"]),
            "trace_dir": trace}


def run(args) -> int:
    target = args.target.strip()
    if not target:
        output_result([], args.output, "a target is required")
        return 2
    provider_cls = PROVIDERS[args.provider]
    key = args.api_key or os.environ.get(provider_cls.env)
    if not key:
        sys.stderr.write(f"logio: provide --api-key or set {provider_cls.env} for --provider {args.provider}\n")
        return 2

    base_url = target if target.startswith(("http://", "https://")) else "https://" + target
    base_host = (urlparse(base_url).hostname or "").lower()
    provider = provider_cls(args.model or provider_cls.default_model, key, base_url=args.base_url)
    headers = list(args.header or [])

    # credentials from --creds, or extracted from the plain-language --context (same as IRVIN's briefing)
    creds = args.creds
    if (not creds or ":" not in creds) and args.context.strip():
        cfg = briefing.parse(provider, args.context, base_host)
        headers += cfg.get("headers", [])
        cc = cfg.get("creds") or []
        if cc:
            creds = f"{cc[0]['user']}:{cc[0]['password']}"
            sys.stderr.write("logio :: credentials parsed from --context (values hidden)\n")
    if not creds or ":" not in creds:
        output_result([], args.output,
                       "logio needs credentials - pass --creds \"user:pass\" or mention them in --context")
        return 2

    user, _, pw = creds.partition(":")
    subs = {"__USER__": user, "__PASS__": pw, "__CREDS__": f"{user}:{pw}"}
    grid = args.grid
    # each run gets its own subdir so screenshots don't pile up loose across runs (numbering restarts per run)
    trace = os.path.join(os.path.abspath(args.trace), "logio-" + time.strftime("%Y%m%d-%H%M%S")) \
        if args.trace else None
    trace_each = bool(getattr(args, "trace_each", False))
    dbg = debug_logger(args.debug)              # verbose tier: full reasoning + per-call outcome, only under --debug
    tools_spec = [_visual_tool_spec()]          # restricted: only the six actions, no session/grid/trace
    messages = [{"role": "user", "content":
                 f"Log in to {base_url} with the supplied credentials, ONE GATED STAGE AT A TIME. I will hand "
                 "you each stage in turn; work only on the current stage and end it with its stage_ok verdict. "
                 "Type __USER__ / __PASS__ for the username/password. Do not run ahead of the stage I give you."}]

    sys.stderr.write(f"logio :: target={target} provider={args.provider} "
                     f"model={args.model or provider_cls.default_model} [grid={grid} | "
                     f"trace={trace or 'off'}{' (each action)' if trace_each else ''} | "
                     f"{len(_STAGES)} gated stages]\n")

    # Each visual-driver call is a FRESH browser, so the login is built as ONE growing replay SCRIPT: `script`
    # is the known-good chain that reaches the current point, `last_chain` is the most recent full call, and a
    # stage that passes promotes its winning chain into `script` for the next stage to replay + extend.
    script: list = []
    last_chain: list = []
    last_puts: list = []               # per-put landed verdicts from the most recent visual-driver reply
    last_state: dict | None = None     # cookie/token/url from the most recent visual-driver reply
    stage_log: list = []               # per-stage {stage, ok, evidence, notes}
    failed_stage: str | None = None
    deadline = time.time() + max(30, args.budget)
    try:
        for i, stage in enumerate(_STAGES, 1):
            if time.time() > deadline:
                debug_print("logio :: wall-clock budget reached - finalizing with the stages done so far")
                break
            messages.append({"role": "user", "content": _STAGE_MSG.format(
                n=i, total=len(_STAGES), name=stage["name"], goal=stage["goal"], gate=stage["gate"],
                script=_script_text(script))})
            verdict = None
            for step_i in range(args.max_steps):
                last_step = step_i >= args.max_steps - 1
                try:
                    resp = provider.send(_SYSTEM, messages, tools_spec)
                except Exception as exc:  # noqa: BLE001
                    sys.stderr.write(f"logio: provider error: {exc}\n")
                    break
                text, calls = provider.parse(resp)
                messages += provider.assistant_msg(resp)
                if text.strip():
                    flat = " ".join(text.split())
                    if args.debug:
                        dbg(f"logio[{stage['key']}]: " + flat)      # the WHY, in full, under --debug
                    else:
                        debug_print(f"logio[{stage['key']}]> " + flat[:300])
                v = _stage_verdict(text)
                if v is not None:
                    verdict = v
                    if v.get("stage_ok") or last_step:
                        break                # PASS, or out of attempts -> accept this (failed) verdict
                    # premature stage_ok:false with budget left - the model is using it as a progress note.
                    # Don't end the whole run: nudge it to do its next step IN this stage.
                    debug_print(f"logio[{stage['key']}]> (stage_ok:false with attempts left - continuing)")
                    messages.append({"role": "user", "content": _RETRY_NUDGE})
                    continue
                if not calls:                # no verdict and nothing to run - nudge to act, don't stall out
                    if last_step:
                        break
                    messages.append({"role": "user", "content": _ACT_NUDGE})
                    continue
                results = []
                for c in calls:
                    log_argv = toolschema.to_argv(c["name"], c["args"])
                    # capture the client-side auth state on the SUBMIT stage, where the login actually completes
                    real_argv = toolschema.to_argv(c["name"], _rewrite(
                        c["name"], c["args"], subs, grid, trace, trace_each,
                        dump_storage=(stage["key"] == "submit")))
                    debug_print("logio> boxcutter " + " ".join(str(a) for a in log_argv))
                    out = _dispatch(real_argv, headers, args.debug)
                    out, images = _take_images(out)
                    dbg(f"    <- {c['name']}: {agentlog.summarize(out)}")
                    if c["name"] == "visual-driver":
                        last_chain = _actions_of(log_argv)     # each call is a whole fresh replay
                        last_puts = _put_landings(out)         # did this replay's puts actually fill the fields
                    st = _last_state(out)
                    if st:
                        last_state = st
                    results.append({"id": c["id"], "output": out, "images": images})
                messages += provider.tool_results(results)

            ok = bool(verdict and verdict.get("stage_ok"))
            note = (verdict or {}).get("notes") or ("" if verdict else "stage did not conclude")
            # ENSURE the credentials really landed: the ENTER stage cannot pass if the tool verified a put
            # did NOT enter its field, no matter what the screenshot-based verdict claimed.
            if ok and stage["key"] == "enter" and last_puts and not all(last_puts):
                ok = False
                note = ("tool verification: a credential did NOT land in its field (put reported empty) - the "
                        "fields were not actually filled" + (f" [agent claimed: {note}]" if note else ""))
            stage_log.append({"stage": stage["key"], "ok": ok,
                              "evidence": (verdict or {}).get("evidence", ""), "notes": note})
            debug_print(f"logio :: stage {i}/{len(_STAGES)} {stage['name']} -> {'PASS' if ok else 'FAIL'}"
                        + (f" ({note})" if note else ""))
            if not ok:
                failed_stage = stage["key"]      # GATE: stop here, do not run the later stages
                break
            if len(last_chain) >= len(script):   # promote the winning replay chain (only ever grows the script)
                script = last_chain
    finally:
        from ..core.cdp import close_all_sessions
        close_all_sessions()

    authenticated = failed_stage is None
    cookie = (last_state or {}).get("cookie", "")
    token = (last_state or {}).get("token", "")
    storage = (last_state or {}).get("storage") or {}
    local_storage = storage.get("local") or {}
    session_storage = storage.get("session") or {}
    session_header = (f"Authorization: Bearer {token}" if token
                      else f"Cookie: {cookie}" if cookie else "")
    evidence = stage_log[-1]["evidence"] if stage_log else ""
    flow = script                      # the known-good replay chain IS the replayable login recipe

    # the REUSABLE session: everything needed to re-enter the app as this logged-in user - cookies + the full
    # client-side auth state (localStorage/sessionStorage) + token, plus the replayable login flow as a fallback
    session = {"url": base_url, "cookies": cookie, "session_header": session_header, "token": token,
               "local_storage": local_storage, "session_storage": session_storage, "flow": flow}
    session_file = ""
    if authenticated:
        session_file = args.session_out or (os.path.join(trace, "session.json") if trace else "")
        if session_file:
            try:
                os.makedirs(os.path.dirname(session_file) or ".", exist_ok=True)
                with open(session_file, "w", encoding="utf-8") as fh:
                    json.dump(session, fh, ensure_ascii=False, indent=2)
            except OSError as exc:
                debug_print(f"logio :: could not write session file {session_file}: {exc}")
                session_file = ""

    debug_print(f"\nlogio :: login {'SUCCEEDED' if authenticated else 'did NOT succeed'} for {base_url}"
                + ("" if authenticated else f" - stopped at stage '{failed_stage}'"))
    debug_print("logio :: stages " + " -> ".join(f"{s['stage']}:{'ok' if s['ok'] else 'FAIL'}" for s in stage_log))
    if trace and os.path.isdir(trace):
        shots = sorted(f for f in os.listdir(trace) if f.endswith(".png"))
        debug_print(f"logio :: {len(shots)} action screenshot(s) saved to {trace}")
    if flow:
        debug_print(f"logio :: login flow ({len(flow)} actions - replays from a fresh page):")
        debug_print("  boxcutter visual-driver <URL> " + " ".join(f"--action {_q(a)}" for a in flow))
    if authenticated:
        debug_print(f"logio :: captured session - {len(cookie.split(';')) if cookie else 0} cookie(s), "
                    f"{len(local_storage)} localStorage + {len(session_storage)} sessionStorage key(s)"
                    + (f", token yes" if token else "") + (f" -> {session_file}" if session_file else ""))
    for s in stage_log:
        if s["notes"]:
            debug_print(f"  {s['stage']}: {s['notes']}")

    summary = {"authenticated": authenticated, "url": base_url, "failed_stage": failed_stage,
               "stages": stage_log, "flow": flow, "session_header": session_header, "cookies": cookie,
               "token": token, "local_storage": local_storage, "session_storage": session_storage,
               "session_file": session_file, "trace_dir": trace, "evidence": evidence,
               "notes": "; ".join(f"{s['stage']}: {s['notes']}" for s in stage_log if s["notes"])}
    report = "\n".join(
        [f"## Logio - login: {base_url}", "",
         f"**Result:** {'authenticated' if authenticated else 'not authenticated'}"
         + (f" (stopped at stage '{failed_stage}')" if failed_stage else ""), "",
         "**Stages:** " + " -> ".join(f"{s['stage']}:{'ok' if s['ok'] else 'FAIL'}" for s in stage_log)]
        + ([f"**Session captured** -> {session_file}"] if authenticated and session_file else [])
        + [f"- {s['stage']}: {s['notes']}" for s in stage_log if s['notes']])
    write_report(getattr(args, "report", None), report)
    print(json.dumps({"success": True, "kind": "items", "data": [summary], "error": None},
                     ensure_ascii=False, indent=2))
    return 0
