"""browser-login - perform a real login flow in a headless browser and return the session.

For SPA / CSRF-token / redirect logins that a raw POST can't do: it fills the login form with --creds,
submits, follows redirects, and returns the resulting cookies (and any bearer token found in storage). Driven
via CDP over the system chromium (core.cdp). Full-image tool: needs chromium + websocket-client. Emits one
item: {url, cookie, token, status}.
"""

from __future__ import annotations

from ..core.args import add_common_args
from ..core.cdp import CDPError, Chrome
from ..core.envelope import debug_logger, output_result
from ..core.validators import is_valid_url

NAME = "browser-login"
KIND = "items"
HELP = "Log in through a real browser (SPA/CSRF/redirect) and return the resulting session cookie/token."

_USER_SEL = ("input[type=email]", "input[name*=user i]", "input[name*=email i]",
             "input[id*=user i]", "input[id*=email i]", "input[type=text]")
_PASS_SEL = ("input[type=password]",)
_SUBMIT_SEL = ("button[type=submit]", "input[type=submit]",
               "button:has-text('log in')", "button:has-text('sign in')", "button:has-text('login')")
_TOKEN_JS = ("() => { try { for (const k of Object.keys(localStorage)) { const v = localStorage.getItem(k); "
             "if (v && /eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+/.test(v)) return v; } } catch (e) {} return ''; }")


def add_arguments(parser) -> None:
    parser.add_argument("target", help="Login page URL")
    parser.add_argument("--creds", required=True, metavar="USER:PASS", help="username:password")
    parser.add_argument("--timeout", type=int, default=45, help="Per-page timeout (seconds)")
    add_common_args(parser)


def _fill_first(page, selectors, value) -> bool:
    for sel in selectors:
        try:
            page.fill(sel, value)
            return True
        except CDPError:
            continue
    return False


def _click_first(page, selectors) -> bool:
    for sel in selectors:
        try:
            page.click(sel)
            return True
        except CDPError:
            continue
    return False


def run(args) -> int:
    target = args.target.strip()
    dbg = debug_logger(args.debug)
    if not is_valid_url(target):
        output_result([], args.output, "Invalid URL.")
        return 1
    if ":" not in args.creds:
        output_result([], args.output, "Use --creds user:pass")
        return 1
    user, pw = args.creds.split(":", 1)

    try:
        with Chrome(timeout=args.timeout, debug=dbg) as page:
            status = page.navigate(target, wait="networkidle")
            if not _fill_first(page, _USER_SEL, user) or not _fill_first(page, _PASS_SEL, pw):
                output_result([], args.output, "could not locate login fields")
                return 1
            _click_first(page, _SUBMIT_SEL)
            page.wait(2000)                       # let the login POST + redirect / SPA transition settle
            cookie = page.cookies()
            try:
                token = page.eval_fn(_TOKEN_JS) or ""
            except CDPError:
                token = ""
    except CDPError as exc:
        output_result([], args.output, f"browser-login unavailable: {exc}")
        return 1
    except Exception as exc:  # noqa: BLE001
        output_result([], args.output, f"browser-login failed: {exc}")
        return 1

    dbg(f"browser-login: cookie={'yes' if cookie else 'no'} token={'yes' if token else 'no'}")
    output_result([{"url": target, "cookie": cookie, "token": token, "status": status}], args.output)
    return 0
