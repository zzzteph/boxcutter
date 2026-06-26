"""browser-login - perform a real login flow in a headless browser and return the session.

For SPA / CSRF-token / redirect logins that a raw POST can't do: it fills the login form with --creds,
submits, follows redirects, and returns the resulting cookies (and any bearer token found in storage).
Capability-gated: needs Playwright + Chromium. Emits one item: {url, cookie, token, status}.
"""

from __future__ import annotations

import os
import shutil

from ..core.args import add_common_args
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


def _fill_first(page, selectors, value):
    for sel in selectors:
        try:
            el = page.query_selector(sel)
            if el:
                el.fill(value, timeout=2000)
                return True
        except Exception:  # noqa: BLE001
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
        from playwright.sync_api import sync_playwright
    except Exception:  # noqa: BLE001
        output_result([], args.output, "playwright is not installed (browser-login is a full-image tool)")
        return 1

    try:
        exe = os.environ.get("CHROMIUM_PATH") or shutil.which("chromium-browser") or shutil.which("chromium")
        with sync_playwright() as pw_ctx:
            browser = pw_ctx.chromium.launch(headless=True, **({"executable_path": exe} if exe else {}))
            ctx = browser.new_context(ignore_https_errors=True)
            page = ctx.new_page()
            resp = page.goto(target, wait_until="networkidle", timeout=args.timeout * 1000)
            status = resp.status if resp else None
            if not _fill_first(page, _USER_SEL, user) or not _fill_first(page, _PASS_SEL, pw):
                browser.close()
                output_result([], args.output, "could not locate login fields")
                return 1
            for sel in _SUBMIT_SEL:
                try:
                    btn = page.query_selector(sel)
                    if btn:
                        btn.click(timeout=3000)
                        break
                except Exception:  # noqa: BLE001
                    continue
            try:
                page.wait_for_load_state("networkidle", timeout=args.timeout * 1000)
            except Exception:  # noqa: BLE001
                pass
            cookies = ctx.cookies()
            cookie = "; ".join(f"{c['name']}={c['value']}" for c in cookies)
            try:
                token = page.evaluate(_TOKEN_JS) or ""
            except Exception:  # noqa: BLE001
                token = ""
            browser.close()
    except Exception as exc:  # noqa: BLE001
        output_result([], args.output, f"browser-login failed: {exc}")
        return 1

    dbg(f"browser-login: cookie={'yes' if cookie else 'no'} token={'yes' if token else 'no'}")
    output_result([{"url": target, "cookie": cookie, "token": token, "status": status}], args.output)
    return 0
