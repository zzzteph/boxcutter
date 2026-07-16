"""browser-crawl - render and interact with a JS/SPA app to capture routes + XHR/fetch.

The raw HTTP tools fetch a SPA's empty shell; this renders it in a headless browser (CDP over the system
chromium, see core.cdp) and records every XHR/fetch the page makes - the real API surface, INCLUDING the
cross-origin backend a SPA talks to (e.g. an api.* host) - plus same-origin routes, clicking a bounded set of
elements to trigger more. Full-image tool: needs chromium + websocket-client, and degrades gracefully without.

Emits items: {url, method, type: xhr|route}.
"""

from __future__ import annotations

from urllib.parse import urlparse

from ..core.args import add_common_args, add_header_arg
from ..core.cdp import CDPError, Chrome, get_session
from ..core.envelope import debug_logger, output_result
from ..core.validators import is_valid_url

NAME = "browser-crawl"
KIND = "items"
HELP = "Render a JS/SPA in a headless browser and capture its routes + API (XHR/fetch) calls."

_SKIP_WORDS = ("logout", "sign out", "log out", "delete", "remove", "deactivate", "pay", "purchase")


def add_arguments(parser) -> None:
    parser.add_argument("target", help="URL to render")
    parser.add_argument("--session", dest="session", default=None, metavar="ID",
                        help="Attach to a persistent browser session by id (e.g. one already LOGGED IN by "
                             "logio/prawlio) instead of spawning a fresh browser - the crawl then runs "
                             "AUTHENTICATED. On attach the start URL is not re-navigated (it crawls from where "
                             "the session already is).")
    add_header_arg(parser)
    parser.add_argument("--timeout", type=int, default=45, help="Per-page timeout (seconds)")
    parser.add_argument("--max-actions", dest="max_actions", type=int, default=25,
                        help="Max elements to click while exploring")
    add_common_args(parser)


def _crawl(page, target, max_actions, dbg, navigate=True):
    """Explore the rendered app and return the captured items. `navigate=False` crawls from wherever the page
    already is (an attached, already-authenticated session) instead of re-loading the start URL."""
    site_hosts = {urlparse(target).hostname or ""}
    if navigate:
        page.navigate(target, wait="networkidle")
    site_hosts.add(urlparse(page.current_url()).hostname or "")
    routes = _same_site_links(page, site_hosts)

    filled = _auto_fill(page, max_actions, dbg)
    if filled:
        site_hosts.add(urlparse(page.current_url()).hostname or "")
        routes.update(_same_site_links(page, site_hosts))

    clicked = _auto_click(page, max_actions, dbg)
    site_hosts.add(urlparse(page.current_url()).hostname or "")
    routes.update(_same_site_links(page, site_hosts))

    captured = page.xhr()
    items = [{"url": u, "method": m, "type": "xhr"} for (m, u) in captured]
    items += [{"url": u, "method": "GET", "type": "route"} for u in sorted(routes)]
    cookie_names = ", ".join(sorted({c.split("=", 1)[0] for c in page.cookies().split("; ") if c})) or "(none)"
    dbg(f"browser-crawl: {len(captured)} api calls, {len(routes)} routes "
        f"({filled} field(s) filled, {clicked} element(s) clicked)")
    # diagnostic for the "did it actually render, or get blocked/redirected?" question - names only, never
    # cookie values, since this line is printed on every --debug run.
    dbg(f"browser-crawl: landed on {page.current_url()!r} titled {page.title()!r}; cookies set: {cookie_names}")
    return items


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
    try:
        if sid:
            # attach to an existing (already logged-in) browser; on attach, DON'T re-navigate - crawl from where
            # the session already is. A freshly-opened session (fresh=True) still gets the start URL.
            page, fresh = get_session(sid, headers=headers, timeout=args.timeout, debug=dbg)
            items = _crawl(page, target, args.max_actions, dbg, navigate=fresh)
        else:
            with Chrome(headers=headers, timeout=args.timeout, debug=dbg) as page:
                items = _crawl(page, target, args.max_actions, dbg, navigate=True)
    except CDPError as exc:
        output_result([], args.output, f"browser-crawl unavailable: {exc}")
        return 1
    except Exception as exc:  # noqa: BLE001
        output_result([], args.output, f"browser-crawl failed: {exc}")
        return 1

    output_result(items, args.output)
    return 0


def _same_site_links(page, hosts) -> set:
    """Links matching ANY host the navigation actually touched (the original target's host plus wherever it
    redirected to) - a single pre-navigation host misses every link once the site redirects (e.g. apex ->
    www), which silently zeroes out 'routes' on an otherwise fully-rendered page."""
    out = set()
    for h in {h for h in hosts if h}:
        out.update(page.links(same_host=h))
    return out


def _auto_fill(page, budget, dbg) -> int:
    """Type a plausible probe value into empty text-like inputs (search/address/email/...) and press Enter.
    Many SPA landing pages ('enter your address to see what's near you') never call their real API until this
    happens - clicking buttons alone never reaches it. Capped well below the click budget: most pages have at
    most a handful of these fields."""
    filled = 0
    for _ in range(min(5, budget)):
        val = page.fill_nth(0)
        if not val:
            break
        filled += 1
        dbg(f"browser-crawl: filled a field with {val!r}, pressing enter")
        try:
            page.press("enter")
        except CDPError:
            pass
        page.wait(400)
    return filled


def _auto_click(page, budget, dbg) -> int:
    """Click through clickable elements up to the budget. Re-checks the LIVE DOM each step (see
    Chrome._CLICKABLE_SEL) instead of a one-shot snapshot, so content revealed by an earlier click (e.g. behind
    a just-dismissed cookie banner) gets explored too. Peeks each element's label BEFORE clicking so a
    dangerous-looking action (logout/delete/pay/purchase) is skipped WITHOUT ever being clicked - not clicked
    first and only silently un-waited-for, which is what happened here before."""
    clicked = 0
    while clicked < budget:
        try:
            if page.clickable(1) < 1:
                break
            label = (page.peek_nth(0) or "").lower()
            if label and any(w in label for w in _SKIP_WORDS):
                page.mark_done(0)
                continue
            page.click_nth(0)
        except CDPError:
            break                                            # navigation mid-click or similar - stop here
        clicked += 1
        page.wait(300)
    return clicked
