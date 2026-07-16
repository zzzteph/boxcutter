"""Minimal Chrome DevTools Protocol client - drives the system chromium, no Playwright.

Playwright publishes no musl/Alpine wheel, but the image already ships chromium + chromium-chromedriver. This
launches that chromium headless on a ``--remote-debugging-port`` and talks CDP over its WebSocket via the
pure-Python ``websocket-client`` lib (installs fine on musl). The headline capability is ``Network.enable`` ->
a ``Network.requestWillBeSent`` event for every request the page makes, so a SPA's real (often cross-origin)
API surface is captured by listening, not guessing. Used by browser-crawl/login/actions.

Usage::

    from ..core.cdp import Chrome, chromium_path, CDPError
    with Chrome(headers={"Authorization": "Bearer ..."}, timeout=45) as page:
        status = page.navigate("https://app.example.com", wait="networkidle")
        page.fill("#user", "admin"); page.click("button[type=submit]")
        api = page.xhr()                 # [(method, url), ...] - XHR/fetch captured live
        cookie = page.cookies(); title = page.title()
"""

from __future__ import annotations

import base64
import contextlib
import json
import math
import os
import random
import shutil
import socket
import subprocess
import time
import urllib.request
from urllib.parse import urlparse

from . import fsutil


class CDPError(Exception):
    pass


# The single biggest automation tell: real browsers never expose navigator.webdriver, but CDP-driven Chrome
# always sets it true unless patched. Injected on EVERY new document (via Page.addScriptToEvaluateOnNewDocument)
# so it applies before any page script runs - the same technique Puppeteer/Playwright's stealth plugins use.
_STEALTH_JS = "Object.defineProperty(navigator, 'webdriver', {get: () => undefined});"

# fill_nth() picks a plausible probe value by matching the input's name/placeholder/autocomplete/type against
# these substrings, in order, falling back to _default - generic enough for any site's search/address/contact
# field, not tailored to one target.
_FILL_HINTS = {
    "email": "test@example.com",
    "phone": "5555550123", "tel": "5555550123",
    "zip": "10001", "postal": "10001", "postcode": "10001",
    "address": "350 5th Ave, New York, NY", "location": "New York",
    "_default": "test",
}


def chromium_path() -> str | None:
    """Resolve the chromium executable, or None if absent (tools then degrade gracefully)."""
    return (os.environ.get("CHROMIUM_PATH") or shutil.which("chromium-browser")
            or shutil.which("chromium") or shutil.which("google-chrome") or shutil.which("chrome"))


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# -- selector -> JS (CSS, text=Foo, TAG:has-text('Foo')) ---------------------

def _find_expr(selector: str) -> str:
    """A JS expression that evaluates to the matching element (or null)."""
    sel = selector.strip()
    if ":has-text(" in sel:
        tag, _, rest = sel.partition(":has-text(")
        txt = rest.strip().rstrip(")").strip().strip("'\"").lower()
        tag = tag.strip() or "*"
        return (f"Array.from(document.querySelectorAll({json.dumps(tag)})).find("
                f"e=>((e.textContent||'').toLowerCase().includes({json.dumps(txt)})))")
    if sel.startswith("text="):
        txt = sel[5:].strip().lower()
        return ("Array.from(document.querySelectorAll('a,button,[role=button],input[type=submit],[onclick]'))"
                f".find(e=>((e.textContent||e.value||'').trim().toLowerCase().includes({json.dumps(txt)})))")
    return f"document.querySelector({json.dumps(sel)})"


_KEYS = {"enter": (13, "Enter"), "tab": (9, "Tab"), "escape": (27, "Escape"),
         "esc": (27, "Escape"), "backspace": (8, "Backspace"), "delete": (46, "Delete")}


def _bezier(p0: float, p1: float, p2: float, p3: float, t: float) -> float:
    """One coordinate of a cubic Bezier at parameter t - used to trace a curved (human-looking) mouse path
    rather than a dead-straight line between two points."""
    u = 1 - t
    return u * u * u * p0 + 3 * u * u * t * p1 + 3 * u * t * t * p2 + t * t * t * p3


# Response bodies are captured only for API-ish content types (skip images/fonts/css/html shells) and capped,
# so the flow log stays a readable record of the app's API traffic rather than a dump of every asset.
_API_MIME = ("json", "xml", "graphql", "x-www-form-urlencoded", "text/plain", "javascript")
_BODY_CAP = 4000

# Pure static-asset resource types, skipped from the default proxy-like "requests" surface view (a page pulls
# dozens of them); requests:all brings them back.
_STATIC_TYPES = {"image", "stylesheet", "font", "media", "manifest", "texttrack",
                 "cspviolationreport", "ping", "prefetch", "signedexchange"}


class Chrome:
    """A headless chromium page driven over CDP. Context manager; one tab."""

    def __init__(self, headers: dict | None = None, timeout: int = 45, debug=lambda _m: None,
                 viewport: tuple | None = None):
        self.headers = headers or {}
        self.timeout = timeout
        self._dbg = debug
        # a fixed viewport at deviceScaleFactor=1 (for the visual driver): 1 screenshot px == 1 CSS px == the
        # x,y we hand to Input.dispatchMouseEvent, so a coordinate the model reads off the grid clicks true.
        self.viewport = viewport
        self._cursor = None                            # logical mouse position, for continuous human motion
        self._proc = None
        self._ws = None
        self._wsmod = None
        self._profile = None
        self._id = 0
        self._requests: list[tuple[str, str]] = []     # (method, url) for XHR/fetch, ordered, deduped
        self._seen: set[tuple[str, str]] = set()
        self._inflight: set[str] = set()
        self._last_activity = 0.0
        self._nav_status = None
        # full request/response flow log for XHR/fetch, keyed by CDP requestId, insertion-ordered. Lets an
        # agent SEE what the app actually sent and got back (method/url/status/bodies), not just a URL list.
        self._flows: dict[str, dict] = {}
        self._flow_order: list[str] = []
        # lightweight log of EVERY request (all resource types) - the proxy-like view: what the page talked to,
        # incl. requests scripts make on their own, third-party backends, redirects. No bodies (see _flows).
        self._reqs: dict[str, dict] = {}
        self._req_order: list[str] = []

    # -- lifecycle -----------------------------------------------------------
    def __enter__(self) -> "Chrome":
        exe = chromium_path()
        if not exe:
            raise CDPError("chromium not found (set CHROMIUM_PATH or install chromium)")
        try:
            import websocket  # websocket-client; lazy so a missing dep degrades instead of breaking import
        except Exception:  # noqa: BLE001
            raise CDPError("websocket-client is not installed (browser tools are full-image tools)")
        self._wsmod = websocket
        port = _free_port()
        self._profile = fsutil.temp_dir("cdp_")
        cmd = [exe, "--headless", "--disable-gpu", "--no-sandbox", "--disable-dev-shm-usage",
               "--no-first-run", "--no-default-browser-check", "--disable-extensions",
               "--remote-allow-origins=*", f"--remote-debugging-port={port}",
               f"--user-data-dir={self._profile}", "about:blank"]
        if self.viewport:
            cmd.insert(-1, f"--window-size={self.viewport[0]},{self.viewport[1]}")
            cmd.insert(-1, "--force-device-scale-factor=1")
        self._dbg("cdp: launching chromium")
        self._proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        ws_url = self._discover(port)
        self._ws = websocket.create_connection(ws_url, timeout=10, suppress_origin=True)
        self._cmd("Page.enable")
        self._cmd("Network.enable")
        self._cmd("Runtime.enable")
        self._cmd("Page.addScriptToEvaluateOnNewDocument", {"source": _STEALTH_JS})
        ua = self._real_user_agent()
        if ua:
            self._cmd("Network.setUserAgentOverride", {"userAgent": ua})
        if self.headers:
            self._cmd("Network.setExtraHTTPHeaders", {"headers": self.headers})
        if self.viewport:
            w, h = self.viewport
            with contextlib.suppress(CDPError):
                self._cmd("Emulation.setDeviceMetricsOverride",
                          {"width": w, "height": h, "deviceScaleFactor": 1, "mobile": False})
            self._cursor = (w // 2, h // 2)            # start the pointer at viewport centre
        return self

    def _real_user_agent(self) -> str:
        """The literal string "HeadlessChrome" in the default UA is itself a bot-detection signal most WAFs
        check for. Ask Chromium for its actual UA and report the ordinary-Chrome form instead - the browser's
        real behaviour is unchanged, only the advertised name."""
        try:
            ua = (self._cmd("Browser.getVersion") or {}).get("userAgent", "")
        except CDPError:
            return ""
        return ua.replace("HeadlessChrome/", "Chrome/")

    def __exit__(self, *_exc):
        if self._ws:
            with contextlib.suppress(Exception):
                self._ws.close()
        if self._proc:
            with contextlib.suppress(Exception):
                self._proc.terminate()
                self._proc.wait(timeout=5)
            with contextlib.suppress(Exception):
                self._proc.kill()
        if self._profile:
            fsutil.remove_dir(self._profile)
        return False

    def _alive(self) -> bool:
        """True while the browser is still usable - the websocket is open and the chromium process is up. Lets
        a persistent-session holder detect a crashed/closed browser and reopen instead of handing back a dead one."""
        return bool(self._ws) and bool(self._proc) and self._proc.poll() is None

    def _discover(self, port: int) -> str:
        """Poll the debug HTTP endpoint until a 'page' target exposes its WebSocket URL."""
        deadline = time.monotonic() + 15
        last = ""
        while time.monotonic() < deadline:
            try:
                raw = urllib.request.urlopen(f"http://127.0.0.1:{port}/json", timeout=1.0).read()
                for t in json.loads(raw):
                    if t.get("type") == "page" and t.get("webSocketDebuggerUrl"):
                        return t["webSocketDebuggerUrl"]
            except Exception as exc:  # noqa: BLE001 - chromium still starting up
                last = str(exc)
            time.sleep(0.2)
        raise CDPError(f"chromium debug endpoint never came up on :{port} ({last})")

    # -- protocol ------------------------------------------------------------
    def _on_event(self, method: str, params: dict) -> None:
        if method == "Network.requestWillBeSent":
            rtype = (params.get("type") or "").lower()
            req = params.get("request") or {}
            rid = params.get("requestId")
            if rid:
                self._inflight.add(rid)
            self._last_activity = time.monotonic()
            url = (req.get("url") or "").split("#")[0]
            if url and rid and rid not in self._reqs and url.startswith(("http://", "https://", "ws")):
                self._reqs[rid] = {"method": req.get("method", "GET"), "url": url,
                                   "type": rtype or "other", "status": None, "size": 0}
                self._req_order.append(rid)
            if rtype in ("xhr", "fetch"):
                key = (req.get("method", "GET"), url)
                if key[1] and key not in self._seen:
                    self._seen.add(key)
                    self._requests.append(key)
                if rid and url and rid not in self._flows:
                    hdrs = req.get("headers") or {}
                    # the Authorization header the SPA sends to its API (a bearer JWT) IS the session artifact for
                    # a token-based app - capture it so auth can lift and reuse it, not just cookies.
                    auth = next((str(v) for k, v in hdrs.items() if k.lower() == "authorization"), "")
                    self._flows[rid] = {
                        "method": req.get("method", "GET"), "url": url, "type": rtype,
                        "req_body": (req.get("postData") or "")[:_BODY_CAP], "req_auth": auth[:1400],
                        "status": None, "mime": "", "resp_body": None,
                        "_finished": False, "_body_done": False,
                    }
                    self._flow_order.append(rid)
        elif method in ("Network.loadingFinished", "Network.loadingFailed"):
            rid = params.get("requestId")
            self._inflight.discard(rid)
            self._last_activity = time.monotonic()
            if rid in self._flows:
                self._flows[rid]["_finished"] = True
            if rid in self._reqs and method == "Network.loadingFinished":
                self._reqs[rid]["size"] = int(params.get("encodedDataLength") or 0)
        elif method == "Network.responseReceived":
            resp = params.get("response") or {}
            if (params.get("type") or "") == "Document" and self._nav_status is None:
                self._nav_status = resp.get("status")
            rid = params.get("requestId")
            if rid in self._reqs:
                self._reqs[rid]["status"] = resp.get("status")
            if rid in self._flows:
                self._flows[rid]["status"] = resp.get("status")
                self._flows[rid]["mime"] = (resp.get("mimeType") or "").lower()

    def _recv(self, deadline: float):
        """Next protocol message (dict), or None on a recv timeout before the deadline."""
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        self._ws.settimeout(remaining)
        try:
            data = self._ws.recv()
        except self._wsmod.WebSocketTimeoutException:
            return None
        except self._wsmod.WebSocketConnectionClosedException:
            raise CDPError("websocket closed by browser")
        if isinstance(data, bytes):
            data = data.decode("utf-8", "replace")
        if not data:
            return None
        return json.loads(data)

    def _cmd(self, method: str, params: dict | None = None, timeout: float | None = None):
        self._id += 1
        mid = self._id
        self._ws.send(json.dumps({"id": mid, "method": method, "params": params or {}}))
        deadline = time.monotonic() + (timeout if timeout is not None else self.timeout)
        while True:
            msg = self._recv(deadline)
            if msg is None:
                raise CDPError(f"{method}: timed out")
            if msg.get("id") == mid:
                if "error" in msg:
                    raise CDPError(f"{method}: {msg['error'].get('message', msg['error'])}")
                return msg.get("result", {})
            if "method" in msg:
                self._on_event(msg["method"], msg.get("params") or {})

    # -- navigation / waiting ------------------------------------------------
    def navigate(self, url: str, wait: str = "networkidle", timeout: int | None = None):
        self._nav_status = None
        self._cmd("Page.navigate", {"url": url}, timeout=timeout or self.timeout)
        if wait == "networkidle":
            self._wait_idle(time.monotonic() + (timeout or self.timeout))
        else:
            self._pump(time.monotonic() + min(5, timeout or self.timeout))
        return self._nav_status

    def _wait_idle(self, deadline: float) -> None:
        """Pump events until no in-flight request for 0.5s, or the deadline."""
        self._last_activity = time.monotonic()
        while time.monotonic() < deadline:
            msg = self._recv(min(deadline, time.monotonic() + 0.4))
            if msg is None:
                if not self._inflight and (time.monotonic() - self._last_activity) > 0.5:
                    return
                continue
            if "method" in msg:
                self._on_event(msg["method"], msg.get("params") or {})

    def _pump(self, deadline: float) -> None:
        """Drain events (capturing network) until the deadline - used for fixed waits."""
        while time.monotonic() < deadline:
            msg = self._recv(deadline)
            if msg is None:
                return
            if "method" in msg:
                self._on_event(msg["method"], msg.get("params") or {})

    # -- evaluation / DOM ----------------------------------------------------
    def eval(self, expression: str, timeout: float | None = None):
        r = self._cmd("Runtime.evaluate",
                      {"expression": expression, "returnByValue": True, "awaitPromise": True},
                      timeout=timeout)
        if r.get("exceptionDetails"):
            exc = r["exceptionDetails"]
            raise CDPError((exc.get("exception") or {}).get("description") or exc.get("text") or "eval error")
        return (r.get("result") or {}).get("value")

    def eval_fn(self, fn_src: str):
        """Evaluate a `() => {...}` / `function(){...}` source by invoking it."""
        return self.eval(f"({fn_src})()")

    def _act(self, find: str, body: str) -> None:
        self.eval(f"(()=>{{const e={find}; if(!e) throw new Error('element not found'); {body}}})()")

    def click(self, selector: str) -> None:
        self._act(_find_expr(selector), "e.click();")

    def fill(self, selector: str, value: str) -> None:
        self._act(_find_expr(selector),
                  f"e.focus(); e.value={json.dumps(value)}; "
                  "e.dispatchEvent(new Event('input',{bubbles:true})); "
                  "e.dispatchEvent(new Event('change',{bubbles:true}));")

    def select(self, selector: str, value: str) -> None:
        self._act(_find_expr(selector),
                  f"e.value={json.dumps(value)}; e.dispatchEvent(new Event('change',{{bubbles:true}}));")

    def set_checked(self, selector: str, checked: bool) -> None:
        self._act(_find_expr(selector),
                  f"e.checked={'true' if checked else 'false'}; "
                  "e.dispatchEvent(new Event('change',{bubbles:true}));")

    def hover(self, selector: str) -> None:
        self._act(_find_expr(selector), "e.dispatchEvent(new MouseEvent('mouseover',{bubbles:true}));")

    def dblclick(self, selector: str) -> None:
        self._act(_find_expr(selector),
                  "e.dispatchEvent(new MouseEvent('dblclick',{bubbles:true})); e.click();")

    def scroll(self, where: str) -> None:
        w = where.strip().lower()
        if w == "bottom":
            self.eval("window.scrollTo(0, document.body.scrollHeight)")
        elif w == "top":
            self.eval("window.scrollTo(0, 0)")
        elif "," in w:
            x, y = w.split(",", 1)
            self.eval(f"window.scrollTo({int(x)}, {int(y)})")

    def wait(self, ms: int) -> None:
        self._pump(time.monotonic() + max(0, ms) / 1000.0)

    def waitfor(self, selector: str, timeout: float | None = None) -> None:
        deadline = time.monotonic() + (timeout or self.timeout)
        find = _find_expr(selector)
        while time.monotonic() < deadline:
            if self.eval(f"!!({find})"):
                return
            self.wait(200)
        raise CDPError(f"waitfor: '{selector}' never appeared")

    def press(self, key: str, selector: str | None = None) -> None:
        if selector:
            self._act(_find_expr(selector), "e.focus();")
        code, keyname = _KEYS.get(key.strip().lower(), (0, key))
        base = {"key": keyname, "windowsVirtualKeyCode": code, "nativeVirtualKeyCode": code}
        self._cmd("Input.dispatchKeyEvent", {"type": "keyDown", **base})
        if len(key) == 1:
            self._cmd("Input.dispatchKeyEvent", {"type": "char", "text": key})
        self._cmd("Input.dispatchKeyEvent", {"type": "keyUp", **base})

    # -- reads ---------------------------------------------------------------
    def xhr(self) -> list[tuple[str, str]]:
        return list(self._requests)

    def flow_marker(self) -> int:
        """The current end of the flow log - pass it to flows(since=marker) later to get only the traffic a
        subsequent action produced (so each turn sees just its own new request/response activity)."""
        return len(self._flow_order)

    def _collect_bodies(self) -> None:
        """Fetch response bodies for finished API flows that don't have one yet. Called at a SAFE point (after
        an action has settled), NEVER from inside the event pump - getResponseBody is an ordinary command, so
        doing it here avoids re-entrant pumping. Bodies evict over time, so this runs promptly after actions."""
        for rid in self._flow_order:
            f = self._flows.get(rid)
            if not f or f["_body_done"] or not f["_finished"]:
                continue
            f["_body_done"] = True
            if not any(tok in (f.get("mime") or "") for tok in _API_MIME):
                continue
            try:
                r = self._cmd("Network.getResponseBody", {"requestId": rid}, timeout=5)
            except CDPError:
                continue
            if r.get("base64Encoded"):       # binary payload - not useful as text, skip
                continue
            f["resp_body"] = (r.get("body") or "")[:_BODY_CAP]

    def flows(self, since: int = 0) -> list[dict]:
        """The captured XHR/fetch flows from index `since` onward - each a request+response record
        (method/url/status + request/response bodies for API content types). Populates bodies first."""
        self._collect_bodies()
        out = []
        for rid in self._flow_order[since:]:
            f = self._flows[rid]
            rec = {"type": "flow", "method": f["method"], "url": f["url"], "status": f["status"]}
            if f.get("req_auth"):
                rec["req_auth"] = f["req_auth"]        # the Authorization/bearer the app sent (session artifact)
            if f["req_body"]:
                rec["req_body"] = f["req_body"]
            if f["resp_body"] is not None:
                rec["resp_body"] = f["resp_body"]
            out.append(rec)
        return out

    def requests(self, include_all: bool = False) -> list[dict]:
        """The lightweight log of EVERY request the page has made this session (method/url/status/type/size) -
        the proxy-like view. Static assets (images/fonts/css/...) are skipped unless include_all."""
        out = []
        for rid in self._req_order:
            r = self._reqs.get(rid)
            if not r or (not include_all and r["type"] in _STATIC_TYPES):
                continue
            out.append({"method": r["method"], "url": r["url"], "status": r["status"],
                        "type": r["type"], "size": r["size"]})
        return out

    def request_summary(self, spec: str = "") -> dict:
        """A proxy-like view of everything the page talked to, for an agent to explore. Default ('' or
        'surface') returns a host->count map of the meaningful requests (static assets skipped) so the whole
        backend + third-party surface is visible at a glance; 'all' includes assets in the map; 'api' lists the
        xhr/fetch calls; any other value is treated as a hostname substring and lists that host's requests."""
        spec = (spec or "").strip()
        low = spec.lower()
        if low in ("", "surface", "all"):
            reqs = self.requests(include_all=(low == "all"))
            by_host: dict = {}
            for r in reqs:
                h = urlparse(r["url"]).hostname or "?"
                by_host[h] = by_host.get(h, 0) + 1
            return {"total": len(reqs),
                    "by_host": dict(sorted(by_host.items(), key=lambda kv: (-kv[1], kv[0]))),
                    "hint": "requests:<host> to list one host; requests:api for xhr/fetch; requests:all incl assets"}
        reqs = self.requests(include_all=True)
        if low == "api":
            reqs = [r for r in reqs if r.get("type") in ("xhr", "fetch")]
        else:
            reqs = [r for r in reqs if low in (urlparse(r["url"]).hostname or "").lower()]
        return {"matched": len(reqs), "requests": reqs}

    def links(self, same_host: str | None = None) -> list[str]:
        hrefs = self.eval("Array.from(document.querySelectorAll('a[href]')).map(a=>a.href)") or []
        out, seen = [], set()
        for h in hrefs:
            if not isinstance(h, str) or not h.startswith(("http://", "https://")):
                continue
            h = h.split("#")[0]
            if same_host and (urlparse(h).hostname or "") != same_host:
                continue
            if h not in seen:
                seen.add(h)
                out.append(h)
        return out

    def cookies(self) -> str:
        r = self._cmd("Network.getCookies")
        return "; ".join(f"{c['name']}={c['value']}" for c in (r.get("cookies") or []))

    def title(self) -> str:
        return self.eval("document.title") or ""

    def current_url(self) -> str:
        return self.eval("location.href") or ""

    def element_at(self, x: int, y: int) -> dict | None:
        """A short descriptor of the element at viewport point (x,y) via document.elementFromPoint - so a
        coordinate click can report WHAT it actually hit (button 'Accept all', input#email, ...), turning a
        blind coordinate into a verifiable one. None if nothing is there."""
        try:
            return self.eval(
                "(()=>{const e=document.elementFromPoint(%d,%d);if(!e)return null;"
                "const t=(e.innerText||e.value||e.getAttribute('aria-label')||e.getAttribute('placeholder')"
                "||'').replace(/\\s+/g,' ').trim().slice(0,50);"
                "return {tag:e.tagName.toLowerCase(),id:e.id||'',type:e.type||'',"
                "role:e.getAttribute('role')||'',text:t};})()" % (int(x), int(y)))
        except CDPError:
            return None

    def find_text(self, text: str) -> dict | None:
        """Find the first VISIBLE interactive element whose text/label matches `text` (case-insensitive
        substring), preferring the SMALLEST match (the actual control, not a big container). Returns its center
        coordinate + a descriptor, or None. Lets an agent aim at 'Log in' by NAME instead of guessing pixels -
        and it's the reliable way to tell 'Log in' apart from 'Sign up'/'Create account'."""
        q = (text or "").strip().lower()
        if not q:
            return None
        try:
            return self.eval(
                "(()=>{const q=%s;"
                "const els=[...document.querySelectorAll('button,a,[role=button],[role=link],input,textarea,"
                "select,label,[tabindex]')];let best=null,ba=1e18;"
                "for(const e of els){if(e.offsetParent===null)continue;"
                # match on visible text, value, aria-label, placeholder, name, or (for inputs) the type - so
                # `find:email`/`find:password` locate the login FIELDS by name, not just buttons by their text.
                "const t=((e.innerText||e.value||e.getAttribute('aria-label')||e.placeholder||e.name||"
                "(e.tagName==='INPUT'?e.type:'')||'').replace(/\\s+/g,' ').trim());"
                "if(!t||!t.toLowerCase().includes(q))continue;"
                "const r=e.getBoundingClientRect();if(r.width<=0||r.height<=0)continue;"
                "const a=r.width*r.height;if(a<ba){ba=a;best={x:Math.round(r.left+r.width/2),"
                "y:Math.round(r.top+r.height/2),tag:e.tagName.toLowerCase(),type:e.type||'',text:t.slice(0,50)};}}"
                "return best;})()" % json.dumps(q))
        except CDPError:
            return None

    def screenshot(self) -> bytes:
        """Capture the current page as PNG bytes (Page.captureScreenshot). Lets an agent SEE what is
        rendered right now - the real login form, an unexpected consent/MFA/error screen, a CSS-in-JS theme
        with no usable field ids - instead of reasoning blind from the DOM alone. Returns b'' if the browser
        hands back nothing."""
        r = self._cmd("Page.captureScreenshot", {"format": "png", "captureBeyondViewport": False})
        data = r.get("data") or ""
        return base64.b64decode(data) if data else b""

    # -- human-like coordinate input (the visual driver) ---------------------
    # The agent decides WHERE (an x,y read off the coordinate grid); these decide HOW - a real, trusted mouse
    # that MOVES to the target along a curved, eased path (never a teleport), because a straight jump / a click
    # with no motion is itself a bot tell. Every event is isTrusted (it comes through Input.*, not JS).
    def _vw(self) -> tuple:
        return self.viewport or (1280, 800)

    def human_move(self, x: float, y: float, buttons: int = 0) -> None:
        w, h = self._vw()
        x = max(0, min(int(x), w - 1))
        y = max(0, min(int(y), h - 1))
        if self._cursor is None:
            self._cursor = (w // 2, h // 2)
        x0, y0 = self._cursor
        dist = math.hypot(x - x0, y - y0)
        steps = max(8, min(28, int(dist / 14) + 6))
        off = min(90.0, dist * 0.22)                   # lateral bow of the curve
        cx1 = x0 + (x - x0) * 0.33 + random.uniform(-off, off)
        cy1 = y0 + (y - y0) * 0.33 + random.uniform(-off, off)
        cx2 = x0 + (x - x0) * 0.66 + random.uniform(-off, off)
        cy2 = y0 + (y - y0) * 0.66 + random.uniform(-off, off)
        pause_at = random.randint(2, steps) if (dist > 120 and random.random() < 0.4) else -1
        for i in range(1, steps + 1):
            t = i / steps
            te = t * t * (3 - 2 * t)                    # ease in-out (accelerate then decelerate)
            px = _bezier(x0, cx1, cx2, x, te) + random.uniform(-1.0, 1.0)
            py = _bezier(y0, cy1, cy2, y, te) + random.uniform(-1.0, 1.0)
            self._cmd("Input.dispatchMouseEvent", {"type": "mouseMoved", "x": px, "y": py, "buttons": buttons})
            self.wait(random.randint(120, 260) if i == pause_at else random.randint(6, 16))
        if dist > 40 and random.random() < 0.45:        # occasional overshoot then correction, like a real hand
            self._cmd("Input.dispatchMouseEvent", {"type": "mouseMoved",
                      "x": x + random.randint(-7, 7), "y": y + random.randint(-7, 7), "buttons": buttons})
            self.wait(random.randint(40, 110))
        self._cmd("Input.dispatchMouseEvent", {"type": "mouseMoved", "x": x, "y": y, "buttons": buttons})
        self._cursor = (x, y)

    def wander(self, seconds: float = 3.0) -> None:
        """Human-like IDLE mouse activity - drift the cursor around the viewport along curved paths with
        pauses, NO click. Builds a believable behavioural history for a score/behaviour-based bot check
        (reCAPTCHA v3, Turnstile's behaviour signal). It does NOT defeat environment/headless fingerprinting."""
        w, h = self._vw()
        end = time.monotonic() + max(0.5, min(float(seconds), 20.0))
        while time.monotonic() < end:
            self.human_move(random.randint(int(w * 0.12), int(w * 0.88)),
                            random.randint(int(h * 0.12), int(h * 0.88)))
            self.wait(random.randint(150, 550))         # dwell between drifts

    def human_click(self, x: float, y: float, button: str = "left", clicks: int = 1) -> None:
        self.human_move(x, y)
        cx, cy = self._cursor
        self.wait(random.randint(30, 90))              # dwell before pressing
        self._cmd("Input.dispatchMouseEvent", {"type": "mousePressed", "x": cx, "y": cy,
                                               "button": button, "buttons": 1, "clickCount": clicks})
        self.wait(random.randint(40, 110))
        self._cmd("Input.dispatchMouseEvent", {"type": "mouseReleased", "x": cx, "y": cy,
                                               "button": button, "buttons": 0, "clickCount": clicks})

    def human_drag(self, x1: float, y1: float, x2: float, y2: float, button: str = "left") -> None:
        """Press at (x1,y1), MOVE to (x2,y2) with the button held (curved, human motion), then release - a real
        click-and-drag (slider captchas, drag-and-drop). The move dispatches with buttons=1 so the page sees a
        genuine drag, not a teleport."""
        self.human_move(x1, y1)
        px, py = self._cursor
        self.wait(random.randint(40, 90))
        self._cmd("Input.dispatchMouseEvent", {"type": "mousePressed", "x": px, "y": py,
                                               "button": button, "buttons": 1, "clickCount": 1})
        self.wait(random.randint(60, 130))
        self.human_move(x2, y2, buttons=1)             # drag while holding the button down
        dx, dy = self._cursor
        self.wait(random.randint(50, 110))
        self._cmd("Input.dispatchMouseEvent", {"type": "mouseReleased", "x": dx, "y": dy,
                                               "button": button, "buttons": 0, "clickCount": 1})

    def human_type(self, text: str) -> None:
        """Type a string with real, trusted per-key events and jittered inter-key delays (instant value-set is
        a bot tell). Whatever element the last click focused receives it."""
        for ch in text:
            self._cmd("Input.dispatchKeyEvent", {"type": "keyDown", "key": ch, "text": ch})
            self._cmd("Input.dispatchKeyEvent", {"type": "keyUp", "key": ch})
            self.wait(random.randint(40, 130))

    def focused_value(self) -> str:
        """The `.value` of the currently focused input/textarea (document.activeElement), or '' if nothing is
        focused or it isn't a value-bearing field. Lets a caller VERIFY a typed value actually landed in a
        field; the caller MUST mask it (report length/landed, never echo a password into output)."""
        try:
            return self.eval_fn(
                "() => { const e = document.activeElement; "
                "return e && ('value' in e) ? String(e.value || '') : ''; }") or ""
        except CDPError:
            return ""

    def storage_dump(self) -> dict:
        """All of localStorage and sessionStorage as {'local': {...}, 'session': {...}} - the full client-side
        auth state, so an authenticated session can be CAPTURED for reuse (many SPAs keep their bearer/JWT and
        user context here, not just in cookies). Best-effort: {} on failure/denied access."""
        js = ("() => { const dump = s => { const o = {}; try { for (let i = 0; i < s.length; i++) { "
              "const k = s.key(i); o[k] = s.getItem(k); } } catch (e) {} return o; }; "
              "return { local: dump(window.localStorage), session: dump(window.sessionStorage) }; }")
        try:
            val = self.eval_fn(js)
            return val if isinstance(val, dict) else {}
        except CDPError:
            return {}

    def clear_field(self) -> None:
        """Empty the focused input: select-all (Ctrl+A) then Delete, via trusted key events - so a pre-filled
        field is cleared before you type into it (put/type otherwise appends)."""
        for phase in ("keyDown", "keyUp"):             # Ctrl+A
            self._cmd("Input.dispatchKeyEvent", {"type": phase, "key": "a", "code": "KeyA",
                                                 "windowsVirtualKeyCode": 65, "modifiers": 2})
        self.wait(random.randint(20, 50))
        for phase in ("keyDown", "keyUp"):             # Delete
            self._cmd("Input.dispatchKeyEvent", {"type": phase, "key": "Delete", "code": "Delete",
                                                 "windowsVirtualKeyCode": 46})

    def wheel(self, dy: int, x: float | None = None, y: float | None = None) -> None:
        w, h = self._vw()
        cx, cy = self._cursor or (w // 2, h // 2)
        self._cmd("Input.dispatchMouseEvent", {"type": "mouseWheel", "x": x if x is not None else cx,
                                               "y": y if y is not None else cy, "deltaX": 0, "deltaY": dy})

    def add_grid(self, minor: int = 50, major: int = 100) -> None:
        """Overlay a semi-transparent coordinate grid (labeled every `major` px, in the margins) so the model
        can read an element's x,y straight off the screenshot. Removed again by remove_grid()."""
        self.eval(
            "(()=>{const id='__bc_grid__';const o=document.getElementById(id);if(o)o.remove();"
            "const W=innerWidth,H=innerHeight,c=document.createElement('canvas');"
            "c.id=id;c.width=W;c.height=H;c.style.cssText='position:fixed;left:0;top:0;width:'+W+'px;height:'+H"
            "+'px;z-index:2147483647;pointer-events:none';const g=c.getContext('2d');g.font='10px monospace';"
            f"for(let x=0;x<=W;x+={minor}){{g.strokeStyle=x%{major}===0?'rgba(255,0,0,.35)':'rgba(255,0,0,.12)';"
            "g.beginPath();g.moveTo(x,0);g.lineTo(x,H);g.stroke();"
            f"if(x%{major}===0){{g.fillStyle='rgba(255,0,0,.85)';g.fillText(x,x+1,10);}}}}"
            f"for(let y=0;y<=H;y+={minor}){{g.strokeStyle=y%{major}===0?'rgba(255,0,0,.35)':'rgba(255,0,0,.12)';"
            "g.beginPath();g.moveTo(0,y);g.lineTo(W,y);g.stroke();"
            f"if(y%{major}===0){{g.fillStyle='rgba(255,0,0,.85)';g.fillText(y,1,y+10);}}}}"
            "document.body.appendChild(c);})()")

    def remove_grid(self) -> None:
        with contextlib.suppress(CDPError):
            self.eval("(()=>{const o=document.getElementById('__bc_grid__');if(o)o.remove();})()")

    # Marking each handled element with data-bc-done (rather than a positional snapshot taken once) means
    # clickable()/click_nth() always operate on the LIVE, remaining set - so newly revealed content (e.g.
    # behind a just-dismissed cookie banner) gets explored too, and the count never goes stale as the DOM
    # changes underneath a click.
    _CLICKABLE_SEL = ("button:not([data-bc-done]), [role=button]:not([data-bc-done]), "
                      "a[href]:not([data-bc-done]), input[type=submit]:not([data-bc-done]), "
                      "input[type=button]:not([data-bc-done])")

    def clickable(self, limit: int) -> int:
        """How many not-yet-handled clickable elements exist right now (bounds the auto-crawler's loop)."""
        n = self.eval(f"document.querySelectorAll({json.dumps(self._CLICKABLE_SEL)}).length") or 0
        return min(int(n), limit)

    def peek_nth(self, index: int) -> str:
        """The index-th not-yet-handled clickable element's visible label, WITHOUT clicking or marking it -
        so the caller can veto a dangerous-looking action (logout/delete/pay) before it's ever clicked."""
        return self.eval(
            f"(()=>{{const els=document.querySelectorAll({json.dumps(self._CLICKABLE_SEL)});"
            f"const e=els[{index}]; if(!e) return null;"
            "return (e.innerText||e.textContent||e.value||'').trim();})()") or ""

    def mark_done(self, index: int) -> None:
        """Mark the index-th not-yet-handled element done WITHOUT clicking it - used to skip past an action
        the caller vetoed (via peek_nth) while still making forward progress."""
        self.eval(
            f"(()=>{{const els=document.querySelectorAll({json.dumps(self._CLICKABLE_SEL)});"
            f"const e=els[{index}]; if(e) e.setAttribute('data-bc-done','1');}})()")

    def click_nth(self, index: int) -> str:
        """Click the index-th not-yet-handled clickable element (marked done FIRST, since the click itself
        may navigate away); returns its visible label (or '')."""
        return self.eval(
            f"(()=>{{const els=document.querySelectorAll({json.dumps(self._CLICKABLE_SEL)});"
            f"const e=els[{index}]; if(!e) return null; e.setAttribute('data-bc-done','1');"
            "const t=(e.innerText||e.textContent||e.value||'').trim();"
            "try{e.click();}catch(_){}; return t;})()") or ""

    _FILLABLE_SEL = ("input:not([type]):not([data-bc-done]), input[type=text]:not([data-bc-done]), "
                     "input[type=search]:not([data-bc-done]), input[type=email]:not([data-bc-done]), "
                     "input[type=tel]:not([data-bc-done]), textarea:not([data-bc-done])")

    def fillable(self, limit: int) -> int:
        """How many empty, visible, not-yet-filled text-like inputs exist right now."""
        n = self.eval(
            f"Array.from(document.querySelectorAll({json.dumps(self._FILLABLE_SEL)}))"
            ".filter(e=>!e.value && e.offsetParent!==null).length") or 0
        return min(int(n), limit)

    def fill_nth(self, index: int) -> str:
        """Fill the index-th empty, visible text-like input with a value inferred from its type/name/
        placeholder/autocomplete (falling back to a generic probe), mark it done, and return what was typed
        ('' if no such input remains) - many SPA landing pages ('enter your address to see what's near you')
        never call their real API until a search/address field is submitted; clicking alone never reaches it."""
        return self.eval(
            f"(()=>{{const els=Array.from(document.querySelectorAll({json.dumps(self._FILLABLE_SEL)}))"
            ".filter(e=>!e.value && e.offsetParent!==null);"
            "const e=els[" + str(index) + "]; if(!e) return '';"
            f"const hints={json.dumps(_FILL_HINTS)};"
            "const sig=((e.name||'')+' '+(e.placeholder||'')+' '+(e.autocomplete||'')+' '+e.type).toLowerCase();"
            "let val=hints._default;"
            "for (const k in hints) { if (k!=='_default' && sig.includes(k)) { val=hints[k]; break; } }"
            "e.setAttribute('data-bc-done','1'); e.focus(); e.value=val;"
            "e.dispatchEvent(new Event('input',{bubbles:true}));"
            "e.dispatchEvent(new Event('change',{bubbles:true}));"
            "return val;})()") or ""

    def describe_form(self) -> list:
        """Structured snapshot of visible interactive elements on the CURRENT page - tag/type/name/id/
        placeholder/aria-label/text, plus a best-effort STABLE css selector for each (id > name > aria-label >
        placeholder > type > nth-of-type-within-parent). For a login form with no usable id/name on its
        fields (common with obfuscated/generated CSS-in-JS themes, or a multi-step identifier-first flow where
        the right field isn't obvious), this lets an agent actually SEE the page structure and pick the right
        selector instead of guessing - the selector survives a FRESH reload of the same static page, so it can
        be computed in one browser-actions call and used in a later one."""
        return self.eval("""
        (() => {
          function cssFor(e) {
            if (e.id) return '#' + CSS.escape(e.id);
            if (e.name) return e.tagName.toLowerCase() + '[name="' + e.name.replace(/"/g, '\\\\"') + '"]';
            const aria = e.getAttribute('aria-label');
            if (aria) return e.tagName.toLowerCase() + '[aria-label="' + aria.replace(/"/g, '\\\\"') + '"]';
            if (e.placeholder) return e.tagName.toLowerCase() + '[placeholder="' + e.placeholder.replace(/"/g, '\\\\"') + '"]';
            if (e.type) return e.tagName.toLowerCase() + '[type="' + e.type + '"]';
            const sibs = Array.from(e.parentElement ? e.parentElement.children : []).filter(s => s.tagName === e.tagName);
            return e.tagName.toLowerCase() + ':nth-of-type(' + (sibs.indexOf(e) + 1) + ')';
          }
          const els = Array.from(document.querySelectorAll('input, textarea, select, button, a[href], [role=button]'));
          return els.filter(e => e.offsetParent !== null).slice(0, 40).map(e => ({
            tag: e.tagName.toLowerCase(), type: e.type || '', name: e.name || '', id: e.id || '',
            placeholder: e.placeholder || '', aria_label: e.getAttribute('aria-label') || '',
            text: (e.innerText || e.value || '').trim().slice(0, 60), css: cssFor(e),
          }));
        })()
        """) or []


# -- persistent sessions -----------------------------------------------------
# A human working with an app keeps ONE browser open across many actions - it stays logged in, the SPA keeps
# its route and in-memory state. IRVIN runs a whole engagement in ONE process, so a persistent session is just
# a reused Chrome kept in this registry (no server/proxy process). browser-actions --session S attaches to the
# live browser for S instead of spawning a fresh one; the caller closes it when the exploration is done.
_SESSIONS: dict[str, Chrome] = {}


def get_session(sid: str, headers: dict | None = None, timeout: int = 45,
                debug=lambda _m: None, viewport: tuple | None = None) -> tuple[Chrome, bool]:
    """The live Chrome for session id `sid`, opening one on first use (or if the previous one died). Returns
    (page, fresh) - fresh=True when it was just opened, so the caller knows to navigate to the start URL rather
    than continue from wherever the persistent session already is. `viewport` pins a fixed size + DPR=1 (used
    by the visual driver so screenshot pixels map 1:1 to click coordinates)."""
    page = _SESSIONS.get(sid)
    if page is not None and page._alive():
        return page, False
    if page is not None:
        with contextlib.suppress(Exception):
            page.__exit__(None, None, None)
    page = Chrome(headers=headers, timeout=timeout, debug=debug, viewport=viewport)
    page.__enter__()
    _SESSIONS[sid] = page
    return page, True


def close_session(sid: str) -> None:
    page = _SESSIONS.pop(sid, None)
    if page is not None:
        with contextlib.suppress(Exception):
            page.__exit__(None, None, None)


def close_all_sessions() -> None:
    """Tear down every persistent session - a safety net for the end of a run."""
    for sid in list(_SESSIONS):
        close_session(sid)
