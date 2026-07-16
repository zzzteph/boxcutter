"""juicy - a single-agent JS ANALYST. One job: take a URL - either a direct link to a JavaScript file OR a page
that loads JS - fetch the JavaScript, and squeeze it for (1) every HIDDEN URL/endpoint referenced inside it and
(2) any client-side XSS, each PROVEN with a WORKING, copy-pasteable PoC that pops alert(1) on the actual
resource where the code runs.

Given a PAGE, juicy discovers the JS it loads first (external <script src> bundles, same-origin first, plus the
inline <script> blocks), then analyses each. Given a direct .js it analyses that file straight away.

It is the read-only, static cousin of crawlio: crawlio DRIVES the app to observe live requests; juicy READS the
bundle's source and reasons about it. The value is the analysis a plain regex grep can't do - following how a
URL is CONSTRUCTED (base + path concatenation, template literals, a route table), and proving an XSS as a real
SOURCE -> SINK taint (location.hash reaching el.innerHTML) rather than flagging every `innerHTML=` as a bug.

Guarantees enforced in CODE (not just the prompt), same philosophy as crawlio's ghost gate:
  - DETERMINISTIC URL NET: every fetched JS body is regex-scanned with the shared js-endpoints patterns, and
    those URLs are UNIONED into the result - so a URL is never lost just because the model under-reported it.
  - A SINK IS NOT A FINDING: raw sink hits (innerHTML=, eval(, ...) are handed to the agent only as HINTS. An
    xss row is `vulnerable` only when the agent traces a controllable SOURCE into that sink AND builds a firing
    PoC; otherwise it is `unverifiable` (and carries no severity) - no source/no-PoC, no finding.
  - WINDOWED: a large minified bundle is fed to the model in overlapping windows so the WHOLE file is analysed,
    not just the head that fits one message; findings are accumulated across every window and every file.
  - BOUNDED: a per-file step cap + a shared http-request cache (identical fetches never re-run).

  boxcutter juicy https://site/static/app.js --provider litellm --model "openai/gpt-5.1" --api-key ... --base-url ...
  boxcutter juicy https://site/ --context "auth: send Cookie: session=abc"   # a page: its JS is discovered first

The DOM-XSS discipline is a strict confirm-don't-grep review (a sink is SAFE
until a tainted SOURCE is traced into it and a firing PoC constructs), the full source/sink taxonomy incl. the
indirect sinks (jQuery, postMessage RPC, prop-smuggling, JSONP, framework escape-hatches), the redirect-param
family, sanitizer-bypass payload craft, known-vulnerable libraries, and a vulnerable/unverifiable verdict with
a PoC-gated severity. A vulnerable LIBRARY (old jQuery/Bootstrap/...) is reported in a separate `libraries`
list, NOT faked into a finding - it becomes a finding only when the app is shown calling its dangerous API with
tainted input. It also HUNTS SECRETS (deterministic scan-secrets net + the ones only a human spots).

Budget: on a PAGE, app bundles get the full LLM taint analysis; vendor bundles (jQuery/polyfills/runtime) are
fingerprint-only (nets, no LLM) so the model's effort lands on the app's own code.

VERIFICATION (so the report is trustworthy, not just asserted): every XSS finding is anchored to the real bytes
(the exact code excerpt + file/offset/line) and then INDEPENDENTLY re-traced from scratch by a second, adversarial
pass (refute-by-default) that reasons over the actual code sliced around the sink/source. Its verdict -
confirmed / needs-review / refuted - is the authoritative signal; refuted false-positives are dropped. Turn it
off with --no-verify.

Output items (tagged by `type`): {type:"url", url, method, kind, params, note, file},
{type:"xss", class, severity, source, sink, trace, snippet, sanitizer, poc, persistent, confidence, note, file,
location:{file,offset,line}, evidence_excerpt, verification:{status,trace,evidence,poc,reason,method}}, and
{type:"secret", kind, match, severity, where, file, note}. The envelope also carries a `libraries` list.
`--table` prints a sectioned report - CONFIRMED findings as detailed, checkable blocks - instead of JSON.
"""

from __future__ import annotations

import json
import os
import re
import sys
from urllib.parse import urljoin, urlparse

from ..core import agentlog
from ..core.envelope import debug_logger, debug_print, output_result, write_report
from ..irvin import briefing
from ..irvin.context import extract_json
from ..irvin.provider import PROVIDERS, add_agent_args
from ..tools import toolschema
from ..tools.js_endpoints import PATTERNS as _JS_URL_PATTERNS, _should_skip as _skip_path
from ..tools.scan_secrets import _COMPILED as _SECRET_PATTERNS

NAME = "juicy"
KIND = "items"
HELP = "Single-agent JS analyst: from a JS file or page, extract hidden URLs, find DOM XSS + secrets, with PoCs."

# The tools the agent may drive (all read-only): fetch more source (lazy webpack chunks, imported modules, the
# sourceMappingURL original), run the cheap regex endpoint extractor on a discovered JS without pulling its whole
# body into context, and scan a URL's body for known-format secrets.
_TOOLS = ["http-request", "js-endpoints", "scan-secrets"]

# -- deterministic hint scan (SOURCES, SINKS, redirect params, vulnerable libs) -----------------------------
# These PRIME the model; they are NOT findings on their own. A client-side XSS needs a controllable SOURCE
# reaching a dangerous SINK with the framework's default escaping bypassed - the regex only says "these appear
# in the file", the agent proves the taint chain that connects a source to a sink. The taxonomy covers the
# standard client-side sources-and-sinks: direct sinks, the indirect ones that are
# easy to miss (jQuery, resource loading, postMessage RPC), the framework escape-hatches, and the redirect
# family. The regex survives minification because it keys on API names/strings the bundler does NOT rename
# (dangerouslySetInnerHTML, __html, bypassSecurityTrust*, insertAdjacentHTML, location, ...).
_SINKS = [
    ("innerHTML/outerHTML =", re.compile(r"\.(?:inner|outer)HTML\s*=(?!=)")),
    ("insertAdjacentHTML()", re.compile(r"\binsertAdjacentHTML\s*\(")),
    ("document.write()", re.compile(r"\bdocument\s*\.\s*write(?:ln)?\s*\(")),
    ("eval()", re.compile(r"\beval\s*\(")),
    ("new Function()", re.compile(r"\bnew\s+Function\s*\(|\bFunction\s*\(\s*['\"]")),
    ("setTimeout/Interval(string)", re.compile(r"\bset(?:Timeout|Interval)\s*\(\s*['\"`]")),
    ("jQuery .html/.append/.after", re.compile(r"\.(?:html|append|prepend|after|before|replaceWith|wrap)\s*\(")),
    ("jQuery $(var)/parseHTML/globalEval/getScript",
     re.compile(r"\$\s*\(\s*[A-Za-z_$][\w$]*\s*\)|\$\.(?:parseHTML|globalEval|getScript)\s*\(")),
    ("location = / assign / replace",
     re.compile(r"\blocation\s*(?:\.\s*(?:href|assign|replace))?\s*=(?!=)|\blocation\s*\.\s*(?:assign|replace)\s*\(")),
    ("window.open()", re.compile(r"\bwindow\s*\.\s*open\s*\(")),
    ("setAttribute(on*/href/src)", re.compile(r"\.setAttribute\s*\(\s*['\"`](?:on\w+|href|src|xlink:href|formaction)")),
    ("iframe.srcdoc =", re.compile(r"\.srcdoc\s*=(?!=)")),
    ("style.cssText =", re.compile(r"\.cssText\s*=(?!=)")),
    ("createContextualFragment/DOMParser", re.compile(r"\bcreateContextualFragment\s*\(|\bparseFromString\s*\(")),
    ("Worker/importScripts", re.compile(r"\bimportScripts\s*\(|new\s+Worker\s*\(")),
    ("React dangerouslySetInnerHTML/__html", re.compile(r"dangerouslySetInnerHTML|__html")),
    ("Vue v-html", re.compile(r"v-html\b")),
    ("Angular bypassSecurityTrust*/trustAs*", re.compile(r"\btrustAs(?:Html|Url|ResourceUrl|Js|Style)\b|"
                                                         r"bypassSecurityTrust\w*")),
    ("dispatch-by-name window[x]()/api[x]", re.compile(r"window\s*\[\s*[A-Za-z_$][\w$]*\s*\]\s*\(")),
]

_SOURCES = [
    ("location.hash/.search/.href/.pathname", re.compile(r"\blocation\s*\.\s*(?:hash|search|href|pathname)\b")),
    ("document.URL/referrer/cookie/baseURI", re.compile(r"\bdocument\s*\.\s*(?:URL|documentURI|baseURI|referrer|cookie)\b")),
    ("window.name", re.compile(r"\bwindow\s*\.\s*name\b")),
    ("URLSearchParams/.searchParams", re.compile(r"\bURLSearchParams\b|\.searchParams\b")),
    ("postMessage handler (event.data)", re.compile(r"addEventListener\s*\(\s*['\"`]message['\"`]|\.onmessage\b|\bevent\.data\b")),
    ("localStorage/sessionStorage/indexedDB", re.compile(r"\b(?:local|session)Storage\b|\bindexedDB\b")),
    ("router params (useParams/route.query/ActivatedRoute)",
     re.compile(r"\buseParams\b|\buseSearchParams\b|\bActivatedRoute\b|\broute\s*\.\s*(?:params|query)\b")),
    ("clipboard/drag (clipboardData/dataTransfer)", re.compile(r"\bclipboardData\b|\bdataTransfer\b")),
]

# Redirect-back parameter names (open-redirect / javascript:-URI family). A URL sink fed by one of these, with
# the scheme not restricted to http(s), is an open redirect or a javascript: XSS.
_REDIRECT_NAMES = ["returnUrl", "ReturnUrl", "redirect", "redirect_url", "redirectUrl", "redirect_uri", "next",
                   "dest", "destination", "continue", "callback", "returnTo", "goto"]
_REDIRECT_RE = re.compile(r"['\"`](" + "|".join(_REDIRECT_NAMES) + r")['\"`]")

# Known client libraries that ship their own URL-reachable DOM-XSS sink (or an escape hatch worth flagging).
# Keyed on strings the bundler does not rename. A hit is a LEAD to check the version, not a finding by itself.
_LIB_FINGERPRINTS = [
    ("Swagger UI", re.compile(r"SwaggerUIBundle|swagger-ui"), "?url=/?configUrl= DOM XSS in old versions"),
    ("AngularJS 1.x", re.compile(r"angular\.module\b|ng-app\b|angular\.bootstrap\b"), "template injection / sandbox escape (CSTI)"),
    ("jQuery", re.compile(r"jQuery\.fn|\bjquery\s*[:=]\s*[\"']?\d|\bjquery[.\-]\d|\bjQuery\.extend\b", re.I),
     "old jQuery (<3.5) adds HTML-parsing sinks ($(), .html()) - CVE-2020-11022/11023"),
    ("DOMPurify", re.compile(r"\bDOMPurify\b|createDOMPurify"), "check version + config (ADD_TAGS/ADD_ATTR self-defeats)"),
    ("Froala", re.compile(r"\bfroala\b", re.I), "known DOM XSS"),
    ("Mermaid", re.compile(r"\bmermaid\b", re.I), "prototype-pollution -> XSS"),
    ("Bootstrap", re.compile(r"data-toggle=|bootstrap(?:\.min)?(?:\.js)?|\.fn\.(?:tooltip|popover|modal|collapse|dropdown)\b", re.I),
     "<3.4 / <4.3.1 data-attribute/template XSS (e.g. CVE-2019-8331)"),
    ("marked/markdown-it", re.compile(r"\bmarked\b|markdown-it"), "raw HTML if html:true / sanitizer off"),
]

_MAX_HINTS = 30                 # sink snippets fed to the model (per whole file) - enough to point, not to drown


def _ctx(source: str, m: re.Match, span: int = 70) -> str:
    """A short verbatim slice around a regex hit - a usable snippet even from a minified (newline-free) bundle."""
    a = max(0, m.start() - span // 3)
    b = min(len(source), m.end() + span)
    return re.sub(r"\s+", " ", source[a:b]).strip()[:160]


def _static_hints(source: str) -> str:
    """A compact briefing of the DOM-XSS SOURCES and SINKS, redirect params, and known-vulnerable libraries that
    statically appear in the bundle, with one sample snippet per sink. Primes the agent to hunt the connections
    between them; it is explicitly NOT a verdict (a sink alone is safe until a source is traced into it)."""
    src_present = [label for label, rx in _SOURCES if rx.search(source)]
    sink_hits: list = []
    seen = set()
    for label, rx in _SINKS:
        for m in rx.finditer(source):
            snip = _ctx(source, m)
            key = (label, snip)
            if key in seen:
                continue
            seen.add(key)
            sink_hits.append((label, snip))
            if len(sink_hits) >= _MAX_HINTS:
                break
        if len(sink_hits) >= _MAX_HINTS:
            break
    redirects = sorted({m.group(1) for m in _REDIRECT_RE.finditer(source)})
    libs = [(name, note) for name, rx, note in _LIB_FINGERPRINTS if rx.search(source)]

    lines = ["STATIC HINTS (regex only - NOT findings; you must trace the source->sink chain yourself):"]
    lines.append("  controllable SOURCES present: " + (", ".join(sorted(set(src_present))) or "none matched (read anyway - regex is coarse)"))
    if sink_hits:
        lines.append("  dangerous SINKS present (sink :: sample):")
        lines += [f"    - {label} :: {snip}" for label, snip in sink_hits]
    else:
        lines.append("  dangerous SINKS present: none matched by regex - read the code, sinks may be minified/aliased.")
    if redirects:
        lines.append("  redirect-back params seen (open-redirect / javascript: family): " + ", ".join(redirects))
    if libs:
        lines.append("  known-vulnerable LIBRARIES fingerprinted (check the version):")
        lines += [f"    - {name}: {note}" for name, note in libs]
    secret_kinds = sorted({s["kind"] for s in _secret_net(source, "")})
    if secret_kinds:
        lines.append("  well-formed SECRETS matched by the net (report + look for more): " + ", ".join(secret_kinds))
    return "\n".join(lines)


# -- deterministic URL net ---------------------------------------------------------------------------------
# juicy is an endpoint-DISCOVERY tool, so its net is deliberately more aggressive than the shared js-endpoints
# regex (which is tuned for precision in crawlio/IRVIN). On top of that shared set we add the call-site and
# path-literal shapes a real Angular/React bundle uses, then a junk filter keeps the recall clean.
_EXTRA_URL_PATTERNS = [
    # a REST call site whose first arg is a path/URL: .get('/x'), .post(`/x`), axios('/x'), request({url:'/x'})
    re.compile(r"""\.(?:get|post|put|patch|delete|head|options|request|getJSON|ajax)\s*\(\s*[`'"]((?:https?:)?/[^`'"]+)"""),
    re.compile(r"""(?:\burl\s*:\s*|\baxios\s*\(\s*)[`'"]((?:https?:)?/[^`'"]+)"""),
    # an API-ish quoted path literal (any first segment that screams backend)
    re.compile(r"""[`'"]((?:https?:)?/(?:api|rest|graphql|gql|gateway|internal|services?|v\d+|oauth2?|auth|bff)"""
               r"""[A-Za-z0-9/_\-.{}$:]*)[`'"]""", re.I),
    # a quoted absolute path with at least two segments (/a/b...) - filtered for static assets below
    re.compile(r"""[`'"](/[A-Za-z0-9][A-Za-z0-9_\-.]*(?:/[A-Za-z0-9_\-.{}$:]+)+)[`'"]"""),
    # a path literal in a call/concat/assign context - catches a single-segment endpoint like base+"/events"
    re.compile(r"""[(+,=]\s*[`'"](/[A-Za-z][A-Za-z0-9_\-.{}$:]*)[`'"]"""),
    # a full backend URL, and websockets
    re.compile(r"""[`'"](https?://[^`'"\s)]+)[`'"]"""),
    re.compile(r"""[`'"](wss?://[^`'"\s)]+)[`'"]"""),
]

_STATIC_EXT = (".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".woff", ".woff2", ".ttf",
               ".eot", ".map", ".mp4", ".webm", ".mp3", ".wav", ".pdf", ".scss", ".less")
_JUNK_SCHEMES = ("data:", "blob:", "javascript:", "about:", "chrome:", "file:", "mailto:", "tel:")
# framework internals that LOOK like URLs but aren't server endpoints (Angular sanitizer doc, webpack loader, i18n)
_INTERNAL_URL = re.compile(r"(?:text/html;charset|/\[name\]|__webpack|/sockjs-node|\.hot-update\.|/@vite/|"
                           r"assets/i18n|/node_modules/)", re.I)


def _is_real_endpoint(u: str) -> bool:
    """A real server endpoint - not a data:/blob: URI, a static asset, a placeholder, or a framework internal
    (Angular's `data:text/html` sanitizer doc, a webpack chunk template, an i18n asset)."""
    if not u:
        return False
    lu = u.strip().lower()
    if lu.startswith(_JUNK_SCHEMES):
        return False
    if _INTERNAL_URL.search(u):
        return False
    path = urlparse(u).path or u
    if any(path.lower().endswith(e) for e in _STATIC_EXT):
        return False
    core = path.strip("/")
    if not core or core.startswith(("${", "{{", "+")):
        return False
    return True


def _net_urls(source: str, base_url: str) -> list:
    """Every URL/path the deterministic net finds in a JS body (the shared js-endpoints regexes PLUS juicy's
    call-site / path-literal shapes), junk-filtered, absolutised against the file's origin, and de-duped. This
    is the safety net that guarantees a referenced endpoint survives even if the model misses it."""
    found: list = []
    seen = set()
    for rx in list(_JS_URL_PATTERNS) + _EXTRA_URL_PATTERNS:
        for m in rx.finditer(source):
            path = (m.group(1) or "").strip()
            if not path or path in seen:
                continue
            # js-endpoints' own asset skip, plus juicy's stricter endpoint test (kills data:/internal/asset URLs)
            if _skip_path(path) if path.startswith("/") else False:
                continue
            if not _is_real_endpoint(path):
                continue
            seen.add(path)
            found.append(path)
    out = []
    for p in found:
        url = p if p.startswith(("http://", "https://")) else (urljoin(base_url, p) if base_url else p)
        out.append({"url": url, "path": p})
    return out


# -- in-process sub-command runner (shared session/registry, like crawlio/prawlio) -------------------------

def _call(argv: list, headers: list, debug: bool = False) -> str:
    """Run a boxcutter sub-command IN-PROCESS and return its raw stdout (the JSON envelope). Header-capable
    tools get the global --header(s) appended (e.g. an auth cookie so a bundle behind a login wall is fetched)."""
    import contextlib
    import io
    from ..cli import main as cli_main
    try:
        flag = toolschema.build(argv[0])["flag_of"].get("header") if argv else None
    except Exception:  # noqa: BLE001
        flag = None
    if flag and headers:
        argv = argv + [x for h in headers for x in (flag, h)]
    argv = agentlog.forward_debug(argv, debug)
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            cli_main(list(argv))
    except SystemExit:
        pass
    except Exception as exc:  # noqa: BLE001
        return json.dumps({"success": False, "error": f"{argv[0]} failed: {exc}"})
    return buf.getvalue().strip()


def _resp_of(raw: str) -> dict:
    """The first data record of an http-request envelope (url/status/content/headers), or {}."""
    try:
        env = json.loads(raw)
        data = env.get("data") or []
        return data[0] if data and isinstance(data[0], dict) else {}
    except Exception:  # noqa: BLE001
        return {}


def _body_of(raw: str) -> str:
    """The response body an http-request envelope carries (data[0].content), or ''."""
    return _resp_of(raw).get("content") or ""


def _content_type(resp: dict) -> str:
    for k, v in (resp.get("headers") or {}).items():
        if str(k).lower() == "content-type":
            return str(v).lower()
    return ""


def _looks_like_js(url: str, resp: dict) -> bool:
    """Decide whether a fetched resource IS JavaScript (analyse it directly) or an HTML PAGE (discover its
    scripts first). Content-Type wins; then the URL extension; then a body sniff. Defaults to JS when genuinely
    ambiguous (a script served with no type and no extension is common; an HTML doc almost always announces
    itself)."""
    ctype = _content_type(resp)
    if any(t in ctype for t in ("javascript", "ecmascript")):
        return True
    if "html" in ctype:
        return False
    path = urlparse(url).path.lower()
    if path.endswith((".js", ".mjs", ".cjs")):
        return True
    if path.endswith((".html", ".htm")) or path in ("", "/"):
        return False
    head = (resp.get("content") or "").lstrip()[:600].lower()
    if head.startswith(("<!doctype", "<html")) or "<head" in head or "<meta" in head:
        return False
    return True


_SCRIPT_SRC = re.compile(r"<script\b[^>]*\bsrc\s*=\s*['\"]([^'\"]+)['\"]", re.I)
_SCRIPT_INLINE = re.compile(r"<script\b([^>]*)>(.*?)</script>", re.I | re.S)


def _extract_scripts(html: str, page_url: str) -> tuple:
    """From an HTML page, pull (external script URLs absolutised against the page, inline <script> bodies). The
    external <script src> bundles are the app's real code; the inline blocks are prime DOM-XSS spots (router
    bootstrap, config, hand-written handlers) so they are analysed too. Non-JS <script> (application/json,
    ld+json, importmap, a template) is skipped."""
    ext: list = []
    for m in _SCRIPT_SRC.finditer(html):
        u = urljoin(page_url, m.group(1).strip())
        if u.startswith(("http://", "https://")) and u not in ext:
            ext.append(u)
    inline: list = []
    for m in _SCRIPT_INLINE.finditer(html):
        attrs = (m.group(1) or "").lower()
        if "src=" in attrs:
            continue                                    # external, already captured above
        if "type=" in attrs and not any(t in attrs for t in ("javascript", "module", "text/babel", "jsx")):
            continue                                    # json / ld+json / importmap / template - not script
        body = (m.group(2) or "").strip()
        if len(body) >= 40:                             # skip trivial one-liners (a GA snippet stub, a nonce)
            inline.append(body)
    return ext, inline


# A third-party / framework bundle by filename - its DOM sinks are the "known-vulnerable library" story, not the
# app's own taint, so juicy fingerprints these cheaply instead of spending LLM windows reading minified jQuery.
_VENDOR_RE = re.compile(r"(?:^|[/\-.~])(vendors?|polyfills?|runtime|framework|chunk-vendors|common|scripts|"
                        r"manifest|styles|main-es5|npm\.[\w-]+|jquery|bootstrap|angular|react|lodash|moment)"
                        r"(?:[.\-~]|\.min|$)", re.I)


def _is_vendor(url: str) -> bool:
    name = urlparse(url).path.rsplit("/", 1)[-1].lower()
    return bool(_VENDOR_RE.search(name))


def _order_scripts(urls: list, page_host: str) -> list:
    """App bundles first, vendor bundles last, same-origin before cross-origin - so the --max-files budget and
    the deep LLM analysis land on the app's OWN code (where its endpoints and taint live), not on jQuery."""
    def key(u: str) -> tuple:
        same = (urlparse(u).hostname or "").lower() == page_host
        return (_is_vendor(u), not same)
    return sorted(urls, key=key)


def _cap_http(raw: str, max_chars: int = 60_000) -> str:
    """Trim a fetched body before it re-enters the model's history so a big chunk can't blow the context window.
    The FULL body is still scanned by the URL net separately, so nothing is lost to this cap."""
    body = _body_of(raw)
    if len(body) <= max_chars:
        return raw
    try:
        env = json.loads(raw)
        env["data"][0]["content"] = body[:max_chars] + f"\n/*...[truncated {len(body) - max_chars} chars; " \
                                                        "the URL net already scanned the full body]...*/"
        return json.dumps(env, ensure_ascii=False)
    except Exception:  # noqa: BLE001
        return raw[:max_chars]


# -- windowing ---------------------------------------------------------------------------------------------

def _windows(text: str, size: int, overlap: int = 2_000) -> list:
    """Slice a (possibly minified, newline-free) source into overlapping windows so the WHOLE file is analysed.
    The overlap keeps a sink/source split across a boundary intact in at least one window."""
    if len(text) <= size:
        return [text]
    out, i = [], 0
    while i < len(text):
        out.append(text[i:i + size])
        if i + size >= len(text):
            break
        i += size - overlap
    return out


_SYSTEM = (
    "You are JUICY, a specialist client-side JavaScript SECURITY ANALYST. You are given the source of ONE "
    "JavaScript file (a bundle, delivered in windows if large) plus read-only tools. You have THREE deliverables, "
    "judged on the RECALL of the first and third and the PRECISION of the second:\n"
    "  1. HIDDEN URLs / ENDPOINTS - every server path/URL the code can call or navigate to.\n"
    "  2. CLIENT-SIDE XSS - every place attacker-controllable input reaches a script/HTML sink, each PROVEN with "
    "a WORKING, copy-pasteable PoC that pops alert(1) on the ACTUAL resource where the code runs (the page/URL "
    "the bundle loads on) - a real trigger for that resource, not a generic payload.\n"
    "  3. SECRETS - credentials/keys/tokens and sensitive internal URLs shipped in the bundle.\n\n"

    "== READING A MINIFIED BUNDLE ==\n"
    "This is almost always production, minified code: identifiers are mangled to a,b,e,t,n,r,i - so trace the "
    "DATA FLOW, not the variable names. What the minifier does NOT rename, and what you therefore anchor on: DOM "
    "API names (innerHTML, insertAdjacentHTML, document.write, eval), string keys (\"__html\", "
    "\"dangerouslySetInnerHTML\"), and library method names (bypassSecurityTrustHtml, createContextualFragment, "
    "$sce). BEST MOVE FIRST: if the file ends with a `//# sourceMappingURL=...` comment, or a `.map` sits beside "
    "it, FETCH it with http-request - the original, un-minified source makes every trace trivial. Also fetch "
    "referenced lazy CHUNKS when a route table or a sink's source lives there.\n\n"

    "== 1. HIDDEN URLs ==\n"
    "Find every endpoint the bundle references, not just the literal strings a grep catches. Follow how a URL is "
    "CONSTRUCTED: a `baseURL`/`API_ROOT` constant concatenated with a path, template literals "
    "(`/users/${id}/orders`), a route/endpoint TABLE (an object/array of paths), axios/fetch/XHR calls, "
    "`.open(METHOD,url)`, GraphQL operations, WebSocket/EventSource URLs, and lazy chunk names. For each: the URL "
    "(absolute against the file origin for a bare path; keep a `${..}` placeholder where a value is interpolated), "
    "the METHOD if the call site shows one (else \"?\"), whether it takes params, and one line on WHERE/HOW it is "
    "built. Collapse id families (/user/1,/user/2 -> /user/{id}). BE EXHAUSTIVE: enumerate EVERY endpoint - the "
    "regex net is a FLOOR, not a substitute, so do NOT skip plain endpoints assuming it caught them; a real app "
    "has dozens (an Angular HttpClient service class, a route table, a config of API paths). Walk each service/"
    "api module and list them all. EXCLUDE non-endpoints: static assets (.css/.png/.woff, /assets/, /fonts/), "
    "and FRAMEWORK INTERNALS that merely look like URLs - Angular's `data:text/html` sanitizer document, webpack "
    "chunk-loader templates (`/[name].[hash].js`), sourcemap URLs, i18n asset paths. Those are NOT server "
    "endpoints; never report them.\n\n"

    "== 2. CLIENT-SIDE XSS - CONFIRM, DON'T GREP ==\n"
    "THE DISCIPLINE (this is the whole job): a keyword match is a CANDIDATE, never a finding. Modern frameworks "
    "escape by default (React {value}, Vue {{ }}, Angular bindings), so a finding exists ONLY where the code "
    "leaves that baseline (a raw/escape-hatch/script sink) AND you can TRACE a tainted SOURCE into it AND you can "
    "build a PoC that FIRES against that sink. A bare `el.innerHTML = t` fed by a constant is SAFE. No traced "
    "source, or no constructable PoC -> it is NOT a finding (mark it `unverifiable`), never a vuln.\n"
    "  CONTROLLABLE SOURCES (tainted): location.hash/.search/.href/.pathname, URLSearchParams / router params "
    "(useParams, route.query, ActivatedRoute); document.URL/documentURI/referrer/cookie; window.name; a "
    "postMessage handler's event.data; localStorage/sessionStorage/IndexedDB; WebSocket/EventSource messages; a "
    "fetch/XHR response field that can carry ANOTHER user's content (a comment, profile, message = STORED XSS, "
    "which outranks reflected - it fires for every viewer); and any function PARAMETER a caller feeds one of "
    "these into. A value from string literals only is NOT tainted.\n"
    "  DANGEROUS SINKS - direct: innerHTML/outerHTML, insertAdjacentHTML, document.write(ln); eval, new Function, "
    "setTimeout/setInterval(STRING); location = / .assign / .replace / window.open; setAttribute('on*'|'href'|"
    "'src'|'formaction'), a.href/form.action = v; iframe.src/.srcdoc; el.style.cssText; "
    "Range.createContextualFragment, DOMParser.parseFromString then inserted; Worker/importScripts/ServiceWorker.\n"
    "  DANGEROUS SINKS - INDIRECT, easy to miss (check each): jQuery `$(x)` (a string starting `<` parses as "
    "HTML), `$(location.hash)` as a selector, `.html/.append/.prepend/.after/.before/.replaceWith/.wrap(v)` "
    "(esp. a value built by CONCATENATION), `$.parseHTML/$.globalEval/$.getScript`; framework escape-hatches - "
    "React `dangerouslySetInnerHTML`/`{...userObject}` prop-spread smuggling, Vue `v-html`/`v-bind=userObject`, "
    "Angular `bypassSecurityTrustHtml/Url/ResourceUrl` (plain `[innerHTML]` is SAFE - Angular sanitizes it; the "
    "finding is the bypass wrap); dynamic component/route chosen by untrusted NAME (`widgets[name]`, "
    "`<component :is=name>`); the `innerHTML`-as-sanitizer trap (`d.innerHTML=x; return d.textContent` EXECUTES "
    "on the assignment) and read-modify-write `el.innerHTML = el.innerHTML.replace(..,userInput)`; dynamic "
    "resource loading `script.src=userUrl`, a `<link rel=stylesheet href=userUrl>`, and JSONP "
    "(`jsonp(base+user)` / a `?callback=` reflected into a `<script>`); markdown/rich-text renderers with raw "
    "HTML on (`marked`, `markdown-it({html:true})`, TinyMCE/CKEditor/Froala/Quill paste paths).\n"
    "  postMessage is the highest-yield sink - report it when BOTH hold: (a) origin validation is WEAK or ABSENT "
    "- no check, or a bypassable one: `origin.indexOf('site.com')!=-1` (substring: site.com.evil.com passes), "
    "`origin.startsWith('https://site.com')` (site.com.evil.com passes), an UNANCHORED regex `/site\\.com/` "
    "(evilsite.com passes) - only an anchored `===` / `new URL(o).origin===` is safe; AND (b) `event.data` (or a "
    "field) reaches a sink OR a method dispatched by name (`window[data.fn](...)`, `api[data.action]` - RPC over "
    "postMessage). Also flag validate-once-then-trust.\n"
    "  NAVIGATION / OPEN REDIRECT (in scope): `location`/`.href/.assign/.replace`, `window.open`, "
    "`router.push/navigateByUrl`, `<a href=user>` built from input where the scheme is NOT restricted to "
    "http(s)/relative. Check the redirect-back params by name: returnUrl/redirect/redirect_uri/next/dest/"
    "continue/callback/returnTo/goto/url/u. `javascript:`/`data:` scheme -> XSS; arbitrary origin -> open "
    "redirect. Also `target=_blank` without `rel=noopener` = reverse tabnabbing (flag, lower sev).\n"
    "  CSTI / prototype pollution (client script exec, report as xss-class): user input compiled as a template "
    "(`new Function`, Vue full build, AngularJS 1.x, lodash/handlebars templates) - "
    "`{{constructor.constructor('alert(1)')()}}`; a recursive merge / query-string-to-object parser that reaches "
    "`__proto__`/`constructor.prototype` with no guard (`?#__proto__[x]=y`), plus a gadget that renders a "
    "polluted value as HTML/script.\n"
    "  KNOWN-VULNERABLE LIBS - DO NOT turn a library CVE into a dom_xss finding. A vulnerable library (old jQuery "
    "<3.5, bootstrap <4.3.1, AngularJS 1.x, Swagger UI, Froala, Mermaid, old/misconfigured DOMPurify) shipping a "
    "dangerous API is only a FINDING when you can point to the APP calling that API with plausibly-attacker-"
    "controlled input - a real call site you cite (e.g. the app does `$(userVar).html(...)`, or enables Bootstrap "
    "popovers with `html:true` on attacker-controlled data-attributes). If you CANNOT show such a call site, it "
    "is NOT a dom_xss row - put one line in `notes` ('jQuery 3.3.1 present (CVE-2020-11022) - no untrusted "
    ".html() call site found'). juicy already reports the fingerprinted libraries separately; a bare 'this "
    "library has a CVE if misused' is noise, not a finding.\n\n"

    "== SANITIZERS AND WHAT A PoC MUST SURVIVE ==\n"
    "If a sink is 'defended', it is STILL vulnerable when the defense is bypassable - and your PoC must reflect "
    "the real context. Note the guard you see (encodeURIComponent, DOMPurify.sanitize, textContent-not-innerHTML, "
    "a `location.protocol`/scheme check) and decide if it actually covers the tainted value on THIS path (a "
    "check on a different value, or AFTER the sink, does not count). Payload craft: stripping `<script>` is not "
    "safe - use event handlers (`<img src=x onerror=alert(document.domain)>`, `<svg onload=..>`, `<input "
    "autofocus onfocus=..>`, `<details open ontoggle=..>`), SVG/MathML + `<style>` for mXSS against allowlist "
    "sanitizers, `<iframe srcdoc=..>`; a misconfigured DOMPurify (`ADD_TAGS:['script']`, `ADD_ATTR:['onerror']`) "
    "or a pinned old version is bypassable. Match the payload to the sink's CONTEXT: HTML body vs attribute "
    "breakout vs a `javascript:`/`data:` URI vs a JS-string escape.\n\n"

    "== 3. SECRETS ==\n"
    "Bundles routinely ship secrets the build baked in. Hunt for them TWO ways. (a) KNOWN FORMATS - run "
    "`scan-secrets` on this file's URL (and on a sibling asset/chunk if useful): it regex-matches AWS/Google/"
    "Stripe/GitHub/Slack/Twilio/SendGrid/OpenAI/... keys. A deterministic net also runs, so well-formed keys "
    "can't be missed. (b) THE ONES ONLY A HUMAN SPOTS, which the regexes DON'T catch - read for them: a hardcoded "
    "`Authorization: Bearer ...`/Basic-auth string, a JWT (`eyJ...`), an OAuth client_secret, a private signing "
    "key, a Firebase/Maps/analytics key, and SENSITIVE INTERNAL URLs baked into the build (an admin/staging/"
    "internal API host, a `.internal`/`.corp` hostname, a build/CI token in `environment.*`/`process.env.*`). "
    "Report each with WHERE it is (the var/context) and redact the middle of a long value. Rate by what it "
    "unlocks: a live third-party/API key = Critical/High; a build/CI token or internal hostname = Medium.\n\n"

    "== VERDICT, CONFIDENCE, SEVERITY (per finding) ==\n"
    "  verdict `vulnerable` : a tainted source reaches a raw/bypassed/script sink with no effective sanitization "
    "AND you can construct a firing PoC. Only these carry a severity.\n"
    "  verdict `unverifiable`: the sink is raw/bypassed but you can't close the loop from static reading - the "
    "source can't be shown attacker-influenced (`[untraced-source]`, e.g. an API field whose server controls "
    "aren't here) OR the source is tainted but no PoC constructs (`[no-poc]`, e.g. an intervening sanitizer whose "
    "strength you can't read). Name what to confirm; never rate it.\n"
    "  confidence: `confirmed` (whole source->sink path visible in the code you read) or `needs-review`.\n"
    "  severity (vulnerable only, and only WITH a PoC): Critical = reliable arbitrary script exec from a "
    "low-friction source (a URL param, or a PERSISTENT store / stored content that fires on every view for every "
    "visitor). High = script exec needing a victim action or a narrower precondition (a `javascript:` URI they "
    "click, an untrusted iframe src, an open redirect accepting `javascript:`/arbitrary origin, a hidden route "
    "leaking a client-shipped secret). Medium = a real bypass with an unusual precondition or lower impact "
    "(phishing-only open redirect, prototype-pollution with no demonstrated gadget, tabnabbing).\n\n"

    "== TOOLS (read-only) ==\n"
    "  - http-request <url> [-H 'K: V'] - fetch more SOURCE: the `//# sourceMappingURL=` original/.map (do this "
    "when present - it un-minifies the trace), a lazy webpack CHUNK, or an imported module - anything referenced "
    "that you must read to finish a trace. Fetch only what matters; don't pull every chunk blindly.\n"
    "  - js-endpoints <js-url> - fast regex endpoint extraction on ANOTHER js file WITHOUT reading its whole body "
    "into context. Cheapest way to enumerate a sibling/chunk bundle's endpoints.\n"
    "  - scan-secrets <url> - fetch a URL and regex-scan its body for known-format secrets (cloud/payment/SCM/"
    "messaging API keys). Point it at THIS file's URL and at any sibling asset/chunk you suspect leaks a key.\n"
    "Reuse the SAME identity/header on every fetch (auth carries automatically). Do NOT invent chunk URLs - only "
    "fetch ones actually referenced by code you have seen.\n\n"

    "== METHOD ==\n"
    "Read each window; NARRATE one short line before a tool call (e.g. 'the app's original source is in the "
    "sourcemap - fetching it to trace the hash router', 'the API base is assembled here - opening chunk 4 for the "
    "route table'). Track sources, then sinks, then trace each sink back to a source. When you've read the source "
    "you need, emit findings. More windows coming -> emit a PARTIAL json per window (I merge them); when I say the "
    "file is fully delivered, emit the FINAL consolidated json.\n"
    + agentlog.NARRATE +
    "\nEnd with ONE fenced ```json block and NOTHING after it:\n"
    '{"urls":[{"url":"<absolute or path with ${..} placeholder>","method":"GET|POST|?","kind":"absolute|'
    'relative|template|route-table|graphql|websocket","params":["name"],"note":"how/where it is built"}],\n'
    ' "dom_xss":[{"class":"dom-xss|stored-xss|open-redirect|postmessage-xss|prop-smuggling|csti|'
    'prototype-pollution|jsonp-xss|known-vuln-lib","verdict":"vulnerable|unverifiable",'
    '"severity":"Critical|High|Medium","source":"location.hash","sink":"el.innerHTML (where in code)",'
    '"trace":"hash -> render(t) -> el.innerHTML, no escaping",'
    '"snippet":"<=160 chars verbatim vulnerable code",'
    '"sanitizer":"none | DOMPurify default (covers it) | present but bypassable via svg+style",'
    '"poc":"<COMPLETE copy-pasteable trigger for the ACTUAL page/URL where this code runs, that makes alert(1) '
    'FIRE: e.g. the full URL https://host/path#<img src=x onerror=alert(1)> , or exact steps for a postMessage/'
    'storage source>",'
    '"persistent":false,"confidence":"confirmed|needs-review",'
    '"note":"[untraced-source]/[no-poc] reason if unverifiable"}],\n'
    ' "secrets":[{"kind":"Google API Key|JWT|hardcoded-bearer|oauth-client-secret|internal-url|...",'
    '"match":"<the value, redact the middle of a long one>","severity":"Critical|High|Medium",'
    '"where":"<var/context it sits in>","note":"what it unlocks"}],\n'
    ' "notes":["sourcemap/chunks fetched, route tables found, a library CVE with no app call site, next-stage '
    'notes"]}')


# Independent re-verification: a SECOND, adversarial pass that re-traces ONE finding from scratch against the
# REAL code (sliced around the sink/source, handed in), so the report doesn't rest on the first pass's word. The
# bar is deliberately high and refute-by-default - the whole point is that a teammate can trust `confirmed`
# without redoing the trace.
_VERIFY_XSS = (
    "You are INDEPENDENTLY RE-VERIFYING a single client-side XSS finding a previous pass reported. Trust NOTHING "
    "- assume it is a FALSE POSITIVE until the code in front of you proves otherwise. You are given the claimed "
    "finding plus the ACTUAL code sliced around the sink (and the source, when it was locatable). Re-trace the "
    "data flow FROM SCRATCH, hop by hop, using ONLY real code - the slices given, plus anything you fetch with "
    "the tools to close a gap (the sourcemap original, a chunk, the imported module). Do not take the previous "
    "pass's trace on faith; rebuild it.\n"
    "CONFIRM (status:confirmed) only when ALL FOUR hold, each cited to code you actually read:\n"
    "  1. a genuinely attacker-CONTROLLABLE source (URL/hash/query/route param, postMessage event.data, "
    "window.name, storage, or a stored API field another user can set) - NOT a constant, NOT a value the app "
    "itself computes;\n"
    "  2. it reaches a raw-HTML / script / navigation sink;\n"
    "  3. with NO effective sanitizer or encoder on THAT path - a guard on a DIFFERENT value, or one that runs "
    "AFTER the sink, does not count; and framework DEFAULT escaping (React {v}, Angular [innerHTML], Vue {{v}}) "
    "is SAFE unless an explicit escape hatch (dangerouslySetInnerHTML / bypassSecurityTrust* / v-html) bypasses "
    "it;\n"
    "  4. you can give a COMPLETE, working PoC - a full URL or exact steps for the real resource - that makes "
    "alert(1) FIRE against THIS sink.\n"
    "REFUTE (status:refuted) the moment the chain breaks: the 'source' isn't actually attacker-controlled, an "
    "escaper/sanitizer covers it, the sink is framework-escaped, or it is a LIBRARY-INTERNAL sink with no app "
    "call site (a jQuery/Bootstrap CVE nobody in the app feeds untrusted input to is NOT a finding). When in "
    "doubt, refute. If the code you can see (and fetch) is genuinely insufficient to decide, status:unconfirmed "
    "and say exactly what a human must check.\n"
    "End with ONE fenced ```json block and NOTHING after it:\n"
    '{"status":"confirmed|refuted|unconfirmed",'
    '"trace":"<your OWN hop-by-hop source->sink, each hop grounded in the code>",'
    '"evidence":"<the decisive code fact: the exact tainted assignment INTO the sink and that nothing escapes it '
    'on that path - <=200 chars, redacted>",'
    '"poc":"<the complete, working PoC that fires alert(1) on the resource, corrected if the original was wrong>",'
    '"reason":"<if refuted/unconfirmed: precisely why, and what a human should check>"}')

_VERIFY_STEPS = 6           # bounded agent budget for one re-verification (mostly reasons over given slices)


def _merge_urls(acc: dict, items, base_url: str, file: str = "") -> None:
    """Union URL records into `acc`, keyed by (method, url). First writer's metadata wins; later ones only fill
    blanks. Absolutises bare paths against the file origin. `file` records which JS the URL was first seen in."""
    for it in items or []:
        if not isinstance(it, dict):
            continue
        url = str(it.get("url") or "").strip()
        if not url:
            continue
        if not url.startswith(("http://", "https://")) and not url.startswith("${") and base_url:
            # keep a templated first segment intact; only absolutise a plain leading path
            if url.startswith("/"):
                url = urljoin(base_url, url)
        if not _is_real_endpoint(url):          # drop data:/blob:/asset/framework-internal 'urls' the model emits
            continue
        method = str(it.get("method") or "?").upper()
        key = (method, url.lower())
        rec = acc.get(key)
        clean = {"type": "url", "url": url, "method": method,
                 "kind": it.get("kind") or "", "params": it.get("params") or [],
                 "note": str(it.get("note") or "")[:200], "file": file}
        if rec is None:
            acc[key] = clean
        else:
            for k in ("kind", "note"):
                if not rec.get(k) and clean.get(k):
                    rec[k] = clean[k]
            if not rec.get("params") and clean["params"]:
                rec["params"] = clean["params"]


def _merge_xss(acc: dict, items, file: str = "") -> None:
    """Union XSS records into `acc`, keyed by (file, sink, source, snippet) so the same taint found in two
    overlapping windows collapses to one row while the SAME-shaped sink in two different files stays distinct.
    An `unverifiable` verdict carries no severity (per the skill's discipline: a severity is only valid with a
    firing PoC)."""
    for it in items or []:
        if not isinstance(it, dict) or not it.get("sink"):
            continue
        sink = str(it.get("sink"))
        source = str(it.get("source") or "")
        snip = str(it.get("snippet") or "")
        key = (file, sink.lower(), source.lower(), re.sub(r"\s+", "", snip)[:80].lower())
        if key in acc:
            continue
        verdict = "vulnerable" if str(it.get("verdict") or "").lower() == "vulnerable" else "unverifiable"
        sev = str(it.get("severity") or "").title() if verdict == "vulnerable" else ""
        acc[key] = {"type": "xss", "class": str(it.get("class") or "dom-xss").lower(), "verdict": verdict,
                    "severity": sev, "source": source, "sink": sink, "file": file,
                    "trace": str(it.get("trace") or it.get("tainted_via") or "")[:280],
                    "snippet": snip[:200], "sanitizer": str(it.get("sanitizer") or "")[:160],
                    "poc": str(it.get("poc") or it.get("example") or "")[:280],
                    "persistent": bool(it.get("persistent")),
                    "confidence": str(it.get("confidence") or "needs-review").lower(),
                    "note": str(it.get("note") or "")[:200]}


# -- code anchoring: pin a finding to the real bytes so it is checkable, and feed the re-verifier real code ----

def _locate(source: str, needle: str, radius: int = 220) -> dict | None:
    """Find `needle` (a reported snippet or a source/sink token) in `source` and return {offset, line, excerpt}.
    Tolerant of the model paraphrasing: tries the verbatim snippet, then its longest distinctive token run - so
    even a slightly-off snippet still anchors to the actual code a teammate can open and read."""
    if not source or not needle:
        return None
    s = needle.strip()
    i = source.find(s)
    if i < 0:                                   # fall back to the longest distinctive run in the snippet
        for run in sorted(re.findall(r"[A-Za-z0-9_.$\[\]()'\"=+-]{14,}", s), key=len, reverse=True):
            i = source.find(run)
            if i >= 0:
                s = run
                break
    if i < 0:
        return None
    start, end = max(0, i - radius), min(len(source), i + len(s) + radius)
    return {"offset": i, "line": source.count("\n", 0, i) + 1, "excerpt": source[start:end]}


def _evidence(finding: dict, sources: dict) -> tuple:
    """Anchor a finding in real code. Prefer the file it was reported in; if the snippet isn't there (the model
    named the wrong file, or it's in a fetched chunk), search every source we hold. Returns (info, code) where
    `info` = {file, offset, line, excerpt, source_excerpt} or None, and `code` is the located file's full source
    (handed to the re-verifier)."""
    order = [finding.get("file", "")] + [k for k in sources if k != finding.get("file", "")]
    for label in order:
        src = sources.get(label) or ""
        loc = _locate(src, finding.get("snippet", ""))
        if not loc:
            continue
        info = {"file": label, "offset": loc["offset"], "line": loc["line"], "excerpt": loc["excerpt"][:480]}
        srcloc = _locate(src, str(finding.get("source", "")).split()[0] if finding.get("source") else "")
        info["source_excerpt"] = (srcloc["excerpt"][:300] if srcloc else "")
        return info, src
    return None, ""


# -- libraries (fingerprint, don't fabricate a finding) ----------------------------------------------------

_JQUERY_VER = re.compile(r"jquery[\"']?\s*[:=]\s*[\"']([0-9]+\.[0-9]+\.[0-9]+)[\"']", re.I)
_GENERIC_VER = re.compile(r"\bVERSION\s*[:=]\s*[\"']([0-9]+\.[0-9]+(?:\.[0-9]+)?)[\"']")


def _lib_version(name: str, source: str) -> str:
    """Best-effort version string for a fingerprinted library (jQuery is reliable; others fall back to a nearby
    VERSION= literal). Empty when it can't be read - the presence + CVE note still stands."""
    if name.startswith("jQuery"):
        m = _JQUERY_VER.search(source)
        if m:
            return m.group(1)
    m = _GENERIC_VER.search(source)
    return m.group(1) if m else ""


def _library_report(source: str) -> list:
    """Which fingerprinted client libraries appear in this source, with a version when readable. A vulnerable
    library is documented here as a LIBRARY - it becomes a `dom_xss` finding only if the app is shown calling
    its dangerous API with tainted input (that is the model's job, not the fingerprint's)."""
    out = []
    for name, rx, note in _LIB_FINGERPRINTS:
        if rx.search(source):
            out.append({"name": name, "version": _lib_version(name, source), "note": note})
    return out


def _add_library(acc: dict, lib: dict, file: str) -> None:
    rec = acc.get(lib["name"])
    if rec is None:
        acc[lib["name"]] = {"type": "library", "name": lib["name"], "version": lib.get("version", ""),
                            "cve_note": lib.get("note", ""), "files": [file]}
    else:
        if file not in rec["files"]:
            rec["files"].append(file)
        if not rec.get("version") and lib.get("version"):
            rec["version"] = lib["version"]


# -- secrets -----------------------------------------------------------------------------------------------

# On top of scan-secrets' known-provider formats, a few high-value shapes that ship in bundles: a signed JWT, an
# inlined private-key block, and HTTP basic-auth creds baked into a URL.
_EXTRA_SECRET_PATTERNS = [
    ("JSON Web Token", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,}")),
    ("Private Key Block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("Basic-Auth Credentials in URL", re.compile(r"https?://[A-Za-z0-9._%+-]+:[^@\s/'\"]{3,}@[A-Za-z0-9.-]+")),
]


def _secret_net(source: str, url: str) -> list:
    """Deterministic secret scan: the known-format patterns scan-secrets uses (AWS/Google/Stripe/GitHub/Slack/...
    keys) PLUS a JWT / private-key / basic-auth-URL net. Guarantees a well-formed secret survives even if the
    model doesn't call it out - the model handles the ones only a human spots (a bare bearer, an internal URL)."""
    out, seen = [], set()
    for name, rx in list(_SECRET_PATTERNS) + _EXTRA_SECRET_PATTERNS:
        for m in rx.finditer(source):
            val = m.group(0)
            if (name, val) in seen:
                continue
            seen.add((name, val))
            out.append({"kind": name, "match": val, "severity": "High", "where": "regex-net", "url": url})
    return out


def _redact(v: str) -> str:
    """Keep a secret identifiable without dumping it in full: first 4 + last 4 for anything long enough."""
    v = str(v)
    return v if len(v) <= 12 else f"{v[:4]}...{v[-4:]} (len {len(v)})"


def _merge_secrets(acc: dict, items, file: str = "") -> None:
    """Union secret records, keyed by (kind, match) so the same key found by the net and the model collapses."""
    for it in items or []:
        if not isinstance(it, dict):
            continue
        match = str(it.get("match") or it.get("value") or "").strip()
        kind = str(it.get("kind") or it.get("title") or "secret").strip()
        if not match:
            continue
        key = (kind.lower(), match)
        if key in acc:
            continue
        acc[key] = {"type": "secret", "kind": kind, "match": _redact(match),
                    "severity": str(it.get("severity") or "High").title(),
                    "where": str(it.get("where") or "")[:120], "file": file,
                    "note": str(it.get("note") or "")[:200]}


def _secrets_from_scan(raw: str) -> list:
    """Map a scan-secrets envelope (findings of {title, info: '... key = VALUE', url}) into juicy secret items."""
    out = []
    for d in _resp_of_list(raw):
        if not isinstance(d, dict):
            continue
        info = str(d.get("info") or "")
        val = info.split("key = ", 1)[-1].strip() if "key = " in info else ""
        out.append({"kind": d.get("title") or "secret", "match": val, "severity": "High", "where": "scan-secrets"})
    return out


def _resp_of_list(raw: str) -> list:
    try:
        env = json.loads(raw)
        return env.get("data") or []
    except Exception:  # noqa: BLE001
        return []


def _harvest_deterministic(source: str, file: str, app_base: str, urls: dict, libraries: dict, secrets: dict) -> None:
    """Run every deterministic net (URLs, library fingerprint, secrets) over a source and fold into the shared
    accumulators - the floor under the model's own analysis, attributed to `file`."""
    _merge_urls(urls, [{"url": u["url"], "method": "?", "kind": "regex-net", "note": f"regex match `{u['path']}`"}
                       for u in _net_urls(source, app_base)], app_base, file=file)
    for lib in _library_report(source):
        _add_library(libraries, lib, file)
    _merge_secrets(secrets, _secret_net(source, file), file=file)


def _reverify_xss(provider, finding: dict, evidence: dict, headers: list, args, vtools, cache: dict,
                  count: dict, dbg) -> dict:
    """Independently re-trace ONE XSS finding against the REAL code (the deterministically-located slices around
    its sink and source), refute-by-default. May fetch the sourcemap/chunk to close a gap. Returns
    {status, trace, evidence, poc, reason}. Any error -> unconfirmed (never silently confirm or drop)."""
    sink_code = (evidence or {}).get("excerpt", "") or "(snippet could not be located verbatim in the source)"
    src_code = (evidence or {}).get("source_excerpt", "")
    where = f"{(evidence or {}).get('file', finding.get('file', '?'))}" \
            + (f" : offset {evidence['offset']} (line {evidence['line']})" if evidence else "")
    user = ("CLAIMED FINDING (re-verify it, do not trust it):\n"
            f"  class:    {finding.get('class')}\n  severity: {finding.get('severity') or '(none)'}\n"
            f"  source:   {finding.get('source')}\n  sink:     {finding.get('sink')}\n"
            f"  claimed trace: {finding.get('trace')}\n  claimed PoC:   {finding.get('poc')}\n"
            f"  sanitizer noted: {finding.get('sanitizer') or '(none)'}\n  location: {where}\n\n"
            f"CODE AROUND THE SINK (real bytes from the file):\n```\n{sink_code}\n```\n"
            + (f"\nCODE AROUND THE SOURCE:\n```\n{src_code}\n```\n" if src_code else "")
            + "\nRe-trace from scratch and return the json verdict. Fetch the sourcemap/chunk with the tools only "
              "if you genuinely cannot decide from the above.")
    messages = [{"role": "user", "content": user}]
    final = ""
    for _ in range(_VERIFY_STEPS):
        try:
            resp = provider.send(_VERIFY_XSS, messages, vtools)
        except Exception as exc:  # noqa: BLE001 - a verify error is "unconfirmed", never a silent confirm/drop
            return {"status": "unconfirmed", "trace": "", "evidence": "",
                    "poc": finding.get("poc", ""), "reason": f"verifier error: {exc}"}
        text, calls = provider.parse(resp)
        messages += provider.assistant_msg(resp)
        if text.strip():
            final = text
            dbg("juicy[verify]> " + " ".join(text.split())[:200])
        if not calls:
            break
        results = []
        for c in calls:
            if c["name"] not in ("http-request", "js-endpoints"):
                results.append({"id": c["id"], "output": json.dumps({"error": "only http-request/js-endpoints"})})
                continue
            argv = toolschema.to_argv(c["name"], c["args"])
            keyt = tuple(argv)
            count[keyt] = count.get(keyt, 0) + 1
            if keyt in cache:
                out = cache[keyt]
            elif count[keyt] > 2:
                out = json.dumps({"success": False, "error": "already ran this exact call"})
            else:
                out = _call(argv, headers, args.debug)
                cache[keyt] = out
                if c["name"] == "http-request":
                    out = _cap_http(out)
            results.append({"id": c["id"], "output": out})
        messages += provider.tool_results(results)
    obj = extract_json(final)
    status = str(obj.get("status", "")).lower()
    if status not in ("confirmed", "refuted", "unconfirmed"):
        status = "unconfirmed"
    return {"status": status, "trace": str(obj.get("trace", ""))[:400],
            "evidence": str(obj.get("evidence", ""))[:240], "poc": str(obj.get("poc") or finding.get("poc", ""))[:280],
            "reason": str(obj.get("reason", ""))[:280]}


def _analyze_source(provider, label: str, source: str, app_base: str, headers: list, args, tools_spec,
                    urls: dict, xss: dict, libraries: dict, secrets: dict, cache: dict, count: dict, dbg) -> None:
    """Run the windowed agent analysis over ONE JavaScript source, folding its findings into the shared `urls`,
    `xss`, `libraries` and `secrets` accumulators (stamped with `label`). The whole file is read window by
    window; the agent may fetch chunks/sourcemaps and run scan-secrets via the tools, and every fetched body is
    also run through the deterministic nets so nothing is lost to under-reporting."""
    _harvest_deterministic(source, label, app_base, urls, libraries, secrets)   # the deterministic floor

    windows = _windows(source, max(4_000, args.window))
    sinks_present = sum(bool(rx.search(source)) for _, rx in _SINKS)
    debug_print(f"juicy :: analysing {label} ({len(source):,} chars, {len(windows)} window(s), "
                f"{sinks_present} sink-type(s) present)")

    intro = (f"ANALYSING: {label}\nENDPOINT ORIGIN (absolutise bare paths against this): {app_base}\n"
             f"SIZE: {len(source):,} chars, delivered in {len(windows)} window(s).\n\n{_static_hints(source)}\n\n"
             f"--- SOURCE WINDOW 1/{len(windows)} ---\n{windows[0]}\n\n"
             "Analyse this window. You may fetch referenced chunks/sourcemaps and run scan-secrets with the "
             "tools. "
             + ("More windows follow - emit a partial json for what you've found so far when done with this one."
                if len(windows) > 1 else "Then emit the final json."))
    messages = [{"role": "user", "content": intro}]
    delivered = 1
    asked_final = False

    for _ in range(max(1, args.max_steps)):
        try:
            resp = provider.send(_SYSTEM, messages, tools_spec)
        except Exception as exc:  # noqa: BLE001
            sys.stderr.write(f"juicy: provider error on {label}: {exc}\n")
            break
        text, calls = provider.parse(resp)
        messages += provider.assistant_msg(resp)
        if text.strip():
            flat = " ".join(text.split())
            debug_print("juicy> " + (flat if args.debug else flat[:220]))
            obj = extract_json(text)
            if isinstance(obj, dict) and (obj.get("urls") or obj.get("dom_xss") or obj.get("secrets")):
                _merge_urls(urls, obj.get("urls"), app_base, file=label)
                _merge_xss(xss, obj.get("dom_xss"), file=label)
                _merge_secrets(secrets, obj.get("secrets"), file=label)

        if calls:
            results = []
            for c in calls:
                if c["name"] not in _TOOLS:
                    results.append({"id": c["id"], "output": json.dumps({"error": f"{c['name']} not available"})})
                    continue
                argv = toolschema.to_argv(c["name"], c["args"])
                keyt = tuple(argv)
                count[keyt] = count.get(keyt, 0) + 1
                if count[keyt] > 2:
                    out = json.dumps({"success": False, "error": "already ran this exact call - reuse the result"})
                elif keyt in cache:
                    out = cache[keyt]
                    dbg(f"    (cache hit) {c['name']}")
                else:
                    debug_print("juicy> boxcutter " + " ".join(str(a) for a in argv))
                    out = _call(argv, headers, args.debug)
                    cache[keyt] = out
                    dbg(f"    <- {c['name']}: {agentlog.summarize(out)}")
                    fetched = argv[1] if len(argv) > 1 else label
                    if c["name"] == "http-request":
                        # a fetched chunk/sourcemap: run every deterministic net over its full body, then cap it
                        body = _body_of(out)
                        if body:
                            _harvest_deterministic(body, fetched, app_base, urls, libraries, secrets)
                        out = _cap_http(out)
                    elif c["name"] == "scan-secrets":
                        _merge_secrets(secrets, _secrets_from_scan(out), file=fetched)
                results.append({"id": c["id"], "output": out})
            messages += provider.tool_results(results)
            continue

        # no tool calls -> the agent finished the current material. Advance the window, or ask for the final.
        if delivered < len(windows):
            messages.append({"role": "user", "content":
                             f"--- SOURCE WINDOW {delivered + 1}/{len(windows)} ---\n{windows[delivered]}\n\n"
                             "Continue the analysis on this window (it overlaps the previous one). "
                             + ("More windows follow - partial json again when done."
                                if delivered + 1 < len(windows) else
                                "This is the LAST window - after it, emit the FINAL consolidated json.")})
            delivered += 1
            continue
        if not asked_final:
            messages.append({"role": "user", "content":
                             "All source has been delivered. Emit the FINAL consolidated json now: every hidden "
                             "URL, every XSS finding (class, verdict, source, sink, trace, snippet, PoC), and every "
                             "secret. One fenced json block, nothing after it."})
            asked_final = True
            continue
        break


def _fingerprint_file(label: str, source: str, app_base: str, urls: dict, libraries: dict, secrets: dict) -> None:
    """A vendor/framework bundle (jQuery, polyfills, runtime): run ONLY the deterministic nets - endpoints,
    library fingerprint, secrets - and DON'T spend LLM windows tracing taint through minified library code. Its
    DOM sinks are the 'known-vulnerable library' story, reported in the libraries list, not app-specific XSS."""
    debug_print(f"juicy :: fingerprint-only (vendor bundle) {label} ({len(source):,} chars) - nets only, no LLM")
    _harvest_deterministic(source, label, app_base, urls, libraries, secrets)


def add_arguments(parser) -> None:
    parser.add_argument("target", help="A URL: either a direct link to a .js file (analysed as-is), or a page "
                                       "URL (juicy fetches it and analyses the JS it loads)")
    parser.add_argument("--window", type=int, default=80_000, metavar="CHARS",
                        help="Analyse the source in windows of this many chars (large bundles are split so the "
                             "whole file is read, not just the head)")
    parser.add_argument("--max-files", dest="max_files", type=int, default=8, metavar="N",
                        help="When the target is a PAGE, analyse at most this many external <script> bundles "
                             "(same-origin first). Inline scripts are always analysed. Ignored for a direct .js")
    parser.add_argument("--no-verify", dest="no_verify", action="store_true",
                        help="Skip the independent re-verification pass. By default every XSS finding is "
                             "re-traced from scratch (refute-by-default) against the real code, so a "
                             "`confirmed` verdict can be trusted without redoing the work; refuted "
                             "false-positives are dropped")
    add_agent_args(parser, max_steps=24)


def _resolve_targets(target: str, headers: list, args, cache: dict, dbg) -> tuple:
    """Turn the target into the list of (label, source, is_vendor) JS files to analyse. A direct .js is one file;
    a PAGE is fetched, and its external <script src> bundles (app-first, capped by --max-files) plus its inline
    <script> blocks become the files. Every http-request envelope is stashed in `cache` so the agent re-fetching
    the same script later hits the cache. Returns (files, app_base, error). `app_base` is the origin bare
    endpoint paths absolutise against - the PAGE origin for a page, the file's origin for a direct .js."""
    debug_print(f"juicy :: fetching {target} ...")
    raw = _call(["http-request", target], headers, args.debug)
    cache[("http-request", target)] = raw
    resp = _resp_of(raw)
    body = resp.get("content") or ""
    if not body.strip():
        err = None
        try:
            err = json.loads(raw).get("error")
        except Exception:  # noqa: BLE001
            pass
        return [], "", f"could not fetch {target} ({err or 'empty body'})"

    parts = urlparse(target)
    origin = f"{parts.scheme}://{parts.netloc}"

    if _looks_like_js(target, resp):
        debug_print(f"juicy :: target is JavaScript ({len(body):,} chars) - analysing it directly")
        return [(target, body, _is_vendor(target))], origin, ""

    # it's a PAGE - discover the JS it loads
    ext, inline = _extract_scripts(body, target)
    ext = _order_scripts(ext, (parts.hostname or "").lower())
    n_vendor = sum(_is_vendor(u) for u in ext)
    debug_print(f"juicy :: HTML page - {len(ext)} external script(s) ({n_vendor} vendor, fingerprint-only) + "
                f"{len(inline)} inline block(s); analysing up to {args.max_files} external, app bundles first")
    files: list = []
    for i, block in enumerate(inline[:10], 1):          # inline blocks: app code, prime DOM-XSS spots
        files.append((f"inline#{i} @ {target}", block, False))
    fetched = 0
    for u in ext:
        if fetched >= max(1, args.max_files):
            break
        r2 = _call(["http-request", u], headers, args.debug)
        cache[("http-request", u)] = r2                # so the agent re-fetching this script hits the cache
        src = _body_of(r2)
        if src.strip():
            files.append((u, src, _is_vendor(u)))
            fetched += 1
            dbg(f"    <- fetched script {u} ({len(src):,} chars){' [vendor]' if _is_vendor(u) else ''}")
        else:
            dbg(f"    x script {u} came back empty - skipped")
    if not files:
        return [], origin, "the page loaded no analysable JavaScript (no external bundles, no inline scripts)"
    return files, origin, ""


def run(args) -> int:
    target = args.target.strip()
    if not target:
        output_result([], args.output, "a target URL is required")
        return 2
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    provider_cls = PROVIDERS[args.provider]
    key = args.api_key or os.environ.get(provider_cls.env)
    if not key:
        sys.stderr.write(f"juicy: provide --api-key or set {provider_cls.env} for --provider {args.provider}\n")
        return 2

    base_host = (urlparse(target).hostname or "").lower()
    headers = list(args.header or [])
    provider = provider_cls(args.model or provider_cls.default_model, key, base_url=args.base_url)

    # auth parsed out of --context (a cookie for a login-walled page/bundle). Reuses IRVIN's briefing parser.
    if args.context.strip():
        cfg = briefing.parse(provider, args.context, base_host)
        headers += cfg.get("headers", [])
        if cfg.get("headers"):
            sys.stderr.write("juicy :: auth header(s) parsed from --context (values hidden)\n")

    dbg = debug_logger(args.debug)
    cache: dict = {}          # shared http-request cache: seeded by resolution, reused across every file's agent

    # 1) RESOLVE the target into the JS file(s) to analyse (a direct .js, or a page's scripts).
    files, app_base, err = _resolve_targets(target, headers, args, cache, dbg)
    if err:
        output_result([], args.output, f"juicy: {err}")
        return 1

    tools_spec = toolschema.native_tools(_TOOLS)
    urls, xss, libraries, secrets = {}, {}, {}, {}
    count: dict = {}

    # 2) ANALYSE each file: app bundles get the full windowed LLM run; vendor bundles are fingerprint-only.
    for label, source, is_vendor in files:
        if is_vendor:
            _fingerprint_file(label, source, app_base, urls, libraries, secrets)
        else:
            _analyze_source(provider, label, source, app_base, headers, args, tools_spec,
                            urls, xss, libraries, secrets, cache, count, dbg)

    # 3) A `known-vuln-lib` row is a real FINDING only when the model traced a live app call site; an
    # unverifiable one is library noise already captured in the libraries list - drop it.
    xss_rows = [x for x in xss.values()
                if not (x["class"] == "known-vuln-lib" and x["verdict"] != "vulnerable")]

    # 4) VERIFY: anchor each finding in the real bytes, then independently re-trace it (refute-by-default). The
    # verification.status becomes the AUTHORITATIVE signal a teammate can trust; refuted false-positives are
    # dropped from the report.
    sources = {label: src for (label, src, _v) in files}
    for k, raw in cache.items():                    # a chunk/sourcemap the agent fetched can hold the sink too
        if isinstance(k, tuple) and len(k) == 2 and k[0] == "http-request":
            b = _body_of(raw)
            if b:
                sources.setdefault(k[1], b)
    verify = not getattr(args, "no_verify", False)
    if verify and xss_rows:
        debug_print(f"juicy :: independently re-verifying {len(xss_rows)} XSS finding(s) ...")
    for x in xss_rows:
        info, _code = _evidence(x, sources)
        if info:
            x["location"] = {"file": info["file"], "line": info["line"], "offset": info["offset"]}
            x["evidence_excerpt"] = info["excerpt"]
        if verify:
            v = _reverify_xss(provider, x, info, headers, args, toolschema.native_tools(["http-request", "js-endpoints"]),
                              cache, count, dbg)
            x["verification"] = {"status": v["status"], "trace": v["trace"], "evidence": v["evidence"],
                                 "poc": v["poc"], "reason": v["reason"], "method": "independent static re-trace"}
            if v["status"] == "confirmed":
                x["confidence"] = "confirmed"
                if v.get("poc"):
                    x["poc"] = v["poc"]
            debug_print(f"    [{v['status']:11}] {x['class']}: {x['source']} -> {x['sink']}"
                        + (f"  ({v['reason'][:60]})" if v["status"] != "confirmed" and v["reason"] else ""))
        else:
            x["verification"] = {"status": "not-run", "trace": "", "evidence": "", "poc": x["poc"],
                                 "reason": "re-verification skipped (--no-verify)", "method": "none"}

    # 5) TIER. When verified: confirmed (trust it) / needs-review (unconfirmed) / refuted (dropped). Without
    # verification, fall back to the model's own vulnerable/unverifiable split.
    def _tier(x):
        st = x["verification"]["status"]
        if st == "not-run":
            return "confirmed" if x["verdict"] == "vulnerable" else "needs-review"
        return {"confirmed": "confirmed", "refuted": "refuted"}.get(st, "needs-review")
    _rank = {"critical": 0, "high": 1, "medium": 2}
    confirmed = sorted([x for x in xss_rows if _tier(x) == "confirmed"],
                       key=lambda x: _rank.get(str(x["severity"]).lower(), 3))
    review = sorted([x for x in xss_rows if _tier(x) == "needs-review"],
                    key=lambda x: _rank.get(str(x["severity"]).lower(), 3))
    refuted = [x for x in xss_rows if _tier(x) == "refuted"]
    for x in review:                                # a needs-review finding carries no severity (unproven)
        x["severity"] = ""
    xss_items = confirmed + review                  # refuted are dropped from the report (counted below)

    url_items = list(urls.values())
    secret_items = sorted(secrets.values(), key=lambda s: _rank.get(str(s["severity"]).lower(), 3))
    lib_items = sorted(libraries.values(), key=lambda l: l["name"].lower())
    items = xss_items + secret_items + url_items    # findings first, then the surface

    debug_print(f"\njuicy :: {target}  ({len(files)} JS file(s) analysed)\n"
                f"  {len(url_items)} URL(s) | {len(secret_items)} secret(s) | {len(lib_items)} library(ies)\n"
                f"  XSS: {len(confirmed)} CONFIRMED, {len(review)} needs-review, {len(refuted)} refuted (dropped)")
    for x in confirmed[:10]:
        debug_print(f"    [CONFIRMED|{x['severity'] or '-'}] {x['class']}: {x['source']} -> {x['sink']}")
    for s in secret_items[:10]:
        debug_print(f"    [{s['severity']}] secret {s['kind']}: {s['match']}  ({s['where']})")

    extra = {"target": target, "files_analyzed": len(files), "urls": len(url_items),
             "xss_confirmed": len(confirmed), "xss_needs_review": len(review), "xss_refuted": len(refuted),
             "verification": "independent static re-trace" if verify else "not-run",
             "secrets": len(secret_items), "libraries": lib_items}
    report = _render_report(target, confirmed, review, refuted, secret_items, url_items, lib_items)
    write_report(getattr(args, "report", None), report)
    if getattr(args, "table", False) and not args.output:
        sys.stdout.write(report + "\n")
        if getattr(args, "jsonl", None):
            with open(args.jsonl, "w", encoding="utf-8") as fh:
                for it in items:
                    fh.write(json.dumps(it, ensure_ascii=False) + "\n")
    else:
        output_result(items, args.output, extra=extra)
    return 0


def _grid(rows: list, cols: list) -> str:
    """A simple aligned grid (used for the secrets/libraries/URL surface sections)."""
    if not rows:
        return "  (none)"
    head = [c[0] for c in cols]
    body = [[str(r.get(c[1], ""))[:c[2]] for c in cols] for r in rows]
    widths = [max(len(head[i]), *(len(b[i]) for b in body)) for i in range(len(cols))]
    line = lambda cells: "  ".join(c.ljust(widths[i]) for i, c in enumerate(cells))
    return "\n".join(["  " + line(head), "  " + "  ".join("-" * w for w in widths)] + ["  " + line(b) for b in body])


def _finding_block(x: dict, tier: str) -> str:
    """A detailed, shareable per-XSS block: verdict, location, independent trace, the real code excerpt, the
    firing PoC, and the decisive evidence - everything a teammate needs to check it without redoing the trace."""
    v = x.get("verification") or {}
    loc = x.get("location") or {}
    where = (f"{loc.get('file')} : offset {loc.get('offset')} (line {loc.get('line')})"
             if loc else x.get("file", "?"))
    sev = x["severity"] or "-"
    head = f"[{tier}] {x['class']} - {sev}" + (f"  (persistent/stored)" if x.get("persistent") else "")
    lines = [head,
             f"    source:   {x.get('source')}",
             f"    sink:     {x.get('sink')}",
             f"    location: {where}",
             f"    trace:    {v.get('trace') or x.get('trace')}"]
    if x.get("sanitizer"):
        lines.append(f"    sanitizer:{x.get('sanitizer')}")
    if x.get("evidence_excerpt"):
        excerpt = " ".join(str(x["evidence_excerpt"]).split())[:400]
        lines.append(f"    code:     {excerpt}")
    lines.append(f"    PoC:      {v.get('poc') or x.get('poc')}")
    if v.get("evidence"):
        lines.append(f"    evidence: {v.get('evidence')}")
    method = v.get("method", "none")
    status = v.get("status", "not-run")
    tail = f"    verified: {status} ({method})"
    if status not in ("confirmed", "not-run") and v.get("reason"):
        tail += f" - {v.get('reason')}"
    lines.append(tail)
    return "\n".join(lines)


def _render_report(target: str, confirmed: list, review: list, refuted: list,
                   secret_items: list, url_items: list, lib_items: list) -> str:
    """A readable, SECTIONED report for --table: CONFIRMED findings as detailed blocks (a teammate can check
    each without redoing the trace), then needs-review, then secrets / libraries / the URL surface as grids.
    The generic envelope renderer would union every column into one unusable grid - this is the shareable view."""
    out = [f"JUICY - {target}",
           f"XSS: {len(confirmed)} confirmed | {len(review)} needs-review | {len(refuted)} refuted   |   "
           f"{len(secret_items)} secret(s) | {len(lib_items)} library(ies) | {len(url_items)} URL(s)", ""]

    out.append(f"== CONFIRMED XSS ({len(confirmed)}) - independently re-traced ==")
    out.append("\n\n".join(_finding_block(x, "CONFIRMED") for x in confirmed) if confirmed
               else "  (none confirmed)")

    out += ["", f"== NEEDS REVIEW ({len(review)}) - a real sink, taint not fully proven statically =="]
    out.append("\n\n".join(_finding_block(x, "NEEDS-REVIEW") for x in review) if review else "  (none)")

    if refuted:
        out += ["", f"== REFUTED ({len(refuted)}) - re-trace found these were false positives, dropped =="]
        out += [f"  - {x['class']}: {x.get('source')} -> {x.get('sink')}  "
                f"({(x.get('verification') or {}).get('reason', '')[:100]})" for x in refuted]

    out += ["", f"== SECRETS ({len(secret_items)}) =="]
    out.append(_grid(secret_items, [("SEV", "severity", 8), ("KIND", "kind", 26), ("MATCH", "match", 28),
                                    ("WHERE", "where", 20), ("FILE", "file", 42)]))
    out += ["", f"== LIBRARIES ({len(lib_items)}) =="]
    out.append(_grid(lib_items, [("NAME", "name", 22), ("VERSION", "version", 10), ("NOTE", "cve_note", 62)]))
    out += ["", f"== URL SURFACE ({len(url_items)}) =="]
    out.append(_grid(url_items, [("METHOD", "method", 7), ("URL", "url", 68), ("KIND", "kind", 12),
                                 ("NOTE", "note", 38)]))
    return "\n".join(out)
