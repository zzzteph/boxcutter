#!/usr/bin/env python3
"""_report.py <url> <outdir> — build report.md from the caleb-lite scanner outputs in <outdir>.
Schema-tolerant: each boxcutter tool returns {success,data,...}; we pull the likely fields from each data item so a
minor schema difference degrades gracefully rather than crashing. Detection only — findings describe PRESENCE, never
an exploit."""
import json
import re
import sys
from collections import Counter
from pathlib import Path

URL = sys.argv[1]
OUT = Path(sys.argv[2])
SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "informational": 4}


def data(name):
    try:
        return json.loads((OUT / name).read_text()).get("data") or []
    except Exception:
        return []


def first(d, *keys, default=""):
    for k in keys:
        v = d.get(k) if isinstance(d, dict) else None
        if v:
            return v
    return default


findings = []   # (severity, issue, where, evidence, fix)
def add(sev, issue, where, ev, fix=""):
    findings.append(((sev or "info").lower(), issue, str(where)[:70], str(ev)[:80], fix))


# ---- security headers / cookies / version disclosure ----
fetch = data("fetch.json")
row = fetch[0] if fetch else {}
H = {k.lower(): v for k, v in (row.get("headers") or {}).items()}
status = row.get("status")
csp = H.get("content-security-policy", "").lower()
HDRS = [
    ("content-security-policy", "Missing Content-Security-Policy", "low", "Add a CSP restricting script/frame sources."),
    ("strict-transport-security", "Missing HSTS", "medium", "Add Strict-Transport-Security: max-age=31536000; includeSubDomains."),
    ("x-frame-options", "Missing clickjacking protection", "medium", "Set X-Frame-Options: DENY or CSP frame-ancestors 'none'."),
    ("x-content-type-options", "Missing nosniff", "low", "Set X-Content-Type-Options: nosniff."),
    ("referrer-policy", "Missing Referrer-Policy", "low", "Set Referrer-Policy: strict-origin-when-cross-origin."),
    ("permissions-policy", "Missing Permissions-Policy", "low", "Set a Permissions-Policy disabling unused features."),
]
if H:
    for k, issue, sev, fix in HDRS:
        if k in H:
            continue
        if k == "x-frame-options" and "frame-ancestors" in csp:
            continue
        add(sev, issue, URL, f"no {k} response header", fix)
    sc = H.get("set-cookie", "")
    if sc:
        low = sc.lower()
        for flag, name in (("secure", "Secure"), ("httponly", "HttpOnly"), ("samesite", "SameSite")):
            if flag not in low:
                add("medium", f"Cookie missing {name} flag", URL, sc[:60], f"Add {name} to session cookies.")
    for k in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
        if H.get(k) and re.search(r"\d", H[k]):
            add("low", "Software/version disclosure", URL, f"{k}: {H[k]}", "Suppress version banners.")

# ---- exposed sensitive files/dirs (path-bust) ----
SENS = re.compile(r"(^|/)(\.git|\.env|\.ds_store|\.svn|\.htpasswd|server-status|phpinfo|backup|dump|\.sql|\.bak|"
                  r"\.old|\.zip|\.tar|config\.|wp-config|id_rsa|\.aws|\.npmrc)", re.I)
for it in data("pathbust.json"):
    loc = first(it, "url", "path", "matched-at", "target", default=str(it))
    st = first(it, "status", "status_code", default="?")
    if SENS.search(str(loc)):
        add("high", "Exposed sensitive file/dir", loc, f"path-bust hit (status {st}); reported by presence, NOT downloaded",
            "Remove or deny access to this path.")

# ---- known issues (nuclei) ----
for it in data("nuclei.json"):
    info = it.get("info", {}) if isinstance(it.get("info"), dict) else {}
    sev = first(it, "severity", default=info.get("severity") or "info")
    name = first(it, "template-id", "templateID", "name", default=info.get("name") or "nuclei finding")
    loc = first(it, "matched-at", "url", "host", default=URL)
    add(sev, f"nuclei: {name}", loc, "detection template matched", "")

# ---- leaked secrets (redacted) ----
for it in data("secrets.json"):
    kind = first(it, "type", "name", "rule", "kind", default="secret")
    loc = first(it, "url", "location", "file", default=URL)
    add("high", f"Leaked secret: {kind}", loc, "secret pattern matched (value REDACTED)",
        "Rotate the key and remove it from the response.")

# ---- fuzz injection signals ----
try:
    for line in (OUT / "fuzz.jsonl").read_text().splitlines():
        j = json.loads(line)
        for it in (j.get("data") or []):
            sev = first(it, "severity", default="medium")
            title = first(it, "title", "name", "type", default="injection signal")
            add(sev, f"fuzz: {title} on param '{j.get('param')}'", URL, str(it)[:70],
                "Validate/parameterise input; confirm a SQLi with sqlmap (interactive skill).")
except Exception:
    pass

findings.sort(key=lambda f: (SEV_RANK.get(f[0], 5), f[1]))
counts = Counter(f[0] for f in findings)
summary = ", ".join(f"**{counts.get(s, 0)} {s}**" for s in ("critical", "high", "medium", "low"))
L = [f"# caleb-lite report — {URL}", "",
     f"_status {status} · server `{H.get('server', '?')}` · single-pass unauthenticated detection (no auth/lateral/exploit)_",
     "", f"- findings: {summary}", "",
     "| severity | issue | where | evidence | fix |", "|---|---|---|---|---|"]
for sev, issue, where, ev, fix in findings:
    L.append(f"| {sev} | {issue} | {where} | {ev} | {fix} |".replace("\n", " "))
if not findings:
    L.append("| info | nothing surfaced by the detection pass | | | |")
(OUT / "report.md").write_text("\n".join(L) + "\n")
print(f"report: {len(findings)} findings {dict(counts)} -> {OUT/'report.md'}")
