"""forge reporting: CWE tagging, a CVSS 3.1 heuristic, secret masking, and
platform report templates (HackerOne / Bugcrowd / Intigriti / Immunefi / generic).

CWE and CVSS are derived from a finding's vulnerability class and severity. The
CVSS score is a per-severity HEURISTIC (a real vector needs per-finding metrics);
the report labels unverified findings as candidates so the number is never passed
off as measured. Secret masking is mandatory: a live-looking credential is never
reprinted in full, so the report cannot itself become a leak vector.
"""

from __future__ import annotations

import re

# vulnerability class -> primary CWE id
_CWE = {
    "sqli": "CWE-89", "xss": "CWE-79", "ssti": "CWE-1336", "lfi": "CWE-98",
    "rce": "CWE-94", "xxe": "CWE-611", "nosql": "CWE-943", "idor": "CWE-639",
    "ssrf": "CWE-918", "open-redirect": "CWE-601", "graphql": "CWE-284",
    "swagger": "CWE-200", "secrets": "CWE-798", "info_disclosure": "CWE-200",
    "csrf": "CWE-352", "auth": "CWE-287", "privesc": "CWE-269", "cors": "CWE-942",
    "jwt": "CWE-347", "business_logic": "CWE-840", "other": "CWE-Other",
}

# severity -> (base score, representative CVSS 3.1 vector). Heuristic, see module docstring.
_CVSS = {
    "critical": (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "high":     (8.2, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"),
    "medium":   (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "low":      (3.1, "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N"),
    "info":     (0.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
}

_TAG = re.compile(r"\[([A-Za-z0-9_-]+)\]")
_HTTP_TAGS = {"get", "post", "put", "patch", "delete", "head", "options",
              "numeric", "custom", "custom-match"}
# a tool whose findings are all one class, when the title carries no class tag
_TOOL_CLASS = {"sqlmap": "sqli", "scan-secrets": "secrets", "graphql-audit": "graphql",
               "git-extract": "info_disclosure", "bola-walk": "idor", "mass-assign": "business_logic"}

# secret shapes to mask; long generic tokens after key=/token=/password= are masked too
_SECRET_RES = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ghp_[A-Za-z0-9]{36}"),
    re.compile(r"sk_live_[A-Za-z0-9]{16,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
    re.compile(r"(?i)(api[_-]?key|token|secret|password)\s*[=:]\s*['\"]?([A-Za-z0-9_\-\.]{16,})"),
]
_PRIVKEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S)


def class_of(f: dict) -> str:
    if f.get("class"):
        return f["class"]
    for tag in _TAG.findall(str(f.get("title", ""))):
        t = tag.lower()
        if t not in _HTTP_TAGS and t in _CWE:
            return t
    return _TOOL_CLASS.get(f.get("source", ""), "other")


def cwe_of(cls: str) -> str:
    return _CWE.get(cls, "CWE-Other")


def cvss_of(severity: str) -> tuple[float, str]:
    return _CVSS.get((severity or "info").lower(), _CVSS["info"])


def enrich(findings: list) -> None:
    """Tag each finding in place with class, cwe, cvss score, and cvss vector."""
    for f in findings:
        if not isinstance(f, dict):
            continue
        cls = class_of(f)
        f["class"] = cls
        f["cwe"] = cwe_of(cls)
        score, vector = cvss_of(f.get("severity", "info"))
        f["cvss"] = score
        f["cvss_vector"] = vector


def _mask_token(tok: str) -> str:
    if len(tok) <= 8:
        return "*" * len(tok)
    return tok[:4] + "*" * (len(tok) - 8) + tok[-4:]


def mask(text: str) -> str:
    """Redact live-looking secrets: keep first 4 + last 4 chars, mask the middle."""
    if not text:
        return text or ""
    out = _PRIVKEY.sub("-----BEGIN PRIVATE KEY----- [REDACTED] -----END PRIVATE KEY-----", text)
    for rx in _SECRET_RES:
        def _sub(m):
            g = m.group(2) if m.lastindex and m.lastindex >= 2 else m.group(0)
            masked = _mask_token(g)
            return m.group(0).replace(g, masked)
        out = rx.sub(_sub, out)
    return out


# --- platform templates -------------------------------------------------------

_LABELS = {
    "h1":        ("Summary", "Steps To Reproduce", "Impact", "Remediation"),
    "bugcrowd":  ("Summary", "Steps to Reproduce", "Impact", "Remediation"),
    "intigriti": ("Description", "Proof of Concept", "Impact", "Recommendation"),
    "immunefi":  ("Bug Description", "Attack Scenario", "Impact", "Recommendation"),
    "generic":   ("Summary", "Evidence", "Impact", "Remediation"),
}


def _finding_block(f: dict, fmt: str) -> list[str]:
    summary, poc, impact, remedy = _LABELS.get(fmt, _LABELS["generic"])
    verdict = f.get("verdict", "")
    tag = f" ({verdict})" if verdict and verdict != "confirmed" else ""
    return [
        f"### [{f.get('severity','info')}] {f.get('title','')}{tag}",
        f"- **Class / CWE:** {f.get('class','other')} / {f.get('cwe','CWE-Other')}",
        f"- **CVSS 3.1 (heuristic):** {f.get('cvss','?')} `{f.get('cvss_vector','')}`",
        f"- **URL:** {f.get('url','')}",
        f"- **Source tool:** {f.get('source','')}",
        f"- **Verdict:** {f.get('verdict','open_proof_gap')} - {f.get('verdict_reason','')}",
        "",
        f"**{summary}.** {mask(str(f.get('title','')))}",
        "",
        f"**{poc}.** {mask(str(f.get('info','')) or 'See the URL and source tool above; evidence in run.jsonl.')}",
        "",
        f"**{impact}.** Severity {f.get('severity','info')}; see CVSS above.",
        "",
        f"**{remedy}.** Address the {f.get('class','other')} weakness ({f.get('cwe','')}).",
        "",
    ]


def render(target: str, model: dict, findings: list, chains: list, loaded: list, fmt: str) -> str:
    fmt = (fmt or "generic").lower()
    sev: dict = {}
    for f in findings:
        sev[f.get("severity", "info")] = sev.get(f.get("severity", "info"), 0) + 1
    lines = [f"# forge report - {target}", "",
             f"- format: {fmt}", f"- findings: {len(findings)}",
             f"- by severity: {sev}", ""]

    # target model (the forge analog of the maps) - what was mapped, before findings
    lines += ["## Target model", ""]
    if model.get("identities"):
        lines.append(f"- identities: {', '.join(model['identities'])} (+ anon)")
    for a in model.get("assets", []):
        score = f"[score {a['score']}] " if a.get("score") is not None else ""
        lines.append(f"- {score}**{a.get('asset','')}** - urls: {a.get('url_count',0)}, "
                     f"params: {len(a.get('param_urls',[]))}, js: {len(a.get('js_urls',[]))}, "
                     f"graphql: {len(a.get('graphql',[]))}, swagger: {len(a.get('swagger_specs',[]))}"
                     + (f", tech: {', '.join(a['tech'])}" if a.get('tech') else ""))
    if loaded:
        lines.append(f"- playbooks loaded: {', '.join(loaded)}")
    lines.append("")

    lines += ["## Findings", ""]
    for f in findings:
        lines += _finding_block(f, fmt)

    if chains:
        lines += ["## Chains", ""]
        for c in chains:
            lines.append(f"- [{c.get('severity','?')}] {c.get('name','')}: "
                         + " -> ".join(str(x) for x in c.get("steps", []))
                         + (f" - {c.get('why','')}" if c.get("why") else ""))
        lines.append("")
    return "\n".join(lines)
