"""Shared soft-404 / catch-all detection for the path tools (path-fuzz, path-bust).

The hard part of path discovery is telling a REAL path from a catch-all / soft-404 / front-controller that
answers for EVERY path. We fingerprint responses by CONTENT and STRUCTURE (never size) and compare them FUZZILY
(Jaccard over the HTML tag-skeleton + normalised-text shingles), so a catch-all that carries per-request noise
(a rotating nonce, an ad, a CSRF token) STILL matches its baseline. The fuzzed token is stripped first so a
reflected path can't make a not-found page look distinct.

Precision over recall: when a hit resembles the catch-all it is a GHOST and dropped. The goal is a
false-positive-free list - better to miss a borderline path than report a ghost.
"""

from __future__ import annotations

import html
import re
import time

from . import http
from .rand import random_string

_TAG = re.compile(r"<\s*(/?[a-zA-Z][a-zA-Z0-9]*)")
_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_MARKUP = re.compile(r"<[^>]+>")
_REDIRECT = {301, 302, 303, 307, 308}
STRUCT_SIM = 0.90     # tag-skeleton Jaccard >= this = same structural template (a catch-all)
TEXT_SIM = 0.90       # normalised-text Jaccard  >= this = same page content
HOMOGENEOUS_CATCHALL = 10   # this many identical hits in ONE directory = a catch-all cluster, not real paths


def shingles(tokens: list, k: int = 3, cap: int = 800) -> frozenset:
    """A capped set of overlapping k-grams - compared with Jaccard. For a very short token list, the tokens
    themselves (so two near-empty pages don't spuriously match on an empty set)."""
    if len(tokens) < k:
        return frozenset(tokens)
    return frozenset(" ".join(tokens[i:i + k]) for i in range(min(len(tokens) - k + 1, cap)))


def jaccard(a: frozenset, b: frozenset) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def _neutralize(text: str, token: str) -> str:
    """Remove a REFLECTED path echo (e.g. a 404 that prints the requested path) from VISIBLE TEXT so two
    different words don't look like two different pages - but only the token as a whole word, case-insensitively,
    and only when it is long enough to be meaningful reflected noise. Applied to tag-stripped text ONLY, never
    the markup: a reflected path changes a page's text, never its HTML tag structure, so the tag skeleton is
    fingerprinted from the RAW body and stays reflection-immune (this is why stripping the token from the whole
    body was wrong - a token like "title" or "e" would shred real tags like <title> and make a catch-all look
    distinct)."""
    text = text or ""
    if not token or len(token) < 3:
        return text
    return re.sub(r"(?<![A-Za-z0-9_-])" + re.escape(token) + r"(?![A-Za-z0-9_-])", "", text, flags=re.I)


def fingerprint(status, headers, body: str, token: str) -> dict:
    """A soft-404-robust fingerprint: status, redirect target, title, normalised length, and two SHINGLE SETS
    (HTML tag-skeleton + normalised text). The tag skeleton comes from the RAW body (structure can't be forged
    by a reflected path); the title and text come from tag-stripped VISIBLE text with the reflected token removed
    so an echoed path can't make a not-found page look distinct."""
    raw = (body or "")[:500000]
    tags = shingles(_TAG.findall(raw.lower()), 3, 800)                     # structure: never token-stripped
    m = _TITLE.search(raw)
    title = _neutralize(re.sub(r"\s+", " ", (m.group(1) if m else "")).strip(), token).strip().lower()[:120]
    visible = _neutralize(_MARKUP.sub(" ", raw), token)                    # visible text, reflected path removed
    norm = re.sub(r"\s+", " ", re.sub(r"\d+", "#", visible)).strip()
    loc = ""
    if status in _REDIRECT:
        loc = str(headers.get("Location") or headers.get("location") or "").split("?")[0].split("#")[0]
    return {"code": status, "loc": loc, "title": title, "len": len(norm),
            "tags": tags, "text": shingles(norm.split(), 3, 600)}


def similar(a: dict, b: dict) -> bool:
    """True when two responses are the SAME page for soft-404 purposes: same status AND one strong match -
    identical redirect target, same title with a close length, or a high FUZZY (Jaccard) overlap of the HTML
    tag-skeleton or the normalised text (which tolerates the per-request noise a catch-all injects)."""
    if a["code"] != b["code"]:
        return False
    if a["loc"] and a["loc"] == b["loc"]:
        return True
    if a["title"] and a["title"] == b["title"]:
        span = max(a["len"], b["len"], 1)
        if abs(a["len"] - b["len"]) / span < 0.25:
            return True
    if len(a["tags"]) >= 3 and jaccard(a["tags"], b["tags"]) >= STRUCT_SIM:
        return True
    if len(a["text"]) >= 3 and jaccard(a["text"], b["text"]) >= TEXT_SIM:
        return True
    # Tiny, structure-less bodies (no tags, no title) give the fuzzy branches nothing to grip - an 11-byte
    # catch-all stub would otherwise look "distinct" from every other tiny body. Fall back to EXACT match:
    # same normalised length AND identical normalised text (digit-normalisation already folds numeric nonces).
    if len(a["tags"]) < 3 and len(b["tags"]) < 3 and not a["title"] and not b["title"]:
        return a["len"] == b["len"] and a["text"] == b["text"]
    return False


def page_title(body: str) -> str:
    """The page's real <title> for display (original case, HTML-entities decoded), or '' if none."""
    m = _TITLE.search(body or "")
    if not m:
        return ""
    return html.unescape(re.sub(r"\s+", " ", m.group(1)).strip())[:200]


def is_ghost(sig: dict, baselines: list) -> bool:
    return any(similar(sig, b) for b in baselines)


def is_dir(word: str, sig: dict) -> bool:
    """A path worth recursing INTO: a redirect to its own trailing-slash form (definitive directory), or an
    extension-less final segment (dir-like). A file with an extension (foo.php) is not a directory."""
    seg = word.rstrip("/").split("/")[-1]
    if sig["loc"].endswith("/") and sig["loc"].rstrip("/").endswith(seg):
        return True
    return "." not in seg


def calibrate(make_url, method: str, sess, dbg) -> list:
    """Fingerprint several random NONEXISTENT paths of varied shapes (redirects visible) to learn THIS
    directory's catch-all behaviour. `make_url(token)` builds the probe URL."""
    probes = [random_string(20), "notreal-" + random_string(12) + ".php", random_string(15) + ".bak",
              "zzq-" + random_string(10), random_string(8) + "/" + random_string(8)]
    baselines = []
    for p in probes:
        r = http.send(method, make_url(p), sess=sess, timeout=8, allow_redirects=False)
        if r["status"] is not None:
            baselines.append(fingerprint(r["status"], r["headers"], r["body"], p))
    seen = sorted({b["code"] for b in baselines})
    if not baselines:
        dbg("  WARNING: baseline probes failed - results UNGATED for this directory")
    elif any(c == 200 or c in _REDIRECT for c in seen):
        dbg(f"  catch-all: nonexistent paths return {seen} here - gating on content/structure")
    else:
        dbg(f"  honest {seen} for nonexistent paths here")
    return baselines


def scan(make_url, method: str, words: list, sess, deadline: float, codes: set, dbg) -> tuple:
    """Fuzz one directory: calibrate its OWN catch-all, then report only words whose status is in `codes` and
    that are structurally DISTINCT from the baseline. Returns (findings, dir_words) - directories (real, not
    ghosts) to recurse into, even when their redirect status isn't in `codes`."""
    baselines = calibrate(make_url, method, sess, dbg)
    findings, fsig = [], []              # fsig[i] = the response signature of findings[i] (parallel list)
    dir_cands = []                       # (word, sigkey) directories to maybe recurse into
    sig_count, catchall = {}, set()      # per-signature hit count; signatures proven to be a catch-all cluster
    total = len(words)
    start = last = time.time()

    def _sk(st, sig):                    # a hashable identity of the RESPONSE (text is already a frozenset)
        return (st, sig["len"], sig["text"])

    for i, word in enumerate(words, 1):
        now = time.time()
        if now >= deadline:
            dbg(f"  timeout reached ({i - 1}/{total} scanned this directory)")
            break
        if now - last >= 15:                       # heartbeat so a long ghost-heavy scan isn't silent
            rate = i / max(now - start, 1e-3)
            eta = (total - i) / rate if rate else 0
            dbg(f"  ...{i}/{total} scanned, {len(findings)} found ({now - start:.0f}s elapsed, ~{eta:.0f}s left here)")
            last = now
        url = make_url(word)
        r = http.send(method, url, sess=sess, timeout=8, allow_redirects=False)
        st = r["status"]
        if st is None:
            continue
        sig = fingerprint(st, r["headers"], r["body"], word)
        if is_ghost(sig, baselines):
            continue
        if st in codes:
            sk = _sk(st, sig)
            if sk in catchall:                     # a code-dependent catch-all calibration missed - suppress
                continue
            sig_count[sk] = sig_count.get(sk, 0) + 1
            if sig_count[sk] >= HOMOGENEOUS_CATCHALL:
                catchall.add(sk)                   # too many IDENTICAL hits here => it's the catch-all, not paths
                n = sum(1 for s in fsig if s == sk)
                findings = [f for f, s in zip(findings, fsig) if s != sk]
                fsig = [s for s in fsig if s != sk]
                dbg(f"  catch-all cluster: {HOMOGENEOUS_CATCHALL}+ identical {st}/{sig['len']}b responses here "
                    f"- dropped {n} and suppressing further (code-dependent catch-all)")
                continue
            loc = f" -> {sig['loc']}" if sig["loc"] else ""
            pt = page_title(r["body"])
            size = r["body_bytes"]
            dbg(f"  [{st}] {url} ({size}b, distinct){loc}" + (f'  "{pt}"' if pt else ""))
            findings.append({"severity": "info", "title": f"path: {url}", "url": url,
                             "status": st, "size": size, "page_title": pt, "loc": sig["loc"],
                             "info": f"HTTP {st}{loc}, {size}b" + (f', title "{pt}"' if pt else "")
                                     + f", structure-distinct from soft-404 (word: {word})"})
            fsig.append(sk)
            if is_dir(word, sig):
                dir_cands.append((word, sk))
        elif st in _REDIRECT and is_dir(word, sig):
            dir_cands.append((word, _sk(st, sig)))   # a directory reachable only via a redirect

    # Don't recurse into directories that turned out to be part of a catch-all cluster (would spawn more of it).
    dirs = [w for (w, sk) in dir_cands if sk not in catchall]
    return findings, dirs


def dedup(findings: list) -> list:
    """Collapse findings that are the SAME page - identical status, byte size, title AND redirect target - into
    one, listing the rest as `aliases`. This kills the common noise of one page served at several paths (e.g. an
    nginx default at /admin, /admin/ and /admin/index.php). Conservative by design: a four-way exact-identity
    match, so genuinely different endpoints are never merged; the merged URLs are preserved as aliases, not lost."""
    out, by_id = [], {}
    for f in findings:
        key = (f.get("status"), f.get("size"), f.get("page_title", ""), f.get("loc", ""))
        rep = by_id.get(key)
        if rep is None:
            by_id[key] = f
            out.append(f)
        else:
            rep.setdefault("aliases", []).append(f["url"])
    for f in out:
        n = len(f.get("aliases", []))
        if n:
            shown = ", ".join(f["aliases"][:5]) + (", ..." if n > 5 else "")
            f["info"] += f" (+{n} identical page(s): {shown})"
    return out


def parse_codes(raw: str, default=(200,)) -> set:
    codes = {int(c) for c in re.split(r"[,\s]+", raw or "") if c.strip().isdigit()}
    return codes or set(default)
