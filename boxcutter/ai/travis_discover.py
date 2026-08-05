"""Travis discovery pipeline (deterministic recon): a domain -> LIVE, wildcard-filtered, de-duped hosts + light
fingerprints. No vuln checking - just find the surface and describe it. The LLM ranking lives in travis.py; this
module is the mechanical part (enum -> brute -> resolve+wildcard-filter -> alive -> clever-mutate -> alive)."""
from __future__ import annotations

import concurrent.futures as cf
import json
import re

from ..core import fsutil, http
from ..core.permute import mutations

_HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,62}\.)+[a-z0-9][a-z0-9-]{0,62}$")
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_REC_RE = re.compile(r"^(\S+)\s+\[(A|AAAA|CNAME)\]\s+(\S+)")


def _data(raw: str) -> list:
    try:
        return [x for x in (json.loads(raw).get("data") or []) if x]
    except Exception:  # noqa: BLE001
        return []


def _names_under(items, base: str) -> set:
    """Pull hostnames under `base` out of subfinder hosts / wayback URLs."""
    base = base.lower()
    out = set()
    for it in items:
        s = str(it).strip().lower()
        m = re.search(r"https?://([^/:\s]+)", s)
        host = (m.group(1) if m else s).split("/")[0].split(":")[0].rstrip(".")
        if host == base or host.endswith("." + base):
            if _HOST_RE.match(host):
                out.add(host)
    return out


def _parse_dnsx(lines) -> dict:
    """Extract {host: [(rectype, value), ...]} from dnsx output. The host is ALWAYS the first token (works whether
    dnsx emits `host`, `host [NOERROR]`, or `host [A] 1.2.3.4`); the A/CNAME record is captured when present."""
    resolved = {}
    for ln in lines:
        ln = str(ln).strip()
        if not ln:
            continue
        host = ln.split()[0].lower().rstrip(".")
        if not host:
            continue
        resolved.setdefault(host, [])
        m = _REC_RE.match(ln)
        if m:
            resolved[host].append((m.group(2), m.group(3).lower()))
    return resolved


def _resolve(names, domain: str, call, dbg) -> dict:
    """dnsx-resolve a set of names; return {host: [(rectype, value), ...]}. (Wildcards are filtered later by content
    fingerprint - dnsx's own -wd flag is unreliable here and drops real hosts.)"""
    names = sorted(n for n in names if n)
    if not names:
        return {}
    f = fsutil.temp_file("travis_dnsx_")
    with open(f, "w", encoding="utf-8") as fh:
        fh.write("\n".join(names))
    raw = call(["dnsx", "--list", f, "--resp"])
    fsutil.remove(f)
    resolved = _parse_dnsx(_data(raw))
    dbg(f"  resolve: {len(names)} in -> {len(resolved)} resolving")
    return resolved


def _brute(domain: str, wordlist: str, call, dbg) -> dict:
    raw = call(["dnsx", "--domain", domain, "--wordlist", wordlist, "--resp"])
    resolved = _parse_dnsx(_data(raw))
    dbg(f"  brute: {len(resolved)} resolving names")
    return resolved


def _fp_key(info: dict):
    """A coarse content signature (status, title, length-bucket) for wildcard/dup detection."""
    return (info.get("status"), info.get("title", ""), (info.get("len", 0) // 512))


def _alive(hosts, headers, dbg, concurrency=24, drop_sigs=None) -> dict:
    """Parallel HTTP probe (https then http). Return {host: {url,status,title,server,len}} for responders, dropping
    any whose content signature matches `drop_sigs` (the wildcard fingerprint)."""
    drop_sigs = drop_sigs or set()
    hdrs = {}
    for h in (headers or []):
        if ":" in h:
            k, v = h.split(":", 1)
            hdrs[k.strip()] = v.strip()

    def probe(host):
        for scheme in ("https", "http"):
            try:
                r = http.send("GET", f"{scheme}://{host}/", timeout=10, allow_redirects=True, headers=hdrs)
            except Exception:  # noqa: BLE001
                continue
            if r.get("status"):
                body = r.get("body") or ""
                t = _TITLE_RE.search(body)
                return host, {"url": r.get("final_url") or f"{scheme}://{host}/", "status": r["status"],
                              "title": (re.sub(r"\s+", " ", t.group(1)).strip()[:140] if t else ""),
                              "server": str((r.get("headers") or {}).get("Server") or "")[:60],
                              "len": len(body)}
        return host, None

    live, dropped = {}, 0
    with cf.ThreadPoolExecutor(max_workers=max(1, concurrency)) as ex:
        for host, info in ex.map(probe, sorted(set(hosts))):
            if not info:
                continue
            if _fp_key(info) in drop_sigs:
                dropped += 1
                continue
            live[host] = info
    dbg(f"  alive: {len(live)} responded" + (f" ({dropped} wildcard-dropped)" if dropped else ""))
    return live


def _wildcard_probe(domain: str, headers, dbg) -> set:
    """Fetch a few RANDOM junk names under the domain; if they answer, their content signatures ARE the wildcard's
    fingerprint (real hosts serving the same page are then dropped). Empty when there's no wildcard (the usual case)."""
    from ..core.rand import random_string
    junk = [f"{random_string(14).lower()}.{domain}" for _ in range(3)]
    live = _alive(junk, headers, lambda _m: None)
    sigs = {_fp_key(info) for info in live.values()}
    if sigs:
        dbg(f"  wildcard zone detected: {len(sigs)} junk-content signature(s) will be dropped from results")
    return sigs


def discover(domain: str, args, call, dbg) -> dict:
    """Run the full pipeline. Returns {"resolved": {host:[recs]}, "live": {host:{fingerprint}}, "stats": {...}}."""
    domain = (domain or "").lower().strip().strip(".")
    headers = list(getattr(args, "header", None) or [])
    mut_cap = int(getattr(args, "mut_cap", 4000) or 4000)
    wild = _wildcard_probe(domain, headers, dbg)

    # 1) passive enum
    names = {domain}
    names |= _names_under(_data(call(["subfinder", domain])), domain)
    names |= _names_under(_data(call(["wayback", domain, "--inc-subdomains"])), domain)
    dbg(f"passive enum (subfinder+wayback): {len(names)} candidate names")

    # 2) active brute (optional wordlist)
    resolved = {}
    wl = getattr(args, "wordlist", None)
    if wl:
        resolved.update(_brute(domain, wl, call, dbg))
        names |= set(resolved.keys())

    # 3-4) resolve + wildcard-filter, then alive
    resolved.update(_resolve(names, domain, call, dbg))
    live = _alive(resolved.keys(), headers, dbg, drop_sigs=wild)

    # 5) clever mutation from what actually resolves -> resolve + filter + alive (one pass)
    muts = mutations(list(resolved.keys()) or list(names), domain, cap=mut_cap)
    dbg(f"mutation: {len(muts)} candidates derived from the discovered scheme")
    if muts:
        mres = _resolve(set(muts), domain, call, dbg)
        fresh = [h for h in mres if h not in resolved]
        resolved.update(mres)
        mlive = _alive([h for h in mres if h not in live], headers, dbg, drop_sigs=wild)
        live.update(mlive)
        dbg(f"mutation payoff: +{len(fresh)} new resolving, +{len(mlive)} new live")

    return {"resolved": resolved, "live": live,
            "stats": {"candidates": len(names), "resolving": len(resolved), "live": len(live),
                      "mutations_tried": len(muts)}}
