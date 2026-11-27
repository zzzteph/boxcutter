"""Findings normalization, fingerprinting, and the rescan reconcile (auto states: new / open / resolved)."""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit

from sqlalchemy import delete, func, update
from sqlmodel import Session, select

from .assets import classify as classify_asset
from .models import Finding, ScanItem

# Informational reconnaissance / reachability items (e.g. "host reachable") are not issues and must not render
# as findings.
_NON_ISSUE_TITLE = re.compile(
    r"\b(reachable|is up|is alive|host up|alive|resolved to|responded|open port|"
    r"no (issues|findings|vulnerabilit))\b", re.I)
_RECON_CLS = {"recon", "reachable", "up", "alive", "info", "dns", "portscan", "port", "ping"}


def is_issue(f: dict) -> bool:
    """True if an engine-envelope item is a real finding worth surfacing; False for pure recon/reachability
    signals. Anything with a genuine severity and a non-recon class is kept."""
    title = str(f.get("title", ""))
    if _NON_ISSUE_TITLE.search(title):
        return False
    sev = str(f.get("severity", "")).strip().lower()
    cls = str(f.get("cls", "")).strip().lower()
    if sev in ("", "info", "informational", "none") and cls in _RECON_CLS:
        return False
    return True


# Keys an engine may use for a plain listable result, best first. A workflow that enumerates URLs/hosts
# returns these instead of findings, and they must not be thrown away just because they aren't issues.
_ITEM_KEYS = ("url", "value", "item", "endpoint", "location", "host", "domain", "ip", "path", "name")


def item_value(entry) -> str:
    """The listable value in an envelope entry that is not a finding. Bare strings count — a tool may simply
    return a list of URLs — and dicts give up their first item-ish key. Empty means there is nothing to list."""
    if isinstance(entry, (str, int)):
        return str(entry).strip()[:2048]
    if isinstance(entry, dict):
        for k in _ITEM_KEYS:
            v = entry.get(k)
            if isinstance(v, (str, int)) and str(v).strip():
                return str(v).strip()[:2048]
    return ""


def item_fingerprint(target: str, value: str) -> str:
    return hashlib.sha256("|".join([target or "", normalize_url(value) or value]).encode()).hexdigest()


def upsert_item(session: Session, scan_id: int, kind: str, target: str, value: str,
                label: str = "", cls: str = "", run_no: int = 0, stage: int = 0) -> bool:
    """Insert a non-finding item, or bump `last_seen` if this scan already has it (so a rerun refreshes rather
    than duplicates). Returns True when the row is new. `stage` is the pipeline stage that first produced it."""
    fp = item_fingerprint(target, value)
    row = session.exec(select(ScanItem).where(ScanItem.scan_id == scan_id,
                                              ScanItem.fingerprint == fp)).first()
    at = datetime.now(timezone.utc)
    if row is not None:
        row.last_seen, row.run_no = at, run_no
        session.add(row)
        return False
    row = ScanItem(scan_id=scan_id, target=target, template_kind=kind, fingerprint=fp,
                   value=value[:2048], asset_type=classify_asset(value), label=(label or "")[:400],
                   run_no=run_no, stage=stage, first_seen=at, last_seen=at)
    row.cls = (cls or "")[:120]      # 'cls' can't be a constructor kwarg (shadows __new__), same as Finding
    session.add(row)
    return True


def _aware(dt: datetime | None) -> datetime | None:
    """SQLite hands datetimes back naive; treat stored times as UTC so comparisons are safe."""
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def normalize_url(u: str) -> str:
    try:
        p = urlsplit(u or "")
        return urlunsplit((p.scheme.lower(), p.netloc.lower(), (p.path.rstrip("/") or "/"), "", ""))
    except Exception:  # noqa: BLE001
        return u or ""


def fingerprint(target: str, kind: str, cls: str, severity: str, url: str, title: str) -> str:
    raw = "|".join([target or "", kind or "", (cls or "").lower(), (severity or "").lower(),
                    normalize_url(url), (title or "").strip().lower()])
    return hashlib.sha256(raw.encode()).hexdigest()


def upsert_finding(session: Session, scan_id: int, kind: str, target: str, f: dict,
                   run_no: int = 0, stage: int = 0) -> tuple[str, bool]:
    """Insert or refresh a finding from one engine-envelope item; returns (fingerprint, created). A resolved
    finding that shows up again flips back to open. `last_seen` is bumped on every sighting — reconcile uses it
    to decide what this run saw. The (scan_id, fingerprint) lookup is indexed for fast ingestion at scale."""
    fp = fingerprint(target, kind, f.get("cls", ""), f.get("severity", ""), f.get("url", ""), f.get("title", ""))
    now = datetime.now(timezone.utc)
    existing = session.exec(select(Finding).where(
        Finding.scan_id == scan_id, Finding.fingerprint == fp)).first()
    raw = json.dumps(f)[:8000]                # keep the full item boxcutter reported, for the detail view
    if existing:
        existing.last_seen = now
        existing.raw_json = raw
        if existing.state in ("unconfirmed", "resolved"):
            existing.state = "open"           # re-checked and still there
        session.add(existing)
        return fp, False
    finding = Finding(
        scan_id=scan_id, target=target, fingerprint=fp, template_kind=kind,
        severity=str(f.get("severity", "info")).title(), title=str(f.get("title", ""))[:300],
        url=f.get("url", ""),
        evidence=str(f.get("evidence", ""))[:2000], reproduce=str(f.get("reproduce", ""))[:2000],
        raw_json=raw, state="new", first_seen=now, last_seen=now, stage=stage)
    finding.cls = str(f.get("cls", "")).lower()   # 'cls' can't be a constructor kwarg (shadows __new__)
    session.add(finding)
    session.flush()                           # so a duplicate in the same result batch is seen as existing
    return fp, True


def reconcile_run(session: Session, scan_id: int, run_no: int, cutoff: datetime | None) -> dict:
    """After a run (whose jobs started at `cutoff`) finishes, bring the scan's findings up to date:

    - found again this run, first seen earlier              -> ``open``
    - first found this run                                 -> ``new`` (set at insert time)
    - NOT found this run, and its step successfully re-ran on the same target this run
                                                            -> deleted (it is gone - fixed or no longer there)
    - NOT found this run, but its step could not re-check that target (the job failed, or the target was not
      reached this time, e.g. a host that wasn't rediscovered) -> ``unconfirmed``, kept until a run checks it

    Returns {"new", "open", "unconfirmed", "removed", "removed_list": [{severity, title, target}, ...]}."""
    from .models import Job, Target
    cut = _aware(cutoff)
    removed: list[dict] = []
    if cut is not None:
        # every (step, target) this run positively re-checked: its job finished successfully
        checked = set(session.exec(select(Job.stage, Target.value).join(Target, Target.id == Job.target_id).where(
            Job.scan_id == scan_id, Job.run_no == run_no, Job.status == "done")).all())
        # a sql-leads step (sqlmap) only runs when fuzz flags SQL injection: a fuzz job that finished clean
        # re-checked that target for the sqlmap step too, so an old sqlmap finding there is gone
        from .models import Scan
        from .pipeline import SEED, lead_value
        scan = session.get(Scan, scan_id)
        try:
            plan = json.loads(scan.plan_json or "[]") if scan else []
        except Exception:  # noqa: BLE001
            plan = []
        lead_kids: dict[int, list[int]] = {}
        for i, st in enumerate(plan if isinstance(plan, list) else []):
            if st.get("input") == "sql-leads":
                for p in st.get("from", []):
                    if p != SEED:
                        lead_kids.setdefault(p, []).append(i)
        for stage, value in list(checked):
            for kid in lead_kids.get(stage, []):
                checked.add((kid, lead_value(value)))
        stale = session.exec(select(Finding.id, Finding.stage, Finding.target, Finding.severity, Finding.title).where(
            Finding.scan_id == scan_id, Finding.last_seen < cut)).all()
        gone = [r for r in stale if (r[1], r[2]) in checked]
        keep = [r[0] for r in stale if (r[1], r[2]) not in checked]
        removed = [{"severity": r[3], "title": r[4], "target": r[2]} for r in gone]
        ids = [r[0] for r in gone]
        for i in range(0, len(ids), 1000):
            session.execute(delete(Finding).where(Finding.id.in_(ids[i:i + 1000])))
        for i in range(0, len(keep), 1000):
            session.execute(update(Finding).where(Finding.id.in_(keep[i:i + 1000])).values(state="unconfirmed"))
        session.execute(update(Finding).where(
            Finding.scan_id == scan_id, Finding.state == "new",
            Finding.last_seen >= cut, Finding.first_seen < cut
        ).values(state="open"))                           # carried-over findings seen again -> open
        session.commit()

    def _count(state: str) -> int:
        return session.exec(select(func.count()).select_from(Finding).where(
            Finding.scan_id == scan_id, Finding.state == state)).one()
    return {"new": _count("new"), "open": _count("open"), "unconfirmed": _count("unconfirmed"),
            "removed": len(removed), "removed_list": removed}
