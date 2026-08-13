"""irvin control roles - the post-hunt agents that operate on the aggregated findings (one each, not a pool).

  Verifier     : independent existence re-check of every finding - drops any whose page provably 404s, so a
                 non-existent page can never reach the report.
  Consolidator : collapses provably-identical findings (same sink reached via several routes) into one.
  Reporter     : writes the CEO executive summary + the technical findings report over the verified findings.

The conductor (irvin/pipeline.py) drives the proven standalone agents travis/bob/caleb; these three run after
the scan to clean up and report. The old suggester council / planner / executor roles are gone.
"""

from __future__ import annotations

import json
import time
from urllib.parse import urlparse, urlunparse

from ..context import extract_json


class Verifier:
    """Runs after the hunt, before consolidation: an INDEPENDENT existence re-check of EVERY finding, so IRVIN
    can never report a vulnerability on a page that isn't actually there. Executors self-verify, but a
    self-verifying agent can still stand a finding on a URL that never truly existed - a dirbust guess that
    never 200'd, a mirror path sqlmap skipped, an endpoint the model half-invented. This gate re-fetches each
    finding's own location through the same runner the executors use and DROPS only the findings whose page is
    PROVABLY absent (a hard 404/410). It is deliberately conservative: a page that answers with anything else -
    200, 301, 401/403, even 500 - is real and kept, and an unreachable/unparseable response is KEPT-but-flagged
    (a transient network failure must not delete a real finding). Every drop is written to the trail, so a
    removed finding is auditable, never silently gone.

    It fetches the BASE path (scheme://host/path), dropping any injected query/payload the finding URL carries,
    so a real endpoint like `/?id=1' UNION...` is checked as `/` and can't be mistaken for absent."""
    name = "verifier"
    role = "verifier"

    _ABSENT = {404, 410}

    def _check(self, ctx, runner, url) -> tuple[str, str]:
        """(verdict, note) where verdict is 'exists' | 'absent' | 'unconfirmed'. Only 'absent' is a proven
        non-existent page (the one thing we drop)."""
        p = urlparse(url or "")
        if not p.scheme or not p.hostname:
            return "unconfirmed", "no fetchable URL - existence not checked"
        base = urlunparse((p.scheme, p.netloc, p.path or "/", "", "", ""))
        out = runner(["http-request", base], ctx=ctx, allowed={"http-request"})
        try:
            obj = json.loads(out)
        except Exception:  # noqa: BLE001
            return "unconfirmed", "unparseable response - kept (not proven absent)"
        data = obj.get("data") or []
        status = data[0].get("status") if data and isinstance(data[0], dict) else None
        if status in self._ABSENT:
            return "absent", f"page does not exist (HTTP {status} at {base})"
        if status:
            return "exists", f"exists (HTTP {status})"
        if obj.get("error"):
            return "unconfirmed", f"unreachable: {str(obj.get('error'))[:80]} - kept (not proven absent)"
        return "unconfirmed", "no status - kept (not proven absent)"

    def verify(self, ctx, runner) -> dict:
        fnds = ctx.landscape["findings"]
        kept, dropped, flagged = [], [], []
        for f in fnds:
            verdict, note = self._check(ctx, runner, f.get("url") or "")
            if verdict == "absent":
                dropped.append({"id": f["id"], "title": f["title"], "url": f["url"], "reason": note})
                continue
            if verdict == "unconfirmed":
                f["status"] = "unconfirmed-existence"
                flagged.append({"id": f["id"], "note": note})
            kept.append(f)
        if dropped:
            ctx.landscape["findings"] = kept
        return {"kept": len(kept), "dropped": dropped, "flagged": flagged}


class Consolidator:
    """Runs ONCE after the hunt, right before the reporter. IRVIN files a finding the moment it confirms one,
    so the SAME underlying vulnerability lands as SEVERAL findings - reached through different endpoints, or
    re-confirmed in a later round with different wording (this is exactly how one `where id=$id` behind /?id,
    /bugs/verify.php and /gotoURL.asp became five separate High rows).

    The fix is NOT a heuristic in either direction. Reporting each endpoint separately OVER-counts one bug;
    blindly merging every same-class finding on a host UNDER-counts distinct bugs (two different features that
    both query the one database are two vulnerabilities, not one). Neither guess is acceptable, so this is a
    VERIFICATION step, held to the same evidence bar as every other IRVIN verdict: two findings collapse into
    one ONLY when the evidence PROVES they hit the same sink/object/code path - the merge has to be earned, and
    when it can't be, the findings stay separate."""
    name = "consolidator"
    role = "consolidator"

    _SEV = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

    SYSTEM = (
        "You are the CONSOLIDATOR of IRVIN. IRVIN files a finding as soon as it confirms one, so the SAME "
        "underlying vulnerability often appears MORE THAN ONCE - reached through different endpoints, or "
        "re-confirmed in a later round with different wording. Working one CLASS at a time, decide which "
        "findings are PROVABLY the one-and-the-same bug (report them as a SINGLE finding with several affected "
        "locations) and which are genuinely DISTINCT (leave them alone).\n"
        "The bar to MERGE is EVIDENCE, never assumption:\n"
        "  - MERGE only when the evidence shows the SAME sink/object: the same injectable query (same table, "
        "same column count, same WHERE shape), the same file read, the same handler/code path - such that ONE "
        "fix closes all of them. Re-confirmations of the identical endpoint across rounds are the clearest "
        "merge.\n"
        "  - A SHARED error/stack-trace LOCATION across findings on DIFFERENT urls - the SAME source file:line "
        "(e.g. every one reports `/app/index.php:53`), the same DBMS + query shape - is STRONG proof of ONE sink "
        "reached through many routes (a front controller that ignores the path and acts on the query). MERGE "
        "those into one finding with all the routes as affected locations; do NOT report the same "
        "`/app/index.php:53` injection five times because it is reachable via /?id, /verify.php, /eam/vib, ...\n"
        "  - Sharing a host, a database, or merely a vuln CLASS is NOT enough. Two different features that each "
        "query the same DB are TWO bugs; a redirect endpoint and a listing endpoint that both have SQLi are TWO "
        "bugs. If the evidence does not PROVE the same sink/code path, keep them SEPARATE.\n"
        "  - When in doubt, DO NOT merge. Over-merging hides a real bug and is worse than an extra row.\n"
        "A merged finding keeps the HIGHEST severity among its members and lists ALL affected URLs.\n"
        'Reply ONLY JSON: {"rationale":"<one line>","merges":[{"ids":["f1","f4"],"title":"<merged title>",'
        '"severity":"High","reason":"<the shared sink you PROVED, citing the evidence>"}]}. '
        "List a group ONLY to merge it (2+ ids that are provably identical); omit every finding that stays on "
        "its own. Return an empty merges list if nothing is provably one-and-the-same.")

    def _full_evidence(self, ctx, f) -> str:
        """The stored finding evidence is truncated to 120 chars for the digest; recover the fuller text from
        the executor RESULT record that produced it, so equivalence is judged on the real signal (the query
        shape / dumped columns / stack trace), not a clipped preview."""
        best = f.get("evidence", "")
        for r in ctx.trail:
            if r.kind != "result":
                continue
            for hf in (r.data.get("findings") or []):
                if not isinstance(hf, dict):
                    continue
                if (hf.get("title") or "").strip().lower() == f["title"].lower() and (hf.get("url") or "") == f["url"]:
                    ev = str(hf.get("evidence", ""))
                    if len(ev) > len(best):
                        best = ev
        return best[:500]

    def consolidate(self, ctx, provider) -> dict:
        fnds = ctx.landscape["findings"]
        by_cls = {}
        for f in fnds:
            by_cls.setdefault(f["cls"] or "?", []).append(f)
        groups = {c: fs for c, fs in by_cls.items() if len(fs) > 1}
        if not groups:
            return {"merges": [], "rationale": "no class has more than one finding - nothing to consolidate"}

        blocks = []
        for cls, fs in groups.items():
            lines = [f"CLASS `{cls}` ({len(fs)} findings):"]
            for f in fs:
                lines.append(f"  {f['id']} [{f['severity']}] {f['title']}\n"
                             f"      url: {f['url']}\n"
                             f"      evidence: {self._full_evidence(ctx, f)}")
            blocks.append("\n".join(lines))
        user = ("Consolidate the findings below. Only merge findings PROVEN to be the same sink/code path; keep "
                "everything else separate.\n\n" + "\n\n".join(blocks) + "\n\nJSON only.")
        try:
            raw = provider.chat(self.SYSTEM, user)
        except Exception as exc:  # noqa: BLE001 - on any error, change nothing (never over-merge on a failure)
            return {"merges": [], "rationale": f"consolidator error: {exc}"}
        obj = extract_json(raw)
        applied = self._apply(ctx, obj.get("merges") or [])
        return {"merges": applied, "rationale": obj.get("rationale", "")}

    def _apply(self, ctx, merges) -> list:
        """Collapse each PROVEN-equivalent group into its lowest-id member: keep the highest severity, gather
        every affected URL, union the causal refs, and drop the other members from the landscape. A finding id
        may be merged only once (first claim wins), so overlapping groups can't double-remove a record."""
        fnds = ctx.landscape["findings"]
        by_id = {f["id"]: f for f in fnds}
        removed, applied = set(), []
        for m in merges:
            if not isinstance(m, dict):
                continue
            ids = [i for i in (m.get("ids") or []) if i in by_id and i not in removed]
            if len(ids) < 2:
                continue
            members = sorted((by_id[i] for i in ids), key=lambda f: f["id"])
            primary = members[0]
            sev = m.get("severity") or max((mm["severity"] for mm in members),
                                           key=lambda s: self._SEV.get(str(s).lower(), 0))
            affected = []
            for mm in members:
                for u in [mm["url"], *mm.get("affected", [])]:
                    if u and u not in affected:
                        affected.append(u)
            refs = list(primary.get("from") or [])
            for mm in members[1:]:
                refs += [r for r in (mm.get("from") or []) if r not in refs]
                removed.add(mm["id"])
            primary["severity"] = str(sev).title()
            primary["title"] = m.get("title") or primary["title"]
            primary["url"] = affected[0] if affected else primary["url"]
            primary["affected"] = affected
            primary["merged_from"] = [mm["id"] for mm in members]
            primary["from"] = refs
            applied.append({"kept": primary["id"], "ids": [mm["id"] for mm in members],
                            "title": primary["title"], "affected": affected, "reason": str(m.get("reason", ""))[:200]})
        if removed:
            ctx.landscape["findings"] = [f for f in fnds if f["id"] not in removed]
        return applied


class Reporter:
    name = "reporter"
    role = "reporter"

    SYSTEM = (
        "You are the REPORTER of IRVIN. The hunt is over. Using ONLY the VERIFIED findings and the RUN FACTS "
        "given (use those numbers verbatim - never invent findings or counts), produce a GitHub-flavored "
        "MARKDOWN report with EXACTLY these sections, in this order. LEAD with a plain-language EXECUTIVE "
        "SUMMARY a non-technical CEO can act on (business risk, no payloads, no jargon), then the technical "
        "detail. One TABLE ROW per finding, evidence <=100 "
        "chars and redacted. A finding may already be CONSOLIDATED - reached through several locations that are "
        "the same underlying bug; when a finding lists multiple affected URLs, keep it as ONE row and put every "
        "URL in Location (comma-separated), never split it back into a row per URL. Findings are already "
        "verified; add [SUGGESTION] rows only for concrete leads the "
        "trail shows are worth a human's follow-up. Output the Markdown directly - no preamble, no code fences "
        "around the whole thing.\n\n"
        "TEMPLATE:\n"
        "# Security Assessment: <target>\n\n"
        "**Mode:** IRVIN conductor (travis -> bob -> caleb)  ·  **Date:** <date>  ·  **Hosts scanned:** <N>\n\n"
        "> ⚠️ Automated analysis - findings need human validation; not all are exploitable in context.\n\n"
        "## Executive summary\n\n"
        "_For leadership. Plain language, no payloads, no jargon._\n\n"
        "**Overall risk:** <Critical|High|Medium|Low> - <one sentence a CEO understands: what an attacker "
        "could reach and the business it touches (customer data, accounts, money, uptime)>.\n\n"
        "**By severity:** Critical <n> · High <n> · Medium <n> · Low <n>\n\n"
        "**What this means for the business:** <2-3 sentences tying the real findings to concrete business "
        "risk - data breach, account takeover, financial loss, downtime, compliance. If nothing serious was "
        "found, say that plainly.>\n\n"
        "**Do this first:** <the single highest-impact action, in business terms - not a payload>\n\n"
        "---\n\n"
        "## Technical findings\n\n"
        "**Tested:** endpoints <N> · params <N> · hosts <N> · verified findings <N>\n\n"
        "| Severity | Title | Location | What is exposed | Reproduce | Evidence |\n"
        "| --- | --- | --- | --- | --- | --- |\n"
        "| High | <title> | `<url>` | <what> | <exact request/step> | <<=100 chars> |\n"
        "| Medium | <...> | | | | |\n"
        "| _Suggestion_ | <title> | | <why worth a human's follow-up> | | |\n\n"
        "(if there are no verified findings, write `None verified.` instead of the table)\n\n"
        "## Not covered\n\n"
        "<one line: what this pass did not reach - flows or areas travis/bob/caleb did not test this run>\n\n"
        "## Summary\n\n"
        "**Vulns** <n> (Critical <n>, High <n>, Medium <n>, Low <n>)  ·  **Suggestions** <n>\n\n"
        "## Conclusion\n\n"
        "<1-2 sentences: posture, top risk, highest-impact fix>")

    def report(self, ctx, provider) -> str:
        fnds = ctx.landscape["findings"]
        findings = "\n".join(
            f"- [{f['severity']}|{f['status']}] {f['cls'] or '?'} :: {f['title']} @ {f['url']}"
            + (f"  (SAME BUG also affects: {', '.join(f['affected'][1:])})"
               if len(f.get("affected") or []) > 1 else "")
            + f"\n    evidence: {f['evidence']}  (by {f['by']})" for f in fnds) or "(no verified findings)"
        sev = {}
        for f in fnds:
            sev[f["severity"]] = sev.get(f["severity"], 0) + 1
        cov = {}
        for f in fnds:                                     # per-agent coverage from who filed each finding
            cov[f.get("by") or "?"] = cov.get(f.get("by") or "?", 0) + 1
        cov_lines = "\n".join(f"  {ag}: {n} finding(s)" for ag, n in sorted(cov.items())) or "  (no findings)"
        s = ctx.landscape["surface"]
        facts = (f"date={time.strftime('%Y-%m-%d')} hosts={len(s['hosts'])} endpoints={len(s['endpoints'])} "
                 f"params={len(s['params'])} verified={len(fnds)}\n"
                 f"severity counts: {sev or '{}'}\nper-agent coverage:\n{cov_lines}")
        user = (f"TARGET: {ctx.target}\n\nRUN FACTS (use these numbers verbatim):\n{facts}\n\n"
                f"VERIFIED FINDINGS:\n{findings}\n\nLANDSCAPE:\n{ctx.landscape_digest()}\n\n"
                f"DECISION TRAIL (tail):\n{ctx.recent_trail(30)}\n\nFill the template exactly.")
        try:
            return provider.chat(self.SYSTEM, user)
        except Exception as exc:  # noqa: BLE001
            return f"(reporter error: {exc})\n\nVerified findings:\n{findings}"
