"""Shared ZAP automation-framework helpers.

All four ZAP commands (crawl / scan-url / scan-full / scan-openapi) drive
``zap.sh -cmd -autorun <plan.yaml>`` against a throwaway home dir, then parse
the traditional-json report or the exported URL list. This module holds the
machinery they share: plan/home scaffolding, the JMEM-capped invocation, scope
regex/quoting helpers, and report parsing.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from urllib.parse import urlparse

from ..core import fsutil, process

ZAP_SH = "/usr/share/zaproxy/zap.sh"
# Cap ZAP's JVM heap so concurrent runs don't auto-size to ~25% of host RAM.
JMEM = "-Xmx1500m"


@dataclass
class ZapRun:
    work_dir: str
    zap_home: str
    plan_path: str
    report_path: str
    urls_path: str


def prepare_run() -> ZapRun:
    """Create an isolated work dir with a nested zap-home for one ZAP run."""
    work_dir = fsutil.temp_dir("zap-run_")
    zap_home = os.path.join(work_dir, "zap-home")
    os.makedirs(zap_home, exist_ok=True)
    return ZapRun(
        work_dir=work_dir,
        zap_home=zap_home,
        plan_path=os.path.join(work_dir, "zap.yaml"),
        report_path=os.path.join(work_dir, "zap-report.json"),
        urls_path=os.path.join(work_dir, "urls.txt"),
    )


def execute(run: ZapRun, plan_text: str, timeout: int, dbg, *,
            host: str | None = None, port: int | None = None) -> None:
    """Write the plan and run ZAP to completion (or until ``timeout``)."""
    with open(run.plan_path, "w", encoding="utf-8") as fh:
        fh.write(plan_text)

    dbg(f"Plan: {run.plan_path}")
    dbg("Plan content:\n" + plan_text)
    dbg(f"ZAP home dir: {run.zap_home}")

    cmd = [ZAP_SH, "-dir", run.zap_home]
    if host is not None and port is not None:
        cmd += ["-host", host, "-port", str(port)]
        dbg(f"ZAP proxy: {host}:{port}")
    cmd += ["-cmd", "-autorun", run.plan_path]
    dbg("JMEM=" + JMEM + " " + process.format_command(cmd))

    result = process.run(cmd, timeout=timeout, env={"JMEM": JMEM})
    if not result.successful():
        dbg("ZAP process did not exit cleanly. Will still try to parse artefacts.")


def cleanup(run: ZapRun) -> None:
    fsutil.remove_dir(run.work_dir)


# -- YAML / scope helpers ----------------------------------------------------

def yaml_quote(value: str) -> str:
    """Single-quote a scalar for the hand-built plan YAML (doubling quotes)."""
    return "'" + value.replace("'", "''") + "'"


def context_base_url(target_url: str, *, keep_path: bool = False) -> str:
    parts = urlparse(target_url)
    scheme = parts.scheme or "https"
    host = parts.hostname or ""
    port = f":{parts.port}" if parts.port else ""
    if keep_path:
        path = parts.path or "/"
        return f"{scheme}://{host}{port}{path}"
    return f"{scheme}://{host}{port}/"


def sibling_scope_regex(target_url: str) -> str | None:
    """Regex matching any host under the target's parent domain.

    ``app.foo.com`` -> ``^https?://([^/]+\\.)?foo\\.com(:\\d+)?(/.*)?``. Returns
    None for IPs, single-label hosts, or registrable-domain-only parents.
    """
    host = urlparse(target_url).hostname
    if not host:
        return None
    # Bare IP?
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host) or ":" in host:
        return None
    labels = host.split(".")
    if len(labels) < 3:
        return None
    parent = ".".join(labels[1:])
    return r"^https?://([^/]+\.)?" + re.escape(parent) + r"(:\d+)?(/.*)?"


def include_block(target_url: str) -> str:
    sibling = sibling_scope_regex(target_url)
    if sibling is None:
        return ""
    return "\n      includePaths:\n        - " + yaml_quote(sibling)


# -- Report parsing ----------------------------------------------------------

def read_alerts(report_path: str) -> list[dict]:
    """Flatten + dedupe alerts from a traditional-json ZAP report."""
    try:
        with open(report_path, "r", encoding="utf-8", errors="replace") as fh:
            doc = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(doc, dict):
        return []

    alerts: list[dict] = []
    for site in doc.get("site", []) or []:
        for alert in site.get("alerts", []) or []:
            instances = alert.get("instances") or []
            instance = instances[0] if instances else {}
            alerts.append(
                {
                    "risk": alert.get("riskdesc", alert.get("risk", "")),
                    "confidence": alert.get("confidence", ""),
                    "pluginid": str(alert.get("pluginid", "")),
                    "name": alert.get("name", alert.get("alert", "")),
                    "url": instance.get("uri", ""),
                    "param": instance.get("param", ""),
                    "evidence": instance.get("evidence", ""),
                    "otherinfo": instance.get("otherinfo", ""),
                    "desc": alert.get("desc", ""),
                }
            )

    seen: set[str] = set()
    out: list[dict] = []
    for alert in alerts:
        key = "|".join([alert["pluginid"], alert["url"], alert["param"], alert["name"]])
        if key in seen:
            continue
        seen.add(key)
        out.append(alert)
    return out


def alerts_to_findings(alerts: list[dict]) -> list[dict]:
    findings: list[dict] = []
    for alert in alerts:
        risk = alert["risk"]
        if risk.startswith("High"):
            severity = "high"
        elif risk.startswith("Medium"):
            severity = "medium"
        elif risk.startswith("Low"):
            severity = "low"
        else:
            severity = "info"
        findings.append(
            {
                "severity": severity,
                "title": alert["name"],
                "info": f"{alert['name']} via {alert['param']}\n{alert['desc']}",
                "url": alert["url"],
            }
        )
    return findings


def read_urls(urls_path: str) -> list[str]:
    raw = fsutil.read_text(urls_path)
    urls: list[str] = []
    for line in raw.splitlines():
        line = line.strip()
        if line and line not in urls:
            urls.append(line)
    return urls
