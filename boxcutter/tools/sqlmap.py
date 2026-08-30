"""sqlmap - SQL injection scanner. Port of app:sqlmap.

Captures sqlmap's stdout, strips ANSI, and reconstructs structured findings
from the ``---`` injection blocks plus an enumeration-metadata summary (DBMS,
banner, databases, tables, dumped rows).
"""

from __future__ import annotations

import re

from ..core import fsutil, process
from ..core.args import add_common_args, add_header_arg, add_opt_args
from ..core.envelope import debug_logger, output_result
from ..core.validators import is_valid_url

NAME = "sqlmap"
KIND = "findings"
HELP = "Run sqlmap SQL injection scanner against a target URL."

SQLMAP = "/usr/share/sqlmap/sqlmap.py"
_ANSI = re.compile(r"\033\[[0-9;]*m")
_BLOCK = re.compile(r"^---$(.*?)^---$", re.M | re.S)


def add_arguments(parser) -> None:
    parser.add_argument("target", help="Target URL")
    parser.add_argument("--timeout", type=int, default=300, help="Process timeout in seconds")
    parser.add_argument("--method", default=None, help="HTTP method (e.g. POST/PUT) for a body request")
    parser.add_argument("--data", default=None, help="Request body to test (enables POST/PUT injection testing)")
    add_opt_args(parser)
    add_header_arg(parser)
    add_common_args(parser)


def run(args) -> int:
    target = args.target.strip()
    opt_args = args.opt_args.strip()
    dbg = debug_logger(args.debug)

    if not is_valid_url(target):
        output_result([], args.output, "Invalid URL.")
        return 1

    artifact_dir = fsutil.temp_dir("sqlmap_")

    cmd = [
        "python3", SQLMAP, "-u", target, "--batch", "--random-agent",
        "--level", "1", "--risk", "1", "--disable-coloring",
        "--banner",                       # VERIFY: read the DB version/banner through any injection found. A
                                          # real injection returns it; a coincidental boolean 'hit' cannot -
                                          # and sqlmap only extracts once it has actually confirmed an injection,
                                          # so this adds no cost on non-injectable targets.
        f"--output-dir={artifact_dir}",
    ]
    for header in args.header:
        cmd += ["-H", header]
    if getattr(args, "data", None):
        cmd += ["--data", args.data]
    if getattr(args, "method", None):
        cmd += ["--method", args.method]
    cmd += process.split_opt_args(opt_args)
    dbg(f"Command: {process.format_command(cmd)}")

    result = process.run(cmd, timeout=args.timeout)
    if not result.successful():
        dbg("sqlmap exited with a non-zero status.")

    output = _ANSI.sub("", result.stdout)
    fsutil.remove_dir(artifact_dir)

    findings = _parse_findings(output, target)
    raw_detections = len(_BLOCK.findall(output))
    if raw_detections and not findings:
        dbg(f"Discarded {raw_detections} unverified detection(s): sqlmap could not read the DB version/banner "
            f"back through them, so they are treated as false positives and not reported.")
    dbg(f"Found {len(findings)} confirmed injection(s).")

    # When extra args were passed (enumeration run), attach the tail after the
    # last --- block so the full enumeration output is visible.
    if opt_args != "" and findings:
        after = re.split(r"^---$", output, flags=re.M)
        tail_text = after[-1].strip() if after else ""
        if tail_text:
            findings[0]["raw_output"] = tail_text

    output_result(findings, args.output)
    return 0


def _parse_findings(output: str, target_url: str) -> list[dict]:
    findings: list[dict] = []

    for block in _BLOCK.findall(output):
        param_match = re.search(r"^Parameter:\s+(.+)$", block, re.M)
        parameter = param_match.group(1).strip() if param_match else "unknown"

        types = [m.strip() for m in re.findall(r"^\s+Type:\s+(.+)$", block, re.M)]
        titles = [m.strip() for m in re.findall(r"^\s+Title:\s+(.+)$", block, re.M)]
        payloads = [m.strip() for m in re.findall(r"^\s+Payload:\s+(.+)$", block, re.M)]

        details: list[str] = []
        for i, type_ in enumerate(types):
            entry = f"Type: {type_}"
            if i < len(titles):
                entry += f"\n  Title:   {titles[i]}"
            if i < len(payloads):
                entry += f"\n  Payload: {payloads[i]}"
            details.append(entry)

        findings.append(
            {
                "title": f"SQL Injection in parameter '{parameter}'",
                "url": target_url,
                "severity": "high",
                "info": f"Parameter: {parameter}\n\n" + "\n\n".join(details),
            }
        )

    meta = _parse_meta(output)
    proof = _read_proof(output)

    # POLICY: an injection counts ONLY if sqlmap could READ data back through it - the DB version/banner, the
    # current user/database, a listed database, or a dumped row. If nothing was read, sqlmap merely detected /
    # fingerprinted, and a boolean-based blind "detection" can trip on a coincidental page difference - so it is
    # a FALSE POSITIVE and is not reported at all.
    if not proof:
        return []

    if findings:
        if meta:
            findings[0]["info"] += "\n\n" + meta
        for f in findings:
            f["info"] += f"\n\nVerified: sqlmap read {proof} through the injection - confirmed exploitable."
    elif meta:
        findings.append(
            {
                "title": "SQL Injection - Enumeration Result",
                "url": target_url,
                "severity": "high",
                "info": meta,
            }
        )

    return findings


def _parse_meta(output: str) -> str:
    lines: list[str] = []

    if m := re.search(r"back-end DBMS:\s*(.+)", output, re.I):
        lines.append("DBMS: " + m.group(1).strip())
    if m := re.search(r"banner:\s*'(.+?)'", output, re.I):
        lines.append("Banner: " + m.group(1).strip())
    if m := re.search(r"web application technology:\s*(.+)", output, re.I):
        lines.append("Technology: " + m.group(1).strip())
    if m := re.search(r"current user:\s*'(.+?)'", output, re.I):
        lines.append("Current user: " + m.group(1).strip())
    if m := re.search(r"current database:\s*'(.+?)'", output, re.I):
        lines.append("Current database: " + m.group(1).strip())

    databases = _parse_databases(output)
    if databases:
        lines.append("Databases: " + ", ".join(databases))

    tables = _parse_table_names(output)
    if tables:
        lines.append("Tables: " + ", ".join(tables))

    warns = re.findall(r"\[WARNING\]\s*(on .+? it is not possible to .+)", output, re.I)
    for warn in dict.fromkeys(warns):  # unique, order-preserving
        lines.append("Note: " + warn.strip())

    lines.extend(_parse_dumped_tables(output))

    return "\n".join(lines)


def _read_proof(output: str) -> str:
    """The data sqlmap actually READ from the DB through the injection - the proof it is real and exploitable,
    not a coincidental boolean/page difference. The DBMS *fingerprint* alone is NOT proof (it can come from an
    error message or timing); a banner/version, current user/db, a listed database or a dumped row are. Returns
    a short label of the strongest read, or '' if sqlmap only detected/fingerprinted without reading anything."""
    for rx, label in (
        (r"banner:\s*'(.+?)'", "the DB banner/version"),
        (r"current user:\s*'(.+?)'", "the current DB user"),
        (r"current database:\s*'(.+?)'", "the current database"),
    ):
        if m := re.search(rx, output, re.I):
            return f"{label} ({m.group(1).strip()})"
    if re.search(r"available databases \[\d+\]:", output, re.I):
        return "the list of databases"
    if re.search(r"Database:\s*\S+\s*\nTable:\s*\S+\s*\n\[\d+ entr", output, re.I):
        return "dumped table rows"
    return ""


def _parse_databases(output: str) -> list[str]:
    section = re.search(r"available databases \[\d+\]:(.*?)(?=\n\[|\Z)", output, re.S)
    if not section:
        return []
    return [m.strip() for m in re.findall(r"^\[\*\]\s+(.+)$", section.group(1), re.M)]


def _parse_table_names(output: str) -> list[str]:
    m = re.search(r"\[\d+ tables?\].*?\n((?:[+|][^\n]*\n)+)", output, re.S)
    if not m:
        return []
    return [t.strip() for t in re.findall(r"\|\s+([^\s|]+)\s+\|", m.group(1))]


def _parse_dumped_tables(output: str) -> list[str]:
    results: list[str] = []
    pattern = re.compile(
        r"Database:\s*(\S+)\s*\nTable:\s*(\S+)\s*\n\[\d+ entr(?:y|ies)\]\n((?:[+|][^\n]*\n)+)",
        re.S,
    )
    for db, table, body in pattern.findall(output):
        rows = [ln for ln in body.strip().split("\n") if ln.strip().startswith("|")]
        parsed: list[str] = []
        for row in rows:
            cells = [c.strip() for c in row.strip("|").split("|")]
            parsed.append(" | ".join(c for c in cells if c != ""))
        if parsed:
            results.append(f"Dumped {db}.{table}:\n  " + "\n  ".join(parsed))
    return results
