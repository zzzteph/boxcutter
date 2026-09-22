"""Direct 'operator run': run a boxcutter ai agent (joseph) locally in THIS container and stream its output.

Unlike a Scan - which fans jobs out across the runner fleet - an operator run executes the engine as a
subprocess right here on the server host: you pick an LLM profile, give a target + brief, and watch the
reasoning stream live, then read the report. It is meant for joseph (the human-operator agent), which inhabits
a live browser and produces a text writeup - the fleet's per-target job model does not fit a single long,
stateful session, so it runs here instead.

The engine's stdout is the machine JSON envelope; its stderr is the live narration. We tail stderr into an
in-memory buffer the UI polls, and pass ``--json <file>`` so the final result (findings + report + token spend)
lands in a file we read reliably when the process exits. The server is single-worker, so an in-memory registry
of live runs is enough; the DB row is the durable record (log persisted at finish).
"""
from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

from sqlmodel import Session

from .db import engine
from .models import OperatorRun

# The whole registry of currently-live runs (single-worker server -> a process-global dict is fine).
_RUNS: dict[int, "_Live"] = {}
_LOCK = threading.Lock()

# How many operator runs may execute at once on this host. joseph is heavy (a browser + ZAP + parallel analyst
# LLMs), so keep this small; override with BOXCUTTER_OPERATOR_MAX.
MAX_CONCURRENT = int(os.environ.get("BOXCUTTER_OPERATOR_MAX", "2") or "2")

# Hard ceiling on the live log we keep/store, so one very chatty run can't exhaust memory or the DB row. When
# hit we stop appending (a note is added) but keep draining the pipe so the child never blocks on a full stderr.
_LOG_CEIL = 1_500_000

# provider -> the env var its api key/token lands in (never on argv). claude-code needs no key: it rides the
# container's own Claude Code login (CLAUDE_CONFIG_DIR on the /data volume); this only matters if the profile
# stores an OAuth token as its secret.
_ENV_FOR = {"anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY", "litellm": "LITELLM_API_KEY",
            "claude-code": "CLAUDE_CODE_OAUTH_TOKEN"}

# Agents an operator run may drive. joseph is the operator; the others are single-shot reasoning agents that
# also take --context/--provider and emit a report. Kept to a known-safe allowlist so a caller can't run an
# arbitrary subcommand through this path.
ALLOWED_AGENTS = ("joseph",)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _engine_python() -> str:
    """A python that can run the LEAN engine (requests/pyyaml/websocket-client). NOT the server venv (which has
    the web deps but not the engine's), so we prefer the system python3 - which in the image carries the engine
    deps. Override with BOXCUTTER_ENGINE_PYTHON."""
    return (os.environ.get("BOXCUTTER_ENGINE_PYTHON")
            or shutil.which("python3") or shutil.which("python") or sys.executable)


def _engine_path() -> str:
    """boxcutter.py: the repo root in dev, /opt/boxcutter in the image (server/app -> up two)."""
    return os.environ.get("BOXCUTTER_ENGINE") or str(Path(__file__).resolve().parents[2] / "boxcutter.py")


def _data_dir() -> str:
    return os.environ.get("DATA_DIR") or str(Path(__file__).resolve().parents[1] / "data")


class _Live:
    """A running subprocess plus its growing stderr buffer. `since`-offsets into the buffer are monotonic (we
    truncate at the END when the ceiling is hit, never slide a window), so the UI can poll for new bytes."""

    def __init__(self, run_id: int, proc: subprocess.Popen):
        self.run_id = run_id
        self.proc = proc
        self._buf: list[str] = []
        self._len = 0
        self._truncated = False
        self._lock = threading.Lock()
        self.done = False

    def append(self, chunk: str) -> None:
        if not chunk:
            return
        with self._lock:
            if self._truncated:
                return
            if self._len + len(chunk) > _LOG_CEIL:
                keep = _LOG_CEIL - self._len
                if keep > 0:
                    self._buf.append(chunk[:keep])
                    self._len += keep
                self._buf.append("\n...[log truncated - open the full report below]\n")
                self._truncated = True
                return
            self._buf.append(chunk)
            self._len += len(chunk)

    def text(self) -> str:
        with self._lock:
            return "".join(self._buf)


def live_tail(run_id: int, since: int) -> tuple[str, int, bool] | None:
    """(new_text, new_offset, done) for a run still in memory, or None if it isn't (read the DB row instead)."""
    live = _RUNS.get(run_id)
    if live is None:
        return None
    full = live.text()
    since = max(0, min(int(since or 0), len(full)))
    return full[since:], len(full), live.done


def is_live(run_id: int) -> bool:
    return run_id in _RUNS


def running_count() -> int:
    with _LOCK:
        return sum(1 for lv in _RUNS.values() if not lv.done)


def build_argv(agent: str, target: str, opts: dict) -> list[str]:
    """The engine argv for an operator run (without the interpreter / engine path). `opts` carries the parsed,
    already-bounded run options. Secrets never go here - they ride the env (see start())."""
    argv = ["ai", agent]
    if target:
        argv.append(target)
    provider = opts.get("provider") or "anthropic"
    argv += ["--provider", provider]
    if opts.get("model"):
        argv += ["--model", str(opts["model"])]
    if opts.get("proxy_url"):
        argv += ["--llm-proxy-url", str(opts["proxy_url"])]
    if opts.get("context"):
        argv += ["--context", str(opts["context"])]
    if opts.get("creds"):
        argv += ["--creds", str(opts["creds"])]
    if opts.get("dry_run"):
        argv.append("--dry-run")
    argv += ["--analysts", str(int(opts.get("analysts", 0)))]
    argv += ["--max-steps", str(int(opts.get("max_steps", 40)))]
    argv += ["--reasoning", "1"]                          # stream the narration to stderr (our live log)
    argv += ["--out-dir", opts["workspace"], "--json", opts["result_file"]]
    return argv


def start(run_id: int, agent: str, target: str, opts: dict, secret_env: dict) -> None:
    """Spawn the engine for `run_id` and stream it. Non-blocking: reader threads own the process from here, and
    finalize() writes the result back to the DB row when it exits."""
    workspace = os.path.join(_data_dir(), "operator", str(run_id))
    os.makedirs(workspace, exist_ok=True)
    opts = {**opts, "workspace": workspace, "result_file": os.path.join(workspace, "result.json")}
    argv = [_engine_python(), _engine_path()] + build_argv(agent, target, opts)

    env = dict(os.environ)
    env["PYTHONUNBUFFERED"] = "1"
    env.update({k: v for k, v in secret_env.items() if v})

    # start_new_session so a Stop can kill the whole process tree (chromium/ZAP children), not just the parent.
    popen_kw: dict = {"cwd": workspace, "env": env, "text": True,
                      "stdout": subprocess.PIPE, "stderr": subprocess.PIPE, "bufsize": 1}
    if os.name == "posix":
        popen_kw["start_new_session"] = True
    try:
        proc = subprocess.Popen(argv, **popen_kw)
    except Exception as exc:  # noqa: BLE001
        _finalize(run_id, status="failed", exit_code=None, error=f"could not start engine: {exc}",
                  result_file=opts["result_file"], log="", workspace=workspace)
        return

    live = _Live(run_id, proc)
    with _LOCK:
        _RUNS[run_id] = live

    t = threading.Thread(target=_pump, name=f"operator-{run_id}",
                         args=(run_id, live, opts["result_file"], workspace), daemon=True)
    t.start()


def _pump(run_id: int, live: _Live, result_file: str, workspace: str) -> None:
    """Drain stderr (live narration) and stdout (final JSON), then finalize the DB row."""
    proc = live.proc
    stdout_box: dict = {"text": ""}

    def _read_stdout():
        try:
            stdout_box["text"] = proc.stdout.read() or ""      # one blob at the end (the JSON envelope)
        except Exception:  # noqa: BLE001
            pass

    ot = threading.Thread(target=_read_stdout, daemon=True)
    ot.start()
    try:
        for line in iter(proc.stderr.readline, ""):
            live.append(line)
    except Exception:  # noqa: BLE001
        pass
    ot.join(timeout=10)
    code = proc.wait()
    live.done = True

    status = "done" if code == 0 else "failed"
    # a Stop marks the row 'stopped' before killing; don't override that to 'failed'.
    with Session(engine) as s:
        row = s.get(OperatorRun, run_id)
        if row and row.status == "stopped":
            status = "stopped"
    _finalize(run_id, status=status, exit_code=code, error=None if code == 0 else _tail_error(live.text()),
              result_file=result_file, log=live.text(), stdout=stdout_box["text"], workspace=workspace)
    with _LOCK:
        _RUNS.pop(run_id, None)


def _tail_error(log: str) -> str | None:
    """A short error hint from the tail of the stderr log for a non-zero exit."""
    lines = [ln for ln in (log or "").splitlines() if ln.strip()]
    return "\n".join(lines[-6:]) if lines else None


def _finalize(run_id: int, *, status: str, exit_code, result_file: str, log: str,
              error: str | None = None, stdout: str = "", workspace: str = "") -> None:
    report, findings, meta = _parse_result(result_file, stdout)
    with Session(engine) as s:
        row = s.get(OperatorRun, run_id)
        if not row:
            return
        row.status = status
        row.exit_code = exit_code
        row.finished_at = _now()
        row.log = log[-_LOG_CEIL:] if log else row.log
        if report:
            row.report = report
        if findings is not None:
            row.findings_json = json.dumps(findings, ensure_ascii=False)
        if meta:
            row.meta_json = json.dumps({**meta, "workspace": workspace}, ensure_ascii=False, default=str)
        if error and not row.error:
            row.error = error[:4000]
        s.add(row)
        s.commit()


def _parse_result(result_file: str, stdout: str) -> tuple[str, list | None, dict]:
    """Pull (report, findings, meta) from the engine's --json file, falling back to parsing stdout. Best-effort:
    a run that crashed before writing the envelope just yields ('', None, {})."""
    env = None
    try:
        with open(result_file, encoding="utf-8") as fh:
            env = json.load(fh)
    except Exception:  # noqa: BLE001
        try:
            env = json.loads((stdout or "").strip().splitlines()[-1]) if stdout.strip() else None
        except Exception:  # noqa: BLE001
            env = None
    if not isinstance(env, dict):
        return "", None, {}
    findings = env.get("data") if isinstance(env.get("data"), list) else None
    report = str(env.get("report") or "")
    meta = {"tokens": env.get("tokens"), "cost_usd": env.get("cost_usd"), "steps": env.get("steps"),
            "mutations": env.get("mutations"), "scripts": env.get("scripts")}
    meta = {k: v for k, v in meta.items() if v is not None}
    return report, findings, meta


def stop(run_id: int) -> bool:
    """Kill a live run's process tree. Returns True if it was live and got signalled."""
    live = _RUNS.get(run_id)
    if live is None or live.done:
        return False
    proc = live.proc
    try:
        if os.name == "posix":
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        else:
            proc.terminate()
    except Exception:  # noqa: BLE001
        try:
            proc.terminate()
        except Exception:  # noqa: BLE001
            return False
    return True


def reap_orphans() -> None:
    """On server startup, mark any run left 'running' by a previous process as failed - its subprocess died with
    the old server and we no longer track it. Called once from the app lifespan."""
    from sqlmodel import select
    with Session(engine) as s:
        for row in s.exec(select(OperatorRun).where(OperatorRun.status == "running")).all():
            if row.id in _RUNS:
                continue
            row.status = "failed"
            row.finished_at = row.finished_at or _now()
            if not row.error:
                row.error = "interrupted (the server restarted while this run was in progress)"
            s.add(row)
        s.commit()
