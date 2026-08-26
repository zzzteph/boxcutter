#!/usr/bin/env python3
"""boxcutter-ui runner supervisor.

Runs inside the stock boxcutter image (`ghcr.io/zzzteph/boxcutter`). Standard library only, so it works when
fetched and exec'd by the self-bootstrap one-liner. It:

  - enrolls with a core server (server URL + enroll token, or username/password),
  - runs up to N concurrent job slots ("number of boxcutters"); each claims a job, runs `boxcutter <argv>`,
    streams the engine's stderr back as live events, and posts the findings envelope,
  - heartbeats status/slots/busy to the server,
  - serves a tiny local control UI on 127.0.0.1:RUNNER_UI_PORT to set the server, enroll, and set N live.

Config precedence: local file (.runner-config.json, written by the UI) over environment.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from boxcutter import __version__ as _ENGINE_VERSION

# Where the agent persists its config. NEVER inside the package dir - a config written there gets baked into
# the image (which shipped a stale ui_port/server once). Prefer $RUNNER_CONFIG, else the working directory.
CONFIG_PATH = os.environ.get("RUNNER_CONFIG") or os.path.join(os.getcwd(), ".runner-config.json")
MAX_SLOTS = 32
# Local control-UI bind port. Comes from env / --ui-port only, defaulting to 7070 - deliberately NOT read from
# the persisted config, so a stale/baked config can never move it (it used to hijack this to 17070).
UI_PORT = int(os.environ.get("RUNNER_UI_PORT", "7070") or 7070)
# The agent re-invokes THIS boxcutter to run each job (same image, same version), so there is no separate
# "engine" to probe and no version skew: the engine version an agent reports is simply boxcutter's own
# __version__. Override BOXCUTTER_CMD only if the engine binary lives elsewhere.
_SELF = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "boxcutter.py")
BOXCUTTER_CMD = (os.environ["BOXCUTTER_CMD"].split() if os.environ.get("BOXCUTTER_CMD")
                 else [sys.executable, _SELF])
VERSION = _ENGINE_VERSION              # the agent ships inside boxcutter, so its version IS the engine version
ENGINE_VERSION = _ENGINE_VERSION
# MOCK_RUNNER=1 runs the whole pipe without the engine: emit a couple of live lines and a canned findings
# envelope. Lets `docker compose up` / a local supervisor demonstrate claim->event->result->diff offline
# (and never scans a real target). See BUILD.md testing notes.
MOCK = os.environ.get("MOCK_RUNNER", "").strip().lower() not in ("", "0", "false", "no")
# A boxcutter scan runs for as long as it needs to. There is NO idle timeout: a deep scan (AI agent, full
# workflow, sqlmap/ZAP/nuclei) is SILENT for long stretches — --steps only prints at step boundaries — so a
# silence clock kills real work. The ONLY bound is a 6h absolute backstop; it exists so a wedged engine can't
# hold a worker slot forever. Raise JOB_MAX_RUNTIME if you run scans that legitimately go longer. Normally a
# job ends when the engine exits, when the server cancels it (scan stopped/deleted), or when the operator stops
# it. While the engine is quiet we emit a periodic "still running" keepalive so a live job never looks dead,
# and whatever it printed is captured/returned even if it is killed.
JOB_IDLE_TIMEOUT = int(os.environ.get("JOB_IDLE_TIMEOUT", "0") or 0)         # kill if silent N seconds (0 = off)
JOB_MAX_RUNTIME = int(os.environ.get("JOB_MAX_RUNTIME", "21600") or 0)       # absolute cap: 6h (0 = unlimited)
JOB_TIMEOUT = int(os.environ.get("JOB_TIMEOUT", "0") or 0)                   # legacy hard cap; 0 = use the above
# Flood guard: stop STREAMING live-log lines for a job past this many (a --debug tool can spew thousands) so we
# don't hammer the server or balloon its log table. The raw report (Raw output) still keeps everything, and the
# server also ring-buffers per job (log_max_events_per_job). 0 = no agent-side cap.
LOG_MAX_LIVE_LINES = int(os.environ.get("LOG_MAX_LIVE_LINES", "3000") or 0)
_POSIX = os.name == "posix"

def _local_ip() -> str:
    """Best-effort primary IP of this host (the outbound-interface address)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:  # noqa: BLE001
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:  # noqa: BLE001
            return ""


_IP = _local_ip()
STATE = {"connected": False, "runner_id": None, "server": "", "concurrency": 1, "ip": _IP,
         "version": VERSION, "engine_version": ENGINE_VERSION,
         "slots": {}, "recent": [], "metrics": {}, "error": ""}   # slots: {idx:{job,target}}; recent: last jobs
_LOCK = threading.Lock()
_ENROLL_LOCK = threading.Lock()             # serialize enroll so startup + heartbeat don't double-register
CANCEL: set = set()                         # job ids the server told us to STOP (scan deleted/stopped/reassigned)
JOB_TOKENS: dict = {}                       # job_id -> run token, echoed on every event/result so a stale post
#                                             can't land on a reused integer id now owned by a different scan


# ---- config -------------------------------------------------------------------------------------------------
def load_config() -> dict:
    cfg = {"server_url": os.environ.get("SERVER_URL", "http://localhost:8000"),
           "enroll_token": os.environ.get("ENROLL_TOKEN", ""),
           "api_key": os.environ.get("API_KEY", ""),          # optional: a system-user key can enroll too
           "username": os.environ.get("RUNNER_USER", ""),
           "password": os.environ.get("RUNNER_PASSWORD", ""),
           "concurrency": int(os.environ.get("CONCURRENCY", "2") or 2),
           "name": os.environ.get("RUNNER_NAME", os.uname().nodename if hasattr(os, "uname") else "runner"),
           "internal": os.environ.get("RUNNER_INTERNAL", "").strip().lower() not in ("", "0", "false", "no"),
           "token": ""}
    if os.path.exists(CONFIG_PATH):
        try:
            cfg.update(json.load(open(CONFIG_PATH, encoding="utf-8")))
        except Exception:  # noqa: BLE001
            pass
    return cfg


def save_config(cfg: dict) -> None:
    try:
        json.dump(cfg, open(CONFIG_PATH, "w", encoding="utf-8"))
    except Exception:  # noqa: BLE001
        pass


CFG = load_config()


# ---- local models (this agent's OWN Ollama) -----------------------------------------------------------------
# Each agent runs models on its own hardware: it pulls to its LOCAL Ollama and reports which it has installed,
# so the server never hands it a job whose model it can't run. Point elsewhere with AGENT_OLLAMA_URL.
OLLAMA_URL = os.environ.get("AGENT_OLLAMA_URL", "http://localhost:11434").rstrip("/")
MODEL_CATALOG = [
    {"name": "qwen2.5:3b",       "size_gb": 2.0, "note": "fast, low-RAM"},
    {"name": "llama3.2:3b",      "size_gb": 2.0, "note": "low-RAM alt"},
    {"name": "phi3.5",           "size_gb": 2.2, "note": "3.8B"},
    {"name": "mistral:7b",       "size_gb": 4.4, "note": "all-round"},
    {"name": "qwen2.5:7b",       "size_gb": 4.7, "note": "recommended"},
    {"name": "qwen2.5-coder:7b", "size_gb": 4.7, "note": "tool-use"},
    {"name": "llama3.1:8b",      "size_gb": 4.9, "note": "strong"},
]
_CATALOG_NAMES = {m["name"] for m in MODEL_CATALOG}
_MODEL_PULLS: dict = {}
_MODEL_LOCK = threading.Lock()
_INSTALLED = {"models": [], "at": 0.0}       # ~10s cache so the claim loop doesn't hammer Ollama


def _ollama_installed(force: bool = False) -> list:
    now = time.monotonic()
    if not force and _INSTALLED["models"] and now - _INSTALLED["at"] < 10:
        return _INSTALLED["models"]
    out: list = []
    try:
        with urllib.request.urlopen(OLLAMA_URL + "/api/tags", timeout=3) as r:
            data = json.loads(r.read().decode() or "{}")
        out = sorted({(m.get("name") or "").split("@")[0] for m in (data.get("models") or []) if m.get("name")})
    except Exception:  # noqa: BLE001
        out = []
    _INSTALLED.update(models=out, at=now)
    return out


def _ollama_reachable() -> bool:
    try:
        urllib.request.urlopen(OLLAMA_URL + "/api/tags", timeout=2).read()
        return True
    except Exception:  # noqa: BLE001
        return False


def _ollama_friendly(exc) -> str:
    s = str(exc)
    low = s.lower()
    if "refused" in low or "111" in s or "10061" in s or "urlopen" in low or "timed out" in low:
        return f"Ollama not reachable at {OLLAMA_URL} - is it running on this agent host?"
    return s[:200]


def _ollama_pull(name: str) -> None:
    if name not in _CATALOG_NAMES:
        raise ValueError("model not in catalog")
    if not _ollama_reachable():
        raise RuntimeError(f"Ollama not reachable at {OLLAMA_URL} - is it running on this agent host? "
                           "(install/start Ollama, or set AGENT_OLLAMA_URL)")
    with _MODEL_LOCK:
        if _MODEL_PULLS.get(name, {}).get("status") == "pulling":
            return
        _MODEL_PULLS[name] = {"status": "pulling", "detail": "starting"}
    _spawn(_do_model_pull, (name,))


def _do_model_pull(name: str) -> None:
    try:
        body = json.dumps({"name": name, "stream": True}).encode()
        req = urllib.request.Request(OLLAMA_URL + "/api/pull", data=body,
                                     headers={"Content-Type": "application/json"}, method="POST")
        detail = "starting"
        with urllib.request.urlopen(req, timeout=3600) as r:
            for raw in r:
                try:
                    j = json.loads(raw.decode())
                except ValueError:
                    continue
                if j.get("error"):
                    raise RuntimeError(j["error"])
                st = j.get("status", "")
                if j.get("total"):
                    st = f"{st} {int(100 * (j.get('completed') or 0) / j['total'])}%"
                detail = st or detail
                with _MODEL_LOCK:
                    _MODEL_PULLS[name] = {"status": "pulling", "detail": detail}
        with _MODEL_LOCK:
            _MODEL_PULLS[name] = {"status": "done", "detail": "installed"}
        _ollama_installed(force=True)
    except Exception as exc:  # noqa: BLE001
        with _MODEL_LOCK:
            _MODEL_PULLS[name] = {"status": "error", "detail": _ollama_friendly(exc)}


def _model_status() -> dict:
    with _MODEL_LOCK:
        return {k: dict(v) for k, v in _MODEL_PULLS.items()}


# ---- http helpers (stdlib) ----------------------------------------------------------------------------------
def _req(method: str, path: str, body: dict | None = None, token: str | None = None, timeout: int = 60):
    url = CFG["server_url"].rstrip("/") + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read().decode()
        return json.loads(raw) if raw else {}


def enroll() -> bool:
    with _ENROLL_LOCK:
        if STATE.get("connected") and CFG.get("token"):
            return True          # already registered by the other startup path; don't create a second runner
        return _enroll_locked()


def _enroll_locked() -> bool:
    body = {"name": CFG.get("name", "runner"), "version": VERSION, "engine_version": engine_version(),
            "slots": CFG.get("concurrency", 1),
            "host": CFG.get("name", ""), "ip": _IP, "internal": bool(CFG.get("internal"))}
    if CFG.get("enroll_token"):
        body["token"] = CFG["enroll_token"]
    elif CFG.get("api_key"):
        body["api_key"] = CFG["api_key"]
    else:
        body["username"] = CFG.get("username")
        body["password"] = CFG.get("password")
    try:
        res = _req("POST", "/runner/enroll", body)
        CFG["token"] = res["runner_token"]
        save_config(CFG)
        with _LOCK:
            STATE.update(connected=True, runner_id=res["runner_id"], server=CFG["server_url"], error="")
        return True
    except Exception as exc:  # noqa: BLE001
        with _LOCK:
            STATE.update(connected=False, error=f"enroll failed: {exc}")
        return False


# ---- job execution ------------------------------------------------------------------------------------------
def _scrub(text: str, secret_vals: list) -> str:
    """Redact any secret value (LLM api key, etc.) from engine output before it leaves the runner."""
    for v in secret_vals:
        if v:
            text = text.replace(v, "***")
    return text


def _emit(job_id: int, line: str, agent: str = "", phase: str = "", reasoning: str | None = None) -> None:
    try:
        _req("POST", f"/runner/jobs/{job_id}/event",
             {"line": line[:2000], "agent": agent, "phase": phase, "reasoning": reasoning,
              "token": JOB_TOKENS.get(job_id, "")},
             CFG["token"], timeout=15)
    except Exception:  # noqa: BLE001 - a dropped log line must not kill the job
        pass


def _mock_run(job: dict) -> dict:
    """Offline stand-in for the engine: stream a few live lines (incl. a reasoning line), return a canned
    findings envelope."""
    argv = [str(a) for a in job.get("argv", [])]
    name = argv[0] if argv else "boxcutter"
    target = job.get("target", "")
    _emit(job["id"], f"starting {name} against {target}", agent=name, phase="mock")
    time.sleep(0.05)
    _emit(job["id"], "probing endpoints ...", agent=name, phase="mock",
          reasoning=f"choosing checks for {target} based on the template")
    time.sleep(0.05)
    _emit(job["id"], f"{name} complete", agent=name, phase="mock")
    url = target if target.startswith("http") else f"http://{target}"
    # a realistic demo finding (not a "reachable" recon line, which the server filters out as non-issue)
    envelope = {"success": True, "data": [
        {"severity": "low", "cls": "headers", "title": "Missing security headers", "url": url,
         "evidence": "Response is missing Content-Security-Policy and X-Frame-Options.",
         "reproduce": f"curl -sI {url}"},
        {"severity": "info", "cls": "recon", "title": f"{target} reachable", "url": url,
         "evidence": "host responded", "reproduce": f"{name} {target}"}]}
    report = (f"$ boxcutter {name} {target}\n"
              f"[i] starting {name} against {target}\n"
              f"[i] probing endpoints ...\n"
              f"[+] {target} reachable\n"
              f"[!] Missing security headers (Content-Security-Policy, X-Frame-Options)\n"
              f"[i] {name} complete — 1 issue\n")
    return {"envelope": envelope, "report": report, "error": None}


def _kill_tree(proc) -> None:
    """Terminate a job subprocess AND its children (boxcutter may spawn tools), escalating to SIGKILL."""
    if proc is None:
        return
    try:
        if _POSIX:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        else:
            proc.terminate()
    except Exception:  # noqa: BLE001
        pass
    try:
        proc.wait(timeout=5)
    except Exception:  # noqa: BLE001
        try:
            if _POSIX:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            else:
                proc.kill()
        except Exception:  # noqa: BLE001
            pass


# ---- engine version -----------------------------------------------------------------------------------------
def engine_version() -> str:
    """The engine version this agent reports to the server. The agent ships inside boxcutter and runs THIS
    engine, so it is simply our own __version__ - no probe, and no way for an agent to disagree with the engine
    it actually runs (the version-skew this used to guard against cannot happen in a single image)."""
    return _ENGINE_VERSION


def run_job(job: dict, secrets: dict) -> dict:
    """Run `boxcutter <argv>`, streaming stderr as live steps and capturing stdout as the findings envelope /
    raw report. No idle timeout — a deep scan is legitimately silent for long stretches — and the only bound is
    the 6h JOB_MAX_RUNTIME backstop, so a wedged engine can't hold a slot forever. Whatever the job printed is
    ALWAYS captured
    and returned — even when killed — so you can always see its output; and the whole process tree is reaped so
    it can't wedge a slot."""
    if MOCK:
        return _mock_run(job)
    env = dict(os.environ)
    env.update({k: str(v) for k, v in (secrets or {}).items()})
    # values to redact from any streamed line or captured output (never leak the LLM key back to the server)
    secret_vals = [str(v) for v in (secrets or {}).values() if v and len(str(v)) >= 6]
    cmd = BOXCUTTER_CMD + [str(a) for a in job["argv"]]
    # a visible first step — tools emit their JSON to stdout at the end and are silent on stderr, so without
    # this the live-steps view would stay empty until (and unless) something prints to stderr.
    _emit(job["id"], _scrub("$ boxcutter " + " ".join(str(a) for a in job["argv"]), secret_vals), phase="run")
    hard_cap = JOB_TIMEOUT if JOB_TIMEOUT > 0 else JOB_MAX_RUNTIME   # legacy JOB_TIMEOUT still honored if set
    out_buf: list = []
    last_active = [time.monotonic()]           # bumped by EITHER stream; drives the idle timeout
    killed = None
    cancelled = False
    proc = None
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
                                text=True, bufsize=1,
                                start_new_session=_POSIX)   # own process group -> we can kill the whole tree

        live_lines = [0]                          # streamed live-log lines for this job (flood guard)

        def _emit_line(line, **kw):
            n = live_lines[0]                     # racy across the two pump threads, but only a soft bound
            if LOG_MAX_LIVE_LINES and n >= LOG_MAX_LIVE_LINES:
                if n == LOG_MAX_LIVE_LINES:
                    _emit(job["id"], f"… live log capped at {LOG_MAX_LIVE_LINES} lines — full output under Raw "
                          "output", phase="run")
                    live_lines[0] += 1
                return
            _emit(job["id"], line, **kw)
            live_lines[0] += 1

        def _pump(stream, is_stderr):
            try:
                for line in iter(stream.readline, ""):
                    last_active[0] = time.monotonic()     # any output = the job is alive, reset the idle clock
                    s = line.rstrip("\n")
                    if is_stderr:
                        if s:
                            _emit_line(_scrub(s, secret_vals))
                    else:
                        out_buf.append(line)              # the report keeps EVERYTHING (never capped)
                        # surface human-readable stdout progress live too — but not the final JSON envelope
                        # blob (that's shown under Raw output and parsed into findings), so the feed stays clean
                        if s and not (s.lstrip()[:1] == "{" and ('"data"' in s or '"success"' in s)):
                            _emit_line(_scrub(s, secret_vals), phase="out")
            except Exception:  # noqa: BLE001 - a broken pipe must not crash the job
                pass

        te = threading.Thread(target=_pump, args=(proc.stderr, True), daemon=True)
        to = threading.Thread(target=_pump, args=(proc.stdout, False), daemon=True)
        te.start()
        to.start()
        started = time.monotonic()
        last_beat = started
        while True:
            try:
                proc.wait(timeout=2)
                break                                    # engine exited on its own
            except subprocess.TimeoutExpired:
                now = time.monotonic()
                # keepalive: when the engine goes quiet, periodically show the job is still alive so a long
                # silent step never looks dead. This does NOT touch last_active (the idle clock tracks ENGINE
                # output only), so it can't mask a real hang.
                if now - last_active[0] >= 45 and now - last_beat >= 60:
                    _emit(job["id"], f"still running — {int(now - started)}s elapsed, "
                          f"{int(now - last_active[0])}s since last engine output", phase="run")
                    last_beat = now
                with _LOCK:
                    stop_now = job["id"] in CANCEL     # server asked us to stop (scan deleted/stopped)
                if stop_now:
                    killed, cancelled = "cancelled by server", True
                elif JOB_IDLE_TIMEOUT and (now - last_active[0]) >= JOB_IDLE_TIMEOUT:
                    killed = f"no output for {int(now - last_active[0])}s — idle timeout ({JOB_IDLE_TIMEOUT}s)"
                elif hard_cap and (now - started) >= hard_cap:
                    killed = f"exceeded max runtime ({hard_cap}s)"
                if killed:
                    _emit(job["id"], killed, phase="run")
                    _kill_tree(proc)
                    break
        te.join(timeout=3)
        to.join(timeout=3)
    except FileNotFoundError:
        _emit(job["id"], f"engine not found: {cmd[0]}", phase="run")
        return {"envelope": {}, "report": None, "error": f"engine not found: {cmd[0]} (set BOXCUTTER_CMD)"}
    except Exception as e:  # noqa: BLE001 - any launch/IO failure -> reported as a failed job, slot survives
        _emit(job["id"], f"agent error: {e}", phase="run")
        return {"envelope": {}, "report": None, "error": f"agent error: {e}"}
    finally:
        if proc is not None and proc.poll() is None:
            _kill_tree(proc)

    envelope, error = {}, None
    text = "".join(out_buf).strip()
    report = text or None                 # ALWAYS keep the raw engine stdout for the debug/raw view — even a
    try:                                   # killed job returns whatever it printed so far ("we need to see it")
        parsed = json.loads(text)
        if isinstance(parsed, dict) and ("data" in parsed or "success" in parsed):
            envelope = parsed             # structured findings for the diff; `report` keeps the raw JSON too
    except Exception:  # noqa: BLE001 - non-JSON / partial stdout (e.g. irvin prints a markdown report)
        pass
    if killed:
        error = killed                    # a killed job is failed, but its partial output above is preserved
    elif proc.returncode not in (0, None):
        error = f"exit {proc.returncode}"
    if report:
        report = _scrub(report, secret_vals)
    if not cancelled:                     # a cancelled job already emitted "cancelled by server" above
        n = len(envelope.get("data") or []) if isinstance(envelope, dict) else 0
        _emit(job["id"], f"failed — {error}" if error else f"finished — {n} result item(s)", phase="run")
    return {"envelope": envelope, "report": report, "error": error, "cancelled": cancelled}


def worker(idx: int) -> None:
    while True:
        try:
            if idx >= CFG.get("concurrency", 1) or not STATE.get("connected"):
                time.sleep(1.0)
                continue
            try:
                # report the local models we have, so the server never hands us a job we can't run
                res = _req("POST", "/runner/claim", {"models": _ollama_installed()}, CFG["token"], timeout=65)
            except Exception:  # noqa: BLE001
                time.sleep(2.0)
                continue
            job = res.get("job")
            if not job:
                time.sleep(1.5)
                continue
            started = time.time()
            tok = job.get("token", "")
            with _LOCK:
                JOB_TOKENS[job["id"]] = tok      # register before running so streamed events carry the token
                CANCEL.discard(job["id"])        # a freshly claimed id starts clean — ignore any stale cancel
                STATE["slots"][idx] = {"job": job["id"], "target": job.get("target", ""), "started": started}
            try:
                out = run_job(job, res.get("secrets") or {})
            except Exception as e:  # noqa: BLE001 - a crashed job must never kill the slot
                out = {"envelope": {}, "report": None, "error": f"agent error: {e}"}
            with _LOCK:
                was_cancelled = bool(out.get("cancelled")) or job["id"] in CANCEL
            if not was_cancelled:                 # a cancelled job posts NOTHING — its integer id may already be
                try:                               # reused by a newer scan, and the server has dropped it anyway
                    _req("POST", f"/runner/jobs/{job['id']}/result", {**out, "token": tok},
                         CFG["token"], timeout=30)
                except Exception:  # noqa: BLE001
                    pass
            with _LOCK:
                JOB_TOKENS.pop(job["id"], None)
                CANCEL.discard(job["id"])
                STATE["recent"].insert(0, {"job": job["id"], "target": job.get("target", ""),
                                           "status": "cancelled" if was_cancelled else
                                           ("failed" if out.get("error") else "done"),
                                           "duration": round(time.time() - started, 1)})
                STATE["recent"] = STATE["recent"][:12]
                STATE["slots"][idx] = {"job": None, "target": ""}
        except Exception:  # noqa: BLE001 - the slot must survive absolutely anything and keep claiming
            try:
                with _LOCK:
                    STATE["slots"][idx] = {"job": None, "target": ""}
            except Exception:  # noqa: BLE001
                pass
            time.sleep(2.0)


def _disc(msg: str) -> None:
    with _LOCK:
        STATE["connected"] = False
        STATE["error"] = msg


# ---- host metrics (stdlib only, best-effort; CPU% needs two samples so it appears from the 2nd heartbeat) ---
_PREV_CPU: dict = {}


def _metrics() -> dict:
    try:
        if sys.platform.startswith("linux"):
            return _metrics_linux()
        if sys.platform.startswith("win"):
            return _metrics_windows()
    except Exception:  # noqa: BLE001 - metrics are best-effort
        pass
    return {}


def _metrics_linux() -> dict:
    m = {}
    with open("/proc/stat", encoding="utf-8") as f:
        vals = [int(x) for x in f.readline().split()[1:]]
    idle = vals[3] + (vals[4] if len(vals) > 4 else 0)
    total = sum(vals)
    prev = _PREV_CPU.get("linux")
    _PREV_CPU["linux"] = (idle, total)
    if prev and total - prev[1] > 0:
        m["cpu"] = round(100 * (1 - (idle - prev[0]) / (total - prev[1])), 1)
    info = {}
    with open("/proc/meminfo", encoding="utf-8") as f:
        for line in f:
            k, _, v = line.partition(":")
            info[k.strip()] = int(v.split()[0])
    tot, avail = info.get("MemTotal", 0), info.get("MemAvailable", info.get("MemFree", 0))
    if tot:
        m["mem"] = round(100 * (1 - avail / tot), 1)
    return m


def _metrics_windows() -> dict:
    import ctypes
    m = {}
    idle, kern, usr = ctypes.c_ulonglong(), ctypes.c_ulonglong(), ctypes.c_ulonglong()
    if ctypes.windll.kernel32.GetSystemTimes(ctypes.byref(idle), ctypes.byref(kern), ctypes.byref(usr)):
        i, k, u = idle.value, kern.value, usr.value
        prev = _PREV_CPU.get("win")
        _PREV_CPU["win"] = (i, k, u)
        if prev:
            di, dtot = i - prev[0], (k - prev[1]) + (u - prev[2])   # kernel time already includes idle
            if dtot > 0:
                m["cpu"] = round(max(0.0, 100 * (dtot - di) / dtot), 1)

    class _MS(ctypes.Structure):
        _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                    ("a", ctypes.c_ulonglong), ("b", ctypes.c_ulonglong), ("c", ctypes.c_ulonglong),
                    ("d", ctypes.c_ulonglong), ("e", ctypes.c_ulonglong), ("f", ctypes.c_ulonglong),
                    ("g", ctypes.c_ulonglong)]
    st = _MS()
    st.dwLength = ctypes.sizeof(_MS)
    if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(st)):
        m["mem"] = float(st.dwMemoryLoad)
    return m


def _heartbeat_once() -> None:
    m = _metrics()
    with _LOCK:
        STATE["metrics"] = m
    if CFG.get("token"):
        with _LOCK:
            busy = [s["job"] for s in STATE["slots"].values() if s.get("job")]
        try:
            resp = _req("POST", "/runner/heartbeat",
                        {"status": "busy" if busy else "idle", "slots": CFG.get("concurrency", 1),
                         "busy_slots": len(busy), "current_jobs": busy, "version": VERSION,
                         "engine_version": engine_version(), "ip": _IP, "metrics": m},
                        CFG["token"], timeout=15)
            # the server (Scanners UI) can ask us to run more/fewer boxcutters — adopt it and persist
            if isinstance(resp, dict) and resp.get("desired_slots") is not None:
                ds = max(0, min(int(resp["desired_slots"]), MAX_SLOTS))
                if ds != CFG.get("concurrency", 1):
                    CFG["concurrency"] = ds
                    with _LOCK:
                        STATE["concurrency"] = ds
                    save_config(CFG)
            # the server can ask us to STOP jobs it no longer wants (scan deleted/stopped/reassigned) — the
            # running worker sees the id in CANCEL on its next poll and kills the boxcutter subprocess.
            if isinstance(resp, dict) and resp.get("cancel"):
                with _LOCK:
                    CANCEL.update(int(j) for j in resp["cancel"])
            with _LOCK:
                STATE["connected"] = True
                STATE["error"] = ""
        except urllib.error.HTTPError as e:
            if e.code == 401:                    # token/runner gone (server redeploy) -> re-enroll
                CFG["token"] = ""
                _disc("re-enrolling")
                enroll()
            else:
                _disc(f"heartbeat {e.code}")
        except Exception as e:  # noqa: BLE001
            _disc(f"heartbeat: {e}")
    elif CFG.get("server_url") and (CFG.get("enroll_token") or CFG.get("api_key") or CFG.get("username")):
        enroll()


def heartbeat_loop() -> None:
    """Heartbeat + self-heal. On a 401 (server restart / lost runner row) we re-enroll for a fresh token; on
    success we (re)assert connected. Wrapped so the thread survives anything (a bad metric read, DNS blip …)."""
    while True:
        try:
            _heartbeat_once()
        except Exception:  # noqa: BLE001 - the heartbeat thread must never die
            pass
        time.sleep(10)


# ---- local control UI (login + dashboard) -------------------------------------------------------------------
_SESSION = {"token": None}


def _hash_pw(pw: str) -> str:
    salt = os.urandom(8).hex()
    return f"{salt}${hashlib.pbkdf2_hmac('sha256', pw.encode(), salt.encode(), 100_000).hex()}"


def _check_pw(pw: str, stored: str) -> bool:
    try:
        salt, dk = stored.split("$", 1)
        return hmac.compare_digest(hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 100_000).hex(), dk)
    except Exception:  # noqa: BLE001
        return False


def _validate_login(username: str, password: str) -> bool:
    """Local, self-contained login for the agent's own control UI. The single account is 'root'; its password
    defaults to 'root' and can be changed here (stored hashed in the config). The agent NEVER delegates its
    login to the server — a scanner stays manageable no matter the server's state or credentials."""
    if username != "root":
        return False
    stored = CFG.get("ui_password_hash")
    return _check_pw(password, stored) if stored else (password == "root")


# Material Design 3 (dark) — same theme/tokens as the boxcutter-server SPA, so the two UIs match.
_CSS = """<style>
:root{--primary:#8ab4f8;--on-primary:#06264d;--surface:#131316;--sc-low:#1a1b1f;--sc-high:#282a2e;
--sc-lowest:#0c0d10;--on-surface:#e4e2e6;--on-var:#c5c6cf;--outline:#43474e;--ok:#6dd58c;--bad:#f04438;
--sec:#303f5a;--on-sec:#dae2f9}
*{box-sizing:border-box}
body{font:14px Roboto,"Helvetica Neue",Arial,system-ui,-apple-system,"Segoe UI",sans-serif;margin:0;
background:var(--surface);color:var(--on-surface);-webkit-font-smoothing:antialiased}
.wrap{max-width:760px;margin:0 auto;padding:24px}
h1{font-size:22px;font-weight:400;margin:0}h1::before{content:"\\25D1 ";color:var(--primary)}
h2{font-size:16px;font-weight:500;margin:0 0 8px}
label{display:block;margin:14px 0 6px;color:var(--on-var);font-size:13px;font-weight:500}
input{width:100%;padding:12px 14px;border:1px solid var(--outline);border-radius:4px;background:transparent;
color:var(--on-surface);font:inherit}
input:focus{outline:none;border-color:var(--primary);box-shadow:inset 0 0 0 1px var(--primary)}
button{margin-top:12px;height:40px;padding:0 24px;border:0;border-radius:20px;background:var(--primary);
color:var(--on-primary);font:500 14px Roboto,sans-serif;cursor:pointer;transition:filter .15s,box-shadow .15s}
button:hover{filter:brightness(1.06);box-shadow:0 1px 3px rgba(0,0,0,.4)}
button.ghost{background:var(--sec);color:var(--on-sec)}
.card{background:var(--sc-low);border-radius:12px;padding:20px;margin-top:16px;
box-shadow:0 1px 2px rgba(0,0,0,.3),0 1px 3px 1px rgba(0,0,0,.15)}
.ok{color:var(--ok)}.bad{color:var(--bad)}.muted{color:var(--on-var)}
.row{display:flex;gap:10px;align-items:center;justify-content:space-between;flex-wrap:wrap}
.slot{padding:8px 0;border-top:1px solid var(--outline);font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px}
.meter{height:6px;background:var(--sc-high);border-radius:999px;overflow:hidden;margin:4px 0 10px}
.meter>div{height:100%;background:var(--primary)}
</style>"""

_LOGIN_HTML = ("<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
               "<title>boxcutter scanner</title>" + _CSS + "<div class=wrap style='max-width:360px;margin-top:12vh'>"
               "<h1>boxcutter scanner</h1><div class=card>"
               "<label>Username</label><input id=u value=root>"
               "<label>Password</label><input id=p type=password onkeyup='if(event.key==\"Enter\")login()'>"
               "<p id=err class=bad></p><button style='width:100%' onclick=login()>Log in</button>"
               "<p class=muted style='font-size:12px'>Default login: <b>root / root</b> — change it below after "
               "signing in. This login is local to the scanner, not the server.</p></div></div><script>"
               "async function login(){let r=await fetch('/login',{method:'POST',headers:{'Content-Type':'application/json'},"
               "body:JSON.stringify({username:u.value,password:p.value})});"
               "if(r.ok)location.reload();else document.getElementById('err').textContent='invalid credentials';}"
               "</script>")

_DASH_HTML = ("<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
              "<title>boxcutter scanner</title>" + _CSS + "<div class=wrap>"
              "<div class=row><h1>boxcutter scanner</h1><button class=ghost onclick=logout()>Log out</button></div>"
              "<div class=card><b>Status:</b> <span id=st></span>"
              "<div class=muted style='font-size:12px;margin-top:4px'>IP: <span id=ip></span></div>"
              "<div class=muted style='font-size:12px'>boxcutter <span id=engine></span> "
              "&middot; agent v<span id=agent></span></div>"
              "<div style='margin-top:10px'><span class=muted>CPU</span><div class=meter><div id=cpu></div></div>"
              "<span class=muted>Memory</span><div class=meter><div id=mem></div></div></div></div>"
              "<div class=card><h2>Connection</h2>"
              "<label>Core server URL</label><input id=server placeholder='https://scanner.example.com'>"
              "<label>Enroll token</label><input id=token placeholder='from the Scanners page'>"
              "<label>Number of boxcutters (instances)</label><input id=conc type=number min=0 max=32>"
              "<div class=row style='justify-content:flex-start;gap:8px'>"
              "<button onclick=save()>Save &amp; connect</button>"
              "<button class=ghost id=drainbtn onclick=drain()>Pause (drain)</button></div></div>"
              "<div class=card><h2>Local models (Ollama)</h2>"
              "<div class=muted id=olstat style='font-size:12px'>—</div>"
              "<div id=models style='margin-top:8px'></div></div>"
              "<div class=card><h2>Agent password</h2>"
              "<div class=muted style='font-size:12px'>The scanner's own login (default root/root). Independent of the server.</div>"
              "<label>New password</label><input id=newpw type=password placeholder='at least 4 characters'>"
              "<div class=row style='justify-content:flex-start;gap:8px;margin-top:8px'>"
              "<button onclick=setpw()>Update password</button><span id=pwmsg class=muted></span></div></div>"
              "<div class=card><h2>Running now</h2><div id=slots class=muted>idle</div></div>"
              "<div class=card><h2>Recent jobs</h2><div id=recent class=muted>none yet</div></div>"
              "</div><script>"
              "var _filled=false;"
              "function esc(s){return String(s==null?'':s).replace(/[&<>\"']/g,function(c){return '&#'+c.charCodeAt(0)+';';});}"
              "async function refresh(){let r=await fetch('/state');if(r.status==401){location.reload();return;}let s=await r.json();"
              "document.getElementById('st').innerHTML=s.connected?'<span class=ok>connected</span> (scanner #'+esc(s.runner_id)+')':'<span class=bad>disconnected</span> '+esc(s.error||'');"
              "document.getElementById('ip').textContent=s.ip||'—';"
              "document.getElementById('engine').textContent=s.engine_version||'unknown';"
              "document.getElementById('agent').textContent=s.version||'?';"
              "let m=s.metrics||{};document.getElementById('cpu').style.width=(m.cpu||0)+'%';document.getElementById('mem').style.width=(m.mem||0)+'%';"
              "document.getElementById('drainbtn').textContent=(s.concurrency>0?'Pause (drain)':'Resume');"
              "if(!_filled){if(s.server)server.value=s.server;conc.value=s.concurrency;_filled=true;}"
              "let busy=Object.values(s.slots||{}).filter(x=>x.job);"
              "document.getElementById('slots').innerHTML=busy.length?busy.map(x=>'<div class=slot>job #'+esc(x.job)+' — '+esc(x.target)+'</div>').join(''):'idle';"
              "document.getElementById('recent').innerHTML=(s.recent&&s.recent.length)?s.recent.map(x=>'<div class=slot>'+esc(x.target)+' — '+esc(x.status)+' ('+esc(x.duration)+'s)</div>').join(''):'none yet';}"
              "async function drain(){let c=parseInt(conc.value||'0');if(c>0)window._last=c;conc.value=(c>0?0:(window._last||2));await save();}"
              "async function save(){await fetch('/config',{method:'POST',headers:{'Content-Type':'application/json'},"
              "body:JSON.stringify({server_url:server.value,enroll_token:token.value,concurrency:parseInt(conc.value||'0')})});_filled=false;refresh();}"
              "async function logout(){await fetch('/logout',{method:'POST'});location.reload();}"
              "async function setpw(){let r=await fetch('/set-password',{method:'POST',headers:{'Content-Type':'application/json'},"
              "body:JSON.stringify({new_password:newpw.value})});"
              "document.getElementById('pwmsg').textContent=r.ok?'\\u2713 updated':'too short (min 4)';newpw.value='';}"
              "async function loadModels(){try{let r=await fetch('/models');if(!r.ok)return;let s=await r.json();"
              "document.getElementById('olstat').innerHTML='Ollama '+(s.reachable?'<span class=ok>reachable</span>':'<span class=bad>not running</span>')+' at '+esc(s.base)+' — models run on THIS agent';"
              "let el=document.getElementById('models');el.innerHTML=(s.models||[]).map(function(m){"
              "var a=m.installed?'<span class=ok>installed</span>':(m.pull&&m.pull.status===\"pulling\"?'<span class=muted>'+esc(m.pull.detail||'downloading…')+'</span>':(m.pull&&m.pull.status===\"error\"?'<span class=bad>'+esc(m.pull.detail)+'</span>':'<button data-pull=\"'+esc(m.name)+'\">Download</button>'));"
              "return '<div class=slot style=\"display:flex;justify-content:space-between;align-items:center;gap:8px\"><span>'+esc(m.name)+' <span class=muted>~'+m.size_gb+'GB · '+esc(m.note)+'</span></span><span>'+a+'</span></div>';}).join('');"
              "el.onclick=function(e){var n=e.target.getAttribute('data-pull');if(n)pullModel(n);};}catch(e){}}"
              "async function pullModel(n){await fetch('/pull',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:n})});loadModels();}"
              "setInterval(refresh,2000);setInterval(loadModels,2500);refresh();loadModels();</script>")


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json", cookie=None):
        b = body if isinstance(body, bytes) else body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(b)

    def _authed(self) -> bool:
        tok = _SESSION.get("token")
        return bool(tok) and ("bc_session=" + tok) in self.headers.get("Cookie", "")

    def _json_body(self) -> dict:
        n = int(self.headers.get("Content-Length", 0))
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except Exception:  # noqa: BLE001
            return {}

    def do_GET(self):
        if self.path == "/state":
            if not self._authed():
                return self._send(401, "{}")
            with _LOCK:
                self._send(200, json.dumps({**STATE, "concurrency": CFG.get("concurrency", 1),
                                            "server": CFG.get("server_url", "")}))
        elif self.path == "/models":
            if not self._authed():
                return self._send(401, "{}")
            installed = set(_ollama_installed())
            st = _model_status()
            self._send(200, json.dumps({
                "reachable": _ollama_reachable(), "base": OLLAMA_URL,
                "models": [{**m, "installed": m["name"] in installed, "pull": st.get(m["name"])}
                           for m in MODEL_CATALOG]}))
        elif self._authed():
            self._send(200, _DASH_HTML, "text/html")
        else:
            self._send(200, _LOGIN_HTML, "text/html")

    def do_POST(self):
        if self.path == "/login":
            b = self._json_body()
            if _validate_login(b.get("username", ""), b.get("password", "")):
                tok = os.urandom(16).hex()
                _SESSION["token"] = tok
                return self._send(200, json.dumps({"ok": True}),
                                  cookie=f"bc_session={tok}; Path=/; HttpOnly; SameSite=Strict")
            return self._send(401, json.dumps({"ok": False}))
        if self.path == "/logout":
            _SESSION["token"] = None
            return self._send(200, json.dumps({"ok": True}), cookie="bc_session=; Path=/; Max-Age=0")
        if not self._authed():
            return self._send(401, "{}")
        if self.path == "/config":
            body = self._json_body()
            CFG.update({k: v for k, v in body.items() if k in ("server_url", "enroll_token", "api_key",
                                                               "concurrency", "username", "password", "name")})
            save_config(CFG)
            enroll()
            return self._send(200, json.dumps({"ok": True}))
        if self.path == "/set-password":
            new = str(self._json_body().get("new_password", ""))
            if len(new) < 4:
                return self._send(400, json.dumps({"ok": False, "error": "password too short"}))
            CFG["ui_password_hash"] = _hash_pw(new)
            save_config(CFG)
            return self._send(200, json.dumps({"ok": True}))
        if self.path == "/pull":
            name = str(self._json_body().get("name", ""))
            try:
                _ollama_pull(name)
            except ValueError:
                return self._send(400, json.dumps({"ok": False, "error": "unknown model"}))
            except RuntimeError as e:
                return self._send(503, json.dumps({"ok": False, "error": str(e)}))
            return self._send(200, json.dumps({"ok": True}))
        self._send(404, "{}")

    def log_message(self, *a):  # quiet
        pass


def _spawn(target, args=()):
    t = threading.Thread(target=target, args=args, daemon=True)
    t.start()
    return t


def watchdog(registry: dict) -> None:
    """Resurrect any worker/heartbeat thread that has died. The loops already catch everything, so this should
    almost never fire — but it guarantees a dead thread can never leave a slot permanently gone."""
    while True:
        time.sleep(15)
        try:
            for key, spec in list(registry.items()):
                if not spec["thread"].is_alive():
                    spec["thread"] = _spawn(spec["target"], spec["args"])
                    print(f"[watchdog] respawned {key}", flush=True)
        except Exception:  # noqa: BLE001
            pass


def _run_supervisor() -> int:
    registry: dict = {}
    for i in range(MAX_SLOTS):
        registry[f"worker-{i}"] = {"target": worker, "args": (i,), "thread": _spawn(worker, (i,))}
    registry["heartbeat"] = {"target": heartbeat_loop, "args": (), "thread": _spawn(heartbeat_loop)}
    _spawn(watchdog, (registry,))
    if CFG.get("server_url") and (CFG.get("enroll_token") or CFG.get("api_key") or CFG.get("username")):
        enroll()
    port = UI_PORT
    srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"boxcutter agent {VERSION} - control UI on http://127.0.0.1:{port}  "
          f"(server={CFG.get('server_url') or 'unset'}, connected={STATE['connected']})", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


def main(argv=None) -> int:
    """``boxcutter agent`` - run this host as a scale-out scanner: enroll with a core server, pull jobs, run
    boxcutter in N slots, heartbeat, and serve a small local control UI. Flags override env / the config file;
    with none given it reads env (SERVER_URL / ENROLL_TOKEN / CONCURRENCY / ...) and the saved config."""
    ap = argparse.ArgumentParser(
        prog="boxcutter agent",
        description="Run boxcutter as a scanner agent: pull jobs from a core server and execute them.")
    ap.add_argument("--server", metavar="URL", help="core server URL, e.g. https://scanner.example.com")
    ap.add_argument("--token", dest="enroll_token", metavar="TOKEN",
                    help="enroll token from the server's Scanners page")
    ap.add_argument("--api-key", dest="api_key", metavar="KEY",
                    help="enroll with a system-user API key instead of a token")
    ap.add_argument("--user", metavar="NAME", help="enroll with username/password instead of a token")
    ap.add_argument("--password", metavar="PW", help="password for --user")
    ap.add_argument("--concurrency", type=int, metavar="N",
                    help="number of boxcutter slots to run (0 = paused; default 2)")
    ap.add_argument("--name", metavar="NAME", help="display name shown on the server's Scanners page")
    ap.add_argument("--ui-port", type=int, metavar="PORT", help="local control-UI port (default 7070)")
    ap.add_argument("--config", metavar="FILE", help="runner config file (persists server/token/concurrency)")
    ap.add_argument("--mock", action="store_true", help="run the pipeline WITHOUT the engine (offline demo)")
    a = ap.parse_args([] if argv is None else list(argv))

    global CONFIG_PATH, MOCK, UI_PORT
    if a.config:
        CONFIG_PATH = a.config
        CFG.clear()
        CFG.update(load_config())
    if a.mock:
        MOCK = True
    for key, val in (("server_url", a.server), ("enroll_token", a.enroll_token), ("api_key", a.api_key),
                     ("username", a.user), ("password", a.password), ("name", a.name)):
        if val:
            CFG[key] = val
    if a.concurrency is not None:
        CFG["concurrency"] = max(0, min(a.concurrency, MAX_SLOTS))
    if a.ui_port is not None:
        UI_PORT = a.ui_port            # flag override for THIS run; never written to the persisted config
    save_config(CFG)
    return _run_supervisor()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
