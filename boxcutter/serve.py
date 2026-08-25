"""``boxcutter serve`` - run the boxcutter web server (API + built SPA) plus one built-in agent, in this
container/host.

The server's own dependencies (FastAPI / uvicorn / SQLModel / ...) are deliberately NOT part of the lean
engine. In the published image they live in a dedicated venv, and ``serve`` re-execs that interpreter when the
current one can't import uvicorn. To run ``serve`` from a source checkout, install them first:

    pip install -r server/requirements.txt   # then: boxcutter serve

The built-in agent auto-enrolls to the local server and starts IDLE (0 slots) - raise it from the Scanners
page, or run separate ``boxcutter agent`` hosts to scale out.
"""
from __future__ import annotations

import argparse
import os
import secrets
import signal
import subprocess
import sys
import time
import urllib.request

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))    # repo root: has boxcutter.py, server/, web/
_SERVER_DIR = os.path.join(_ROOT, "server")
_BOXCUTTER = os.path.join(_ROOT, "boxcutter.py")


def _log(msg: str) -> None:
    print(f"[boxcutter serve] {msg}", flush=True)


def _server_python() -> list:
    """Interpreter to run uvicorn with: the current one if it already has uvicorn, else a bundled server venv
    (the image ships one at /opt/srv), else none (with an install hint)."""
    try:
        import uvicorn  # noqa: F401
        return [sys.executable]
    except Exception:  # noqa: BLE001
        pass
    for cand in (os.environ.get("BOXCUTTER_SERVER_PYTHON"), "/opt/srv/bin/python", "/opt/srv/bin/python3"):
        if cand and os.path.exists(cand):
            return [cand]
    _log("server dependencies not found. Install them with:\n"
         "    pip install -r server/requirements.txt\n"
         "or use the boxcutter Docker image, which bundles them.")
    return []


def _wait_healthy(proc, url: str, tries: int = 90) -> bool:
    for _ in range(tries):
        if proc.poll() is not None:
            return False
        try:
            urllib.request.urlopen(url, timeout=2).read()
            return True
        except Exception:  # noqa: BLE001
            time.sleep(1)
    return False


def _spawn_agent(port: int, token: str, data_dir: str):
    env = dict(os.environ)
    env["SERVER_URL"] = f"http://127.0.0.1:{port}"
    env["ENROLL_TOKEN"] = token
    env["RUNNER_INTERNAL"] = "1"                         # a permanent, non-removable singleton runner
    env.setdefault("CONCURRENCY", "0")                  # idle by default - raise it from the Scanners page
    env.setdefault("RUNNER_CONFIG", os.path.join(data_dir, ".runner-config.json"))
    env.setdefault("RUNNER_NAME", "built-in")
    return subprocess.Popen([sys.executable, _BOXCUTTER, "agent"], env=env)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="boxcutter serve",
        description="Run the boxcutter web UI/API server plus one built-in agent.")
    ap.add_argument("--host", default=os.environ.get("HOST", "0.0.0.0"))
    ap.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8000")))
    ap.add_argument("--no-agent", action="store_true", help="API/UI only - do not start the built-in agent")
    ap.add_argument("--data-dir", default=os.environ.get("DATA_DIR", os.path.join(_SERVER_DIR, "data")),
                    help="where the SQLite DB + JWT secret live (default: server/data)")
    a = ap.parse_args([] if argv is None else list(argv))

    py = _server_python()
    if not py:
        return 1

    env = dict(os.environ)
    env.setdefault("PYTHONUNBUFFERED", "1")
    # so the /runner.py bootstrap endpoint can still serve the agent source in the merged image
    env.setdefault("RUNNER_BOOTSTRAP_PATH", os.path.join(_ROOT, "boxcutter", "agent.py"))
    # a shared enroll token: the server seeds it (ENROLL_TOKEN), the built-in agent enrolls with it
    token = env.get("ENROLL_TOKEN") or secrets.token_urlsafe(24)
    env["ENROLL_TOKEN"] = token

    _log(f"starting server on {a.host}:{a.port}  (data: {a.data_dir})")
    server = subprocess.Popen(
        [*py, "-m", "uvicorn", "app.main:app", "--host", a.host, "--port", str(a.port),
         "--proxy-headers", "--forwarded-allow-ips=*"],
        cwd=_SERVER_DIR, env=env)

    if not _wait_healthy(server, f"http://127.0.0.1:{a.port}/health"):
        _log("server did not become healthy - aborting")
        try:
            server.terminate()
        except Exception:  # noqa: BLE001
            pass
        return 1
    _log("server healthy")

    procs = {"server": server}
    if not a.no_agent:
        _log("starting built-in agent (idle; raise its slots from the Scanners page)")
        procs["agent"] = _spawn_agent(a.port, token, a.data_dir)

    def _shutdown(*_):
        for p in procs.values():
            try:
                p.terminate()
            except Exception:  # noqa: BLE001
                pass
    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    # Self-heal: restart a died built-in agent; if the SERVER dies, exit so Docker restarts the container clean.
    restarts, last_start = 0, time.time()
    while True:
        if server.poll() is not None:
            _log(f"server exited ({server.returncode}); stopping")
            if procs.get("agent"):
                try:
                    procs["agent"].terminate()
                except Exception:  # noqa: BLE001
                    pass
            return server.returncode or 1
        ag = procs.get("agent")
        if ag is not None and ag.poll() is not None:
            now = time.time()
            if now - last_start > 60:
                restarts = 0
            restarts += 1
            if restarts > 5:
                _log("built-in agent crash-looping; stopping so the container restarts clean")
                return 1
            _log(f"built-in agent exited ({ag.returncode}); restarting (attempt {restarts})")
            time.sleep(min(2 * restarts, 10))
            procs["agent"] = _spawn_agent(a.port, token, a.data_dir)
            last_start = time.time()
        time.sleep(1)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
