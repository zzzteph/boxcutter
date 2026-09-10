"""Run the bundled ZAP as a long-lived PROXY DAEMON so an agent can capture ALL its traffic and query the
history over ZAP's REST API - zero new dependency (ZAP already ships in the image; see tools/_zap.py which uses
it in one-shot autorun mode instead).

Usage (see vera):
    z = start(dbg)                     # launches `zap.sh -daemon`, waits for the API, exports the CA
    os.environ["HTTP_PROXY"] = os.environ["HTTPS_PROXY"] = z.proxy
    os.environ["REQUESTS_CA_BUNDLE"] = z.ca_file      # so requests-based tools trust ZAP's MITM cert
    ... run the agent; every request that honours HTTP(S)_PROXY is recorded ...
    msgs = messages(z, baseurl="https://target/")     # condensed history for the model to analyse
    full = message(z, mid)                            # one full request/response exchange (evidence)
    shutdown(z)

Everything here is best-effort: if ZAP is not installed or never comes up, start() returns None and the caller
falls back to plain in-process capture. Nothing raises into the run.
"""
from __future__ import annotations

import json
import os
import secrets
import socket
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass

from ..core import fsutil, process

ZAP_SH = "/usr/share/zaproxy/zap.sh"
JMEM = "-Xmx1500m"


@dataclass
class Zap:
    proc: object
    port: int
    key: str
    home: str
    ca_file: str

    @property
    def proxy(self) -> str:
        return f"http://127.0.0.1:{self.port}"


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _api(z: Zap, path: str, **params) -> dict | None:
    """Call a ZAP JSON API endpoint; return the parsed dict or None on any failure."""
    params["apikey"] = z.key
    url = f"http://127.0.0.1:{z.port}{path}?" + urllib.parse.urlencode(params)
    try:
        with urllib.request.urlopen(url, timeout=30) as r:   # noqa: S310 - localhost daemon we started
            return json.loads(r.read().decode("utf-8", "replace"))
    except Exception:  # noqa: BLE001
        return None


def _wait_ready(z: Zap, dbg, timeout: int = 90) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        v = _api(z, "/JSON/core/version/")
        if v and v.get("version"):
            dbg(f"vera :: ZAP proxy up on :{z.port} (v{v['version']})")
            return True
        time.sleep(2)
    dbg("vera :: ZAP proxy did not become ready; falling back to in-process capture")
    return False


def start(dbg) -> Zap | None:
    """Launch ZAP in daemon+proxy mode on a free port, wait for its API, and export its root CA to a temp file.
    Returns a Zap handle, or None if ZAP is unavailable / never came up (caller then skips proxy capture)."""
    if not os.path.exists(ZAP_SH):
        dbg("vera :: ZAP not installed (no zap.sh) - skipping proxy capture")
        return None
    port = _free_port()
    key = secrets.token_hex(12)
    home = fsutil.temp_dir("vera-zap_")
    cmd = [ZAP_SH, "-daemon", "-dir", home, "-host", "127.0.0.1", "-port", str(port),
           "-config", f"api.key={key}",
           "-config", "api.addrs.addr.name=127.0.0.1", "-config", "api.addrs.addr.regex=false"]
    try:
        proc = process.spawn(cmd, env={"JMEM": JMEM}) if hasattr(process, "spawn") else None
    except Exception:  # noqa: BLE001
        proc = None
    if proc is None:
        # process has no spawn(): launch detached via subprocess directly
        import subprocess
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
                                    env={**os.environ, "JMEM": JMEM})
        except Exception as exc:  # noqa: BLE001
            dbg(f"vera :: could not launch ZAP daemon ({exc}) - skipping proxy capture")
            fsutil.remove_dir(home)
            return None
    z = Zap(proc=proc, port=port, key=key, home=home, ca_file=os.path.join(home, "zap-ca.pem"))
    if not _wait_ready(z, dbg):
        shutdown(z)
        return None
    _export_ca(z, dbg)
    return z


def _export_ca(z: Zap, dbg) -> None:
    """Write ZAP's dynamic root CA to z.ca_file so requests-based tools can trust its MITM cert over HTTPS."""
    url = f"http://127.0.0.1:{z.port}/OTHER/core/other/rootcert/?apikey={z.key}"
    try:
        with urllib.request.urlopen(url, timeout=30) as r:   # noqa: S310
            pem = r.read()
        if pem and b"BEGIN CERTIFICATE" in pem:
            with open(z.ca_file, "wb") as fh:
                fh.write(pem)
            dbg(f"vera :: ZAP root CA exported to {z.ca_file}")
            return
    except Exception:  # noqa: BLE001
        pass
    z.ca_file = ""      # no CA available; HTTPS through the proxy will need verify off (caller decides)
    dbg("vera :: could not export ZAP CA; HTTPS capture may fail cert validation")


def _first_line(raw: str) -> str:
    return (raw or "").splitlines()[0] if raw else ""


def messages(z: Zap, baseurl: str | None = None, limit: int = 200) -> list[dict]:
    """Condensed capture history: [{id, method, url, status}] most-recent-last, optionally scoped to baseurl."""
    params = {"start": "0", "count": str(limit)}
    if baseurl:
        params["baseurl"] = baseurl
    data = _api(z, "/JSON/core/messages/", **params) or {}
    out = []
    for m in data.get("messages", []) or []:
        req_line = _first_line(m.get("requestHeader", ""))
        resp_line = _first_line(m.get("responseHeader", ""))
        method, _, rest = req_line.partition(" ")
        url = rest.rsplit(" ", 1)[0] if rest else ""
        status = ""
        parts = resp_line.split(" ")
        if len(parts) >= 2:
            status = parts[1]
        out.append({"id": m.get("id"), "method": method, "url": url, "status": status})
    return out


def message(z: Zap, mid: str | int) -> dict | None:
    """One full request/response exchange by id - the evidence a finding cites."""
    data = _api(z, "/JSON/core/message/", id=str(mid)) or {}
    m = data.get("message") or {}
    if not m:
        return None
    return {"id": m.get("id"),
            "request": {"header": m.get("requestHeader", ""), "body": m.get("requestBody", "")},
            "response": {"header": m.get("responseHeader", ""), "body": (m.get("responseBody", "") or "")[:2000]}}


def shutdown(z: Zap | None) -> None:
    """Ask ZAP to shut down cleanly, then hard-kill and remove its home dir. Never raises."""
    if not z:
        return
    try:
        _api(z, "/JSON/core/shutdown/")
    except Exception:  # noqa: BLE001
        pass
    try:
        z.proc.terminate()
        z.proc.wait(timeout=15)
    except Exception:  # noqa: BLE001
        try:
            z.proc.kill()
        except Exception:  # noqa: BLE001
            pass
    fsutil.remove_dir(z.home)
