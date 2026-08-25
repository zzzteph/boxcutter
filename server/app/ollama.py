"""Curated small Ollama models (fit ~8GB RAM) + helpers to list/pull them on a configured Ollama host.

Ollama runs OUTSIDE the boxcutter image (a separate runtime), reached at ``settings.ollama_base_url`` (its root,
e.g. ``http://localhost:11434``). This module offers a one-click download of a shortlist and lists what is
installed, so an admin can pull a model and wire it into an ai_agent template (provider ``ollama``) without
leaving the UI. The pull runs in a background thread with pollable progress; the server is single-worker, so an
in-memory tracker is fine.
"""
from __future__ import annotations

import json
import threading
import urllib.request

# Curated for a ~8GB-RAM box (Ollama's default Q4 quant). size_gb ~= RAM footprint (model + a little context).
CATALOG = [
    {"name": "qwen2.5:3b",       "size_gb": 2.0, "note": "fast, low-RAM; weakest reasoning"},
    {"name": "llama3.2:3b",      "size_gb": 2.0, "note": "low-RAM alternative"},
    {"name": "phi3.5",           "size_gb": 2.2, "note": "3.8B, decent for its size"},
    {"name": "mistral:7b",       "size_gb": 4.4, "note": "solid all-round"},
    {"name": "qwen2.5:7b",       "size_gb": 4.7, "note": "recommended: best small tool-use + reasoning"},
    {"name": "qwen2.5-coder:7b", "size_gb": 4.7, "note": "structured / tool-use"},
    {"name": "llama3.1:8b",      "size_gb": 4.9, "note": "strong; the engine default"},
]
_NAMES = {m["name"] for m in CATALOG}

_PULLS: dict = {}                       # name -> {"status": pulling|done|error, "detail": str}
_LOCK = threading.Lock()


_RESOLVED = {"url": ""}
# When ollama_base_url is unset, try these in order. host.docker.internal is the Docker-Desktop bridge to the
# HOST's Ollama - the common case where the server runs in a container and Ollama runs on the machine.
_DEFAULT_CANDIDATES = ("http://localhost:11434", "http://host.docker.internal:11434")


def base_url() -> str:
    """The Ollama root URL. An explicit ollama_base_url always wins; otherwise the first reachable of
    localhost / host.docker.internal, probed once and cached (so the server-in-Docker + Ollama-on-host case
    works with no config)."""
    from .config import settings
    if settings.ollama_base_url:
        return settings.ollama_base_url.rstrip("/")
    if _RESOLVED["url"]:
        return _RESOLVED["url"]
    for cand in _DEFAULT_CANDIDATES:
        try:
            urllib.request.urlopen(cand + "/api/tags", timeout=2).read()
            _RESOLVED["url"] = cand
            return cand
        except Exception:  # noqa: BLE001
            continue
    return _DEFAULT_CANDIDATES[0]                        # nothing up yet; localhost for a clear error message


def openai_base() -> str:
    """The OpenAI-compatible endpoint boxcutter's ollama provider talks to (root + /v1)."""
    return base_url() + "/v1"


def _get(path: str, timeout: int = 8):
    with urllib.request.urlopen(base_url() + path, timeout=timeout) as r:
        return json.loads(r.read().decode() or "{}")


def reachable() -> bool:
    try:
        _get("/api/tags", timeout=3)
        return True
    except Exception:  # noqa: BLE001
        return False


def list_installed() -> list:
    """Model names already pulled on the Ollama host (empty if unreachable)."""
    try:
        data = _get("/api/tags")
        return sorted({(m.get("name") or "").split("@")[0]
                       for m in (data.get("models") or []) if m.get("name")})
    except Exception:  # noqa: BLE001
        return []


def _friendly(exc) -> str:
    """Turn a raw urllib connection error into an actionable message."""
    s = str(exc)
    low = s.lower()
    if "refused" in low or "111" in s or "10061" in s or "urlopen" in low or "timed out" in low:
        return f"Ollama not reachable at {base_url()} - is it running? (start Ollama, or set ollama_base_url)"
    return s[:200]


def pull_async(name: str) -> None:
    """Start a background pull of a catalog model. Raises ValueError for a model not in the catalog, or a
    RuntimeError with a clear message when the Ollama host is not reachable."""
    if name not in _NAMES:
        raise ValueError("model is not in the curated catalog")
    if not reachable():
        raise RuntimeError(f"Ollama not reachable at {base_url()} - is it running? "
                           "(start Ollama on that host, or set ollama_base_url)")
    with _LOCK:
        if _PULLS.get(name, {}).get("status") == "pulling":
            return
        _PULLS[name] = {"status": "pulling", "detail": "starting"}
    threading.Thread(target=_do_pull, args=(name,), daemon=True).start()


def _do_pull(name: str) -> None:
    try:
        body = json.dumps({"name": name, "stream": True}).encode()
        req = urllib.request.Request(base_url() + "/api/pull", data=body,
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
                detail = _progress(j) or detail
                with _LOCK:
                    _PULLS[name] = {"status": "pulling", "detail": detail}
        with _LOCK:
            _PULLS[name] = {"status": "done", "detail": "installed"}
    except Exception as exc:  # noqa: BLE001
        with _LOCK:
            _PULLS[name] = {"status": "error", "detail": _friendly(exc)}


def _progress(j: dict) -> str:
    st = j.get("status", "")
    total, done = j.get("total"), j.get("completed")
    if total:
        return f"{st} {int(100 * (done or 0) / total)}%"
    return st


def pull_status() -> dict:
    with _LOCK:
        return {k: dict(v) for k, v in _PULLS.items()}
