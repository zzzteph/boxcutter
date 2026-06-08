"""External process execution - the Python port of Laravel's ``Process`` usage.

The PHP commands all follow the same shape: start a tool with a timeout, let
it stream into a temp file, and on timeout kill it but still parse whatever it
already wrote. :func:`run` reproduces that: a hard wall-clock timeout, a
graceful-then-forceful kill that takes down the whole process group (so ZAP's
firefox/geckodriver children don't get orphaned), and the captured output
returned regardless of how the process ended.
"""

from __future__ import annotations

import os
import shlex
import signal
import subprocess
from dataclasses import dataclass


@dataclass
class ProcResult:
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool

    def successful(self) -> bool:
        return self.returncode == 0


_POSIX = os.name == "posix"


def split_opt_args(opt_args: str | None) -> list[str]:
    """Split a raw ``--opt-args`` string into argv tokens (shell-style)."""
    if not opt_args:
        return []
    try:
        return shlex.split(opt_args)
    except ValueError:
        # Unbalanced quotes - fall back to a naive split rather than crashing.
        return opt_args.split()


def format_command(args: list[str]) -> str:
    """Shell-quoted single-line rendering of an argv list, for --debug display.

    The command is run via argv (no shell), so a target containing ``&``, spaces
    or other metacharacters is always safe; this just makes the printed line
    accurate and copy-pasteable.
    """
    return shlex.join(args)


def run(
    args: list[str],
    timeout: int,
    *,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
    grace_seconds: int = 5,
) -> ProcResult:
    """Run ``args`` (an argv list, no shell) with a wall-clock ``timeout``.

    On timeout the process group is sent SIGTERM, given ``grace_seconds`` to
    tear down, then SIGKILL'd. Output captured up to that point is returned with
    ``timed_out=True``.
    """
    full_env = {**os.environ, **(env or {})}

    popen_kwargs: dict = {
        "cwd": cwd,
        "env": full_env,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "text": True,
        "encoding": "utf-8",
        "errors": "replace",
    }
    if _POSIX:
        popen_kwargs["start_new_session"] = True  # own process group for killpg

    try:
        proc = subprocess.Popen(args, **popen_kwargs)
    except FileNotFoundError as exc:
        return ProcResult(127, "", f"{args[0]}: not found ({exc})", False)

    try:
        out, err = proc.communicate(timeout=timeout)
        return ProcResult(proc.returncode, out or "", err or "", False)
    except subprocess.TimeoutExpired:
        _terminate(proc, grace_seconds)
        try:
            out, err = proc.communicate(timeout=grace_seconds)
        except subprocess.TimeoutExpired:
            out, err = "", ""
        return ProcResult(proc.returncode, out or "", err or "", True)


def _terminate(proc: subprocess.Popen, grace_seconds: int) -> None:
    """Send SIGTERM then SIGKILL to the process (group on POSIX)."""
    try:
        if _POSIX:
            pgid = os.getpgid(proc.pid)
            os.killpg(pgid, signal.SIGTERM)
        else:
            proc.terminate()
    except (ProcessLookupError, PermissionError, OSError):
        return

    try:
        proc.wait(timeout=grace_seconds)
        return
    except subprocess.TimeoutExpired:
        pass

    try:
        if _POSIX:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        else:
            proc.kill()
    except (ProcessLookupError, PermissionError, OSError):
        pass
