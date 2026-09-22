"""In-browser console to authorize Claude Code INSIDE this container (the Docker-level login).

Bridges an xterm.js terminal to a PTY running ONLY the whitelisted `claude` command in the server container, so
an admin can run `claude` + /login from the browser without `docker exec`. The credentials land under
CLAUDE_CONFIG_DIR (the /data volume) and persist, so every operator run with a claude-code profile then rides
that login - no API key. This mirrors security-forge's in-image authorization console.

POSIX only (the container is Linux; a Windows dev host has no pty). Admin only. The JWT rides the query string
because a browser WebSocket can't set an Authorization header - the same query-param auth `decode_user` already
serves for SSE.
"""
from __future__ import annotations

import asyncio
import os
import shutil

from fastapi import APIRouter, WebSocket
from sqlmodel import Session

from ..db import engine
from ..security import decode_user

router = APIRouter(tags=["operator"])

# Whitelisted commands the PTY may run - the Claude Code login/authorize flow only, never an arbitrary shell.
_CMDS = {"claude": ["claude"]}
_RESIZE = "\x00resize:"


def _authed_admin(token: str):
    if not token:
        return None
    with Session(engine) as s:
        u = decode_user(token, s)
        return u if (u and u.role == "admin") else None


@router.websocket("/console/claude/ws")
async def claude_console(ws: WebSocket):
    await ws.accept()
    if not _authed_admin(ws.query_params.get("token", "")):
        await ws.send_text("not authorized (admin only)\r\n")
        await ws.close()
        return
    argv = _CMDS.get(ws.query_params.get("cmd", "claude"))
    if not argv or not shutil.which(argv[0]):
        await ws.send_text(f"'{(argv or ['?'])[0]}' is not installed in this image "
                           "(build the full image with INSTALL_CLAUDE_CODE=true).\r\n")
        await ws.close()
        return
    try:
        import fcntl  # noqa: E401  (POSIX-only, imported lazily)
        import pty
        import struct
        import subprocess
        import termios
        master, slave = pty.openpty()
        env = {**os.environ, "TERM": "xterm-256color"}
        proc = subprocess.Popen(argv, stdin=slave, stdout=slave, stderr=slave,
                                start_new_session=True, env=env)
        os.close(slave)
    except Exception as e:  # noqa: BLE001  (no pty on a Windows dev host - it runs in the Linux container)
        await ws.send_text(f"cannot open a console here: {e}\r\n"
                           "This terminal is Linux-only - it runs inside the container, not on a Windows host.\r\n")
        await ws.close()
        return

    loop = asyncio.get_event_loop()
    await ws.send_text(f"$ {' '.join(argv)}\r\n")

    def _read() -> bytes:
        try:
            return os.read(master, 4096)
        except OSError:                                   # EIO when the child exits and closes the pty
            return b""

    async def pump_out():
        while True:
            data = await loop.run_in_executor(None, _read)
            if not data:
                break
            await ws.send_text(data.decode("utf-8", "replace"))

    async def pump_in():
        while True:
            msg = await ws.receive_text()
            if msg.startswith(_RESIZE):
                try:
                    cols, rows = (int(x) for x in msg[len(_RESIZE):].split(","))
                    fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
                except (ValueError, OSError):
                    pass
            else:
                os.write(master, msg.encode("utf-8"))

    tasks = [asyncio.create_task(pump_out()), asyncio.create_task(pump_in())]
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    except Exception:  # noqa: BLE001
        pass
    for t in tasks:
        t.cancel()
    for fn in (proc.terminate, lambda: os.close(master)):
        try:
            fn()
        except Exception:  # noqa: BLE001
            pass
    try:
        await ws.send_text("\r\n[console closed - reopen the picker to refresh the login status]\r\n")
        await ws.close()
    except Exception:  # noqa: BLE001
        pass
