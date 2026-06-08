"""screenshot - capture a target URL with httpx headless. Port of app:screenshot.

httpx drives chromium to render the page; we base64-encode the resulting PNG.
"""

from __future__ import annotations

import base64
import json
import os

from ..core import fsutil, process
from ..core.args import add_common_args, add_header_arg, add_opt_args
from ..core.envelope import debug_logger, output_result
from ..core.validators import is_valid_url

NAME = "screenshot"
KIND = "items"
HELP = "Take a screenshot of a target URL using httpx (headless chromium)."


def add_arguments(parser) -> None:
    parser.add_argument("target", help="Target URL")
    add_opt_args(parser)
    add_header_arg(parser)
    add_common_args(parser)


def run(args) -> int:
    target = args.target.strip()
    dbg = debug_logger(args.debug)

    if not is_valid_url(target):
        output_result([], args.output, "Invalid URL.")
        return 1

    work_dir = fsutil.temp_dir("screenshot_")
    out_file = fsutil.temp_file("scr_output_")

    cmd = [
        "httpx", "-u", target, "-fr", "-ss", "-sr", "-silent",
        "-no-screenshot-full-page", "-title", "-srd", work_dir, "-j", "-o", out_file,
    ]
    for header in args.header:
        cmd += ["-H", header]
    cmd += process.split_opt_args(args.opt_args)
    dbg(f"Command: {process.format_command(cmd)}")

    process.run(cmd, timeout=30)

    if not os.path.exists(out_file) or os.path.getsize(out_file) == 0:
        _cleanup(out_file, work_dir)
        output_result([], args.output, "httpx produced no output.")
        return 1

    try:
        data = json.loads(fsutil.read_text(out_file).strip())
    except json.JSONDecodeError:
        data = None

    if not isinstance(data, dict) or "screenshot_path" not in data:
        _cleanup(out_file, work_dir)
        output_result([], args.output, "Screenshot path not found in httpx output.")
        return 1

    screenshot_path = data["screenshot_path"]
    if not os.path.exists(screenshot_path) or os.path.getsize(screenshot_path) <= 10:
        _cleanup(out_file, work_dir)
        output_result([], args.output, "Screenshot file missing or empty.")
        return 1

    image_bytes = fsutil.read_bytes(screenshot_path) or b""

    result = {
        "url": data.get("url", ""),
        "title": data.get("title", ""),
        "content": data.get("headless_body", ""),
        "image": base64.b64encode(image_bytes).decode("ascii"),
    }

    _cleanup(out_file, work_dir)
    output_result([result], args.output)
    return 0


def _cleanup(out_file: str, work_dir: str) -> None:
    fsutil.remove(out_file)
    fsutil.remove_dir(work_dir)
