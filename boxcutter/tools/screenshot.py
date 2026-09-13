"""screenshot - capture a URL in a real browser (Chrome DevTools Protocol).

A native reimplementation of zzzteph/screenshot (originally Java/Selenium): drive
the system chromium over CDP - the same engine browser-login/harvest use - at a
1920x1080 viewport with certificate errors ignored, wait for JS to render, then
capture the page.

Emits KIND=screenshots: one record per URL with the full screenshot and a
thumbnail, both PNG base64 - the screenshot DATA TYPE {url, title, full, thumbnail}.
With -s / -d / --save-thumb it also writes the PNG(s) and HTML source to files.

Full-image tool: needs chromium + websocket-client (as with the other browser tools).
"""

from __future__ import annotations

import base64

from ..core.args import add_common_args, add_header_arg
from ..core.cdp import CDPError, Chrome
from ..core.envelope import debug_logger, output_result
from ..core.validators import is_valid_url

NAME = "screenshot"
KIND = "screenshots"
HELP = "Screenshot a URL in a real browser (CDP) -> {url, full, thumbnail}; optional PNG/source files."


def add_arguments(parser) -> None:
    parser.add_argument("target", help="Target URL")
    parser.add_argument("-s", "--save", dest="save_image", default=None, metavar="PATH",
                        help="Also write the full PNG to this file (e.g. /tmp/site.png)")
    parser.add_argument("--save-thumb", dest="save_thumb", default=None, metavar="PATH",
                        help="Also write the thumbnail PNG to this file")
    parser.add_argument("-d", "--source", dest="save_source", default=None, metavar="PATH",
                        help="Also write the rendered HTML source to this file")
    parser.add_argument("--full-page", dest="full_page", action="store_true",
                        help="Capture the whole scrollable page, not just the viewport")
    parser.add_argument("--thumb-scale", dest="thumb_scale", type=float, default=0.25, metavar="F",
                        help="Thumbnail scale relative to the full capture (default 0.25)")
    parser.add_argument("--wait", type=int, default=5000, metavar="MS",
                        help="Wait this many ms after load for JS to render (default 5000)")
    parser.add_argument("--timeout", type=int, default=45, help="Per-page timeout (seconds)")
    add_header_arg(parser)
    add_common_args(parser)


def _write_png(path: str, b64: str, dbg) -> bool:
    try:
        with open(path, "wb") as fh:
            fh.write(base64.b64decode(b64))
        dbg(f"wrote {path}")
        return True
    except (OSError, ValueError) as exc:
        dbg(f"could not write {path}: {exc}")
        return False


def run(args) -> int:
    target = args.target.strip()
    dbg = debug_logger(args.debug)
    if not is_valid_url(target):
        output_result([], args.output, "Invalid URL.")
        return 1

    headers: dict[str, str] = {}
    for h in args.header:
        if ":" in h:
            name, value = h.split(":", 1)
            headers[name.strip()] = value.strip()

    try:
        with Chrome(headers=headers, timeout=args.timeout, debug=dbg, viewport=(1920, 1080)) as page:
            status = page.navigate(target, wait="networkidle")
            if args.wait > 0:
                page.wait(args.wait)
            full = page.screenshot(full_page=args.full_page)
            thumbnail = page.screenshot(full_page=args.full_page, scale=args.thumb_scale)
            try:
                title = page.eval("document.title") or ""
            except CDPError:
                title = ""
            source = page.content()
    except CDPError as exc:
        output_result([], args.output, f"screenshot unavailable: {exc}")
        return 1
    except Exception as exc:  # noqa: BLE001
        output_result([], args.output, f"screenshot failed: {exc}")
        return 1

    if not full:
        output_result([], args.output, "no screenshot captured.")
        return 1

    # the screenshot DATA TYPE: url + the full capture + a thumbnail (both PNG base64)
    record = {"url": target, "title": title, "status": status, "full": full, "thumbnail": thumbnail}

    if args.save_image and _write_png(args.save_image, full, dbg):
        record["screenshot_path"] = args.save_image
    if args.save_thumb and thumbnail and _write_png(args.save_thumb, thumbnail, dbg):
        record["thumbnail_path"] = args.save_thumb
    if args.save_source and source:
        try:
            with open(args.save_source, "w", encoding="utf-8") as fh:
                fh.write(source)
            record["source_path"] = args.save_source
            dbg(f"wrote source to {args.save_source}")
        except OSError as exc:
            dbg(f"could not write source: {exc}")

    output_result([record], args.output)
    return 0
