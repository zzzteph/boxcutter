"""subfinder - passive subdomain discovery. Port of app:subfinder."""

from __future__ import annotations

from ..core import fsutil, process
from ..core.args import add_common_args
from ..core.envelope import debug_logger, output_result
from ..core.validators import is_valid_domain_name

NAME = "subfinder"
KIND = "urls"
HELP = "Discover subdomains of a target domain using Subfinder."


def add_arguments(parser) -> None:
    parser.add_argument("target", help="Target domain")
    add_common_args(parser)


def run(args) -> int:
    target = args.target.strip()
    dbg = debug_logger(args.debug)

    tmp = fsutil.temp_file("subfinder_")
    dbg(f"Creating tmp file: {tmp}")

    cmd = ["subfinder", "-max-time", "3", "--silent", "-o", tmp, "-d", target]
    dbg(f"Command: {process.format_command(cmd)}")

    result = process.run(cmd, timeout=240)
    if not result.successful():
        dbg("subfinder exited with a non-zero status.")

    output = fsutil.read_text(tmp)
    fsutil.remove(tmp)

    dbg("Parsing subfinder results")

    domains: list[str] = []
    for line in output.splitlines():
        line = line.strip()
        if not is_valid_domain_name(line):
            continue
        if target != line and not line.endswith("." + target):
            dbg(f"Subdomain {line} - not under {target}, skipping")
            continue
        if line not in domains:
            domains.append(line)

    output_result(domains, args.output)
    return 0
