"""git-extract - reconstruct source from an exposed .git dir, scan for secrets.
Port of app:git-extract.

Walks loose objects from HEAD/packed-refs and (when present) enumerates pack
index SHAs, inflates each object, rebuilds the file tree, then runs secret
regexes over the blobs and collects reviewable source files. Output envelope
carries an extra ``sources`` array.
"""

from __future__ import annotations

import re
import struct
import zlib

from ..core import http
from ..core.args import add_common_args
from ..core.envelope import output_result
from ..core.validators import is_valid_url

NAME = "git-extract"
KIND = "findings"
HELP = "Extract source from an exposed .git directory and scan it for secrets."

_SCAN_PATTERNS = [
    ("Private Key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY", re.I), "high"),
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}"), "high"),
    ("GitHub Token", re.compile(r"gh[pousr]_[A-Za-z0-9_]{16,}"), "high"),
    ("AWS Secret", re.compile(r"aws[_\-]?secret[_\-]?(?:access[_\-]?)?key\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{20,}", re.I), "high"),
    ("Database URL", re.compile(r"(?:mysql|postgres|mongodb|redis|mssql)://[^:\s]+:[^@\s]+@[^\s]+", re.I), "high"),
    ("Password", re.compile(r"(?:password|passwd|pwd)\s*[=:]\s*['\"]?(?!null|true|false|undefined|\$)[^\s'\"]{6,}", re.I), "high"),
    ("API Key", re.compile(r"(?:api[_\-]?key|api[_\-]?token|access[_\-]?token)\s*[=:]\s*['\"]?[a-zA-Z0-9_\-]{16,}", re.I), "high"),
    ("Secret Key", re.compile(r"(?:secret[_\-]?key|app[_\-]?secret|jwt[_\-]?secret)\s*[=:]\s*['\"]?[^\s'\"]{8,}", re.I), "high"),
    ("Slack Token", re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"), "high"),
    ("Generic Secret", re.compile(r"(?<![/*#])\b(?:secret|token)\s*[=:]\s*['\"]?[a-zA-Z0-9+/=_\-]{20,}", re.I), "medium"),
    ("Internal IP", re.compile(r"(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})"), "low"),
]
_SKIP_EXT = re.compile(r"\.(png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot|pdf|zip|gz|tar|lock|sum|map)$", re.I)
_INTERESTING = re.compile(r"\.(php|py|js|ts|rb|go|java|cs|cpp|c|sh|bash|env|yml|yaml|xml|json|ini|conf|config|toml|htaccess)$", re.I)
_SOURCE_SKIP = re.compile(r"(?:node_modules|vendor|\.min\.js|\.map|dist/|public/build/)", re.I)
_MAX_SOURCE_BYTES = 30_000


def add_arguments(parser) -> None:
    parser.add_argument("target", help="Base URL of the target, e.g. https://example.com")
    add_common_args(parser)


def run(args) -> int:
    target = args.target.strip().rstrip("/")
    extractor = _GitExtractor(target, args.debug)

    if not is_valid_url(target):
        _write(args.output, [], [], "Invalid URL.")
        return 1

    head = extractor.get("/.git/HEAD")
    if head is None or not head.decode("utf-8", "replace").strip().startswith("ref:"):
        _write(args.output, [], [], ".git/HEAD not accessible or not a valid git repo.")
        return 1

    extractor.dbg(f"Confirmed .git exposure at {target}")

    packs_raw = extractor.get("/.git/objects/info/packs")
    if packs_raw is not None:
        for pack_hash in re.findall(rb"pack-([a-f0-9]{40})\.pack", packs_raw):
            extractor.extract_from_pack_index(pack_hash.decode())

    ref = head.decode("utf-8", "replace").replace("ref: ", "").strip()
    sha = (extractor.get(f"/.git/{ref}") or b"").decode("utf-8", "replace").strip()
    if len(sha) == 40:
        extractor.walk_object(sha)

    packed_refs = extractor.get("/.git/packed-refs")
    if packed_refs is not None:
        for branch_sha in re.findall(rb"(?m)^([a-f0-9]{40})\s+refs/heads/", packed_refs):
            extractor.walk_object(branch_sha.decode())

    extractor.dbg(f"Extracted {len(extractor.files)} file(s). Scanning...")
    findings = extractor.scan_files()
    sources = extractor.collect_sources()
    extractor.dbg(f"Found {len(findings)} finding(s). Collected {len(sources)} source file(s).")

    _write(args.output, findings, sources, None)
    return 0


def _write(output_file, findings, sources, error) -> None:
    output_result(findings, output_file, error, extra={"sources": sources}, pretty=True)


class _GitExtractor:
    def __init__(self, base: str, debug: bool) -> None:
        self.base = base
        self.debug = debug
        self.visited: set[str] = set()
        self.files: dict[str, bytes] = {}
        self.finding_keys: set[str] = set()

    def dbg(self, message: str) -> None:
        if self.debug:
            import sys

            sys.stderr.write(message + "\n")

    # -- HTTP ------------------------------------------------------------
    def get(self, path: str) -> bytes | None:
        try:
            response = http.get(self.base + path, timeout=10)
            if http.is_successful(response):
                return response.content
        except Exception:  # noqa: BLE001
            pass
        return None

    # -- Object walking --------------------------------------------------
    def extract_from_pack_index(self, pack_hash: str) -> None:
        idx = self.get(f"/.git/objects/pack/pack-{pack_hash}.idx")
        if idx is None or len(idx) < 8:
            return
        magic = idx[0:4]
        version = struct.unpack(">I", idx[4:8])[0] if len(idx) >= 8 else 0

        if magic == b"\377tOc" and version == 2:
            count = struct.unpack(">I", idx[8 + 255 * 4 : 8 + 255 * 4 + 4])[0]
            sha_offset = 8 + 256 * 4
            for i in range(min(count, 10000)):
                sha = idx[sha_offset + i * 20 : sha_offset + i * 20 + 20].hex()
                self.walk_object(sha)
        else:
            count = struct.unpack(">I", idx[255 * 4 : 255 * 4 + 4])[0]
            offset = 256 * 4
            for _ in range(min(count, 10000)):
                if offset + 24 > len(idx):
                    break
                sha = idx[offset + 4 : offset + 24].hex()
                self.walk_object(sha)
                offset += 24

    def walk_object(self, sha: str, path_context: str = "") -> None:
        if not sha or len(sha) != 40 or sha in self.visited:
            return
        self.visited.add(sha)

        raw = self.get(f"/.git/objects/{sha[:2]}/{sha[2:]}")
        if raw is None:
            return
        try:
            data = zlib.decompress(raw)
        except zlib.error:
            return

        null_pos = data.find(b"\0")
        if null_pos == -1:
            return
        type_ = data[:null_pos].split(b" ", 1)[0]
        content = data[null_pos + 1 :]

        if type_ == b"commit":
            self._parse_commit(content)
        elif type_ == b"tree":
            self._parse_tree(content, path_context)
        elif type_ == b"blob":
            self._store_blob(path_context, content)

    def _parse_commit(self, content: bytes) -> None:
        if m := re.search(rb"(?m)^tree ([a-f0-9]{40})", content):
            self.walk_object(m.group(1).decode())
        if m := re.search(rb"(?m)^parent ([a-f0-9]{40})", content):
            self.walk_object(m.group(1).decode())

    def _parse_tree(self, content: bytes, prefix: str) -> None:
        offset, length = 0, len(content)
        while offset < length:
            space_pos = content.find(b" ", offset)
            if space_pos == -1 or space_pos >= length:
                break
            null_pos = content.find(b"\0", space_pos + 1)
            if null_pos == -1 or null_pos + 20 > length:
                break
            name = content[space_pos + 1 : null_pos].decode("utf-8", "replace")
            sha = content[null_pos + 1 : null_pos + 21].hex()
            full_path = f"{prefix}/{name}" if prefix else name
            self.walk_object(sha, full_path)
            offset = null_pos + 21

    def _store_blob(self, path: str, content: bytes) -> None:
        if not path:
            return
        self.files[path] = content
        self.dbg(f"  + {path} ({len(content)}b)")

    # -- Scanning / source collection ------------------------------------
    def scan_files(self) -> list[dict]:
        findings: list[dict] = []
        for path, content in self.files.items():
            if _SKIP_EXT.search(path):
                continue
            text = content[:200_000].decode("utf-8", "replace")
            lines = text.split("\n")
            for name, regex, severity in _SCAN_PATTERNS:
                for line_num, line in enumerate(lines):
                    if not regex.search(line):
                        continue
                    key = f"{name}|{path}|{line_num}"
                    if key in self.finding_keys:
                        continue
                    self.finding_keys.add(key)
                    snippet = line[:300].strip()
                    findings.append(
                        {
                            "title": f"[Git] {name} in {path}",
                            "url": f"{self.base}/.git/",
                            "severity": severity,
                            "info": "\n".join(
                                [
                                    f"File:    {path}",
                                    f"Line:    {line_num + 1}",
                                    f"Type:    {name}",
                                    f"Snippet: {snippet}",
                                    f"Source:  {self.base}/.git/",
                                ]
                            ),
                        }
                    )
        return findings

    def collect_sources(self) -> list[dict]:
        hit_paths = {
            path for path in self.files
            for key in self.finding_keys
            if f"|{path}|" in key
        }
        ordered = list(hit_paths) + [p for p in self.files if p not in hit_paths]

        sources: list[dict] = []
        for path in ordered:
            if path not in self.files:
                continue
            if _SOURCE_SKIP.search(path) or not _INTERESTING.search(path):
                continue
            content = self.files[path]
            if len(content) == 0:
                continue
            try:
                text = content.decode("utf-8")
            except UnicodeDecodeError:
                continue
            sources.append(
                {
                    "path": path,
                    "content": text[:_MAX_SOURCE_BYTES],
                    "truncated": len(content) > _MAX_SOURCE_BYTES,
                }
            )
        return sources
