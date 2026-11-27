"""Filesystem and unified-diff scanning with containment and resource guards."""

import errno
import os
import re
import stat
from dataclasses import replace
from typing import Iterable, Optional, Union

from .baseline import apply_baseline, read_baseline
from .errors import UsageError, SecretSweepError
from .finder import scan_text
from .ignore import is_always_ignored, is_ignored, load_ignore_files
from .output import sort_findings
from .types import Finding, ScanResult
from .util import safe_display

DEFAULT_MAX_FILE_BYTES = 1_048_576

BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".avif",
    ".pdf", ".zip", ".gz", ".tar", ".bz2", ".xz", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib", ".o", ".a", ".class", ".jar",
    ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp3", ".mp4",
    ".mov", ".avi", ".wav", ".flac", ".webm", ".sqlite", ".db",
    ".p12", ".pfx", ".keystore", ".pyc", ".node", ".wasm", ".bin",
}


def looks_binary(data: bytes) -> bool:
    """Classify bytes using content evidence, not file extension."""

    if not data:
        return False
    controls = 0
    for byte in data:
        if byte == 0:
            return True
        if byte < 9 or 13 < byte < 32 or byte == 127:
            controls += 1
    return controls / len(data) > 0.3


def is_binary_path(path: Union[str, os.PathLike]) -> bool:
    """Extension-only classification retained as a convenience API."""

    return os.path.splitext(os.fspath(path))[1].lower() in BINARY_EXTENSIONS


def _validate_max_file_bytes(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise UsageError("max_file_bytes must be a positive integer")
    return value


def _inside_root(root_real: str, identity: str) -> bool:
    try:
        return os.path.commonpath([root_real, identity]) == root_real
    except (ValueError, OSError):
        return False


def _normal_excludes(exclude: Optional[Iterable[str]]) -> list:
    values = []
    for item in exclude or []:
        text = str(item).replace("\\", "/").strip("/")
        while text.startswith("./"):
            text = text[2:]
        if text and text != ".":
            values.append(text)
    return values


def _coerce_baseline(baseline):
    if baseline is None:
        return None
    if isinstance(baseline, (str, os.PathLike)):
        return read_baseline(baseline)
    values = set()
    for item in baseline:
        if not isinstance(item, str) or not item:
            raise UsageError("invalid baseline entry")
        values.add(item)
    return values


def scan_path(
    root: Union[str, os.PathLike],
    *,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    exclude: Optional[Iterable[str]] = None,
    use_gitignore: bool = True,
    baseline=None,
    detectors=None,
    severity: Optional[str] = None,
    ignore_comments: bool = True,
    allow_placeholder: bool = False,
) -> ScanResult:
    """Safely scan a file or directory tree.

    Directory scans do not follow symlinks that resolve outside the real scan
    root. Symlink loops, special files, binary content, oversized files, and
    unreadable entries are reported in ``skipped`` without aborting the scan.
    """

    max_bytes = _validate_max_file_bytes(max_file_bytes)
    target = os.path.abspath(os.fspath(root))
    try:
        root_stat = os.stat(target)
    except OSError as exc:
        detail = exc.strerror or exc.__class__.__name__
        raise SecretSweepError("cannot read {}: {}".format(safe_display(target), detail)) from exc

    root_is_directory = stat.S_ISDIR(root_stat.st_mode)
    root_real = os.path.realpath(target)
    rules = []
    if root_is_directory:
        try:
            rules = load_ignore_files(target, include_gitignore=use_gitignore)
        except ValueError as exc:
            raise SecretSweepError(str(exc)) from exc

    excludes = _normal_excludes(exclude)
    findings = []
    skipped = []
    visited = set()
    scanned_files = 0

    def add_skip(rel_path: str, reason: str) -> None:
        skipped.append({"path": rel_path, "reason": reason})

    def is_excluded(rel_path: str) -> bool:
        return any(rel_path == item or rel_path.startswith(item + "/") for item in excludes)

    def visit(path: str, rel_path: str) -> None:
        nonlocal scanned_files
        if rel_path:
            if is_always_ignored(rel_path.split("/")[-1]):
                return
            if is_excluded(rel_path):
                return

        try:
            path_stat = os.lstat(path)
        except OSError:
            add_skip(rel_path, "unreadable-file")
            return

        is_directory = stat.S_ISDIR(path_stat.st_mode)
        if rel_path and is_ignored(rel_path, is_directory, rules):
            return

        effective_stat = path_stat
        if stat.S_ISLNK(path_stat.st_mode):
            try:
                effective_stat = os.stat(path)
            except OSError as exc:
                reason = "symlink-loop" if exc.errno == errno.ELOOP else "broken-symlink"
                add_skip(rel_path, reason)
                return
            identity = os.path.realpath(path)
            if root_is_directory and not _inside_root(root_real, identity):
                add_skip(rel_path, "path-escape")
                return
        else:
            identity = os.path.realpath(path)

        if identity in visited:
            add_skip(rel_path, "symlink-loop")
            return
        visited.add(identity)

        if stat.S_ISDIR(effective_stat.st_mode):
            try:
                names = sorted(os.listdir(path))
            except OSError:
                add_skip(rel_path, "unreadable-directory")
                return
            for name in names:
                child_rel = "{}/{}".format(rel_path, name) if rel_path else name
                visit(os.path.join(path, name), child_rel)
            return

        if not stat.S_ISREG(effective_stat.st_mode):
            add_skip(rel_path, "special-file")
            return

        if effective_stat.st_size > max_bytes:
            add_skip(rel_path, "too-large")
            return
        try:
            with open(path, "rb") as handle:
                data = handle.read(max_bytes + 1)
        except OSError:
            add_skip(rel_path, "unreadable-file")
            return
        if len(data) > max_bytes:
            add_skip(rel_path, "too-large")
            return
        if looks_binary(data):
            add_skip(rel_path, "binary")
            return

        text = data.decode("utf-8", "replace")
        filename = rel_path if rel_path else os.path.basename(path)
        result = scan_text(
            text,
            filename=filename,
            detectors=detectors,
            severity=severity,
            ignore_comments=ignore_comments,
            allow_placeholder=allow_placeholder,
        )
        scanned_files += 1
        findings.extend(result.findings)

    if root_is_directory:
        visit(target, "")
    else:
        visit(target, os.path.basename(target))

    ordered = sort_findings(findings)
    result = ScanResult(findings=ordered, skipped=skipped, root=target, scanned_files=scanned_files)
    baseline_keys = _coerce_baseline(baseline)
    if baseline_keys is not None:
        result = apply_baseline(result, baseline_keys)
    return result


def _unquote_git_path(value: str) -> str:
    if len(value) < 2 or value[0] != '"' or value[-1] != '"':
        return value
    output = bytearray()
    index = 1
    escapes = {
        "n": 10, "r": 13, "t": 9, "b": 8, "a": 7,
        "f": 12, "v": 11, "\\": 92, '"': 34,
    }
    while index < len(value) - 1:
        char = value[index]
        if char != "\\":
            output.extend(char.encode("utf-8", "surrogateescape"))
            index += 1
            continue
        if index + 1 >= len(value) - 1:
            output.append(92)
            index += 1
            continue
        index += 1
        marker = value[index]
        if marker in escapes:
            output.append(escapes[marker])
            index += 1
        elif marker in "01234567":
            digits = marker
            index += 1
            while len(digits) < 3 and index < len(value) - 1 and value[index] in "01234567":
                digits += value[index]
                index += 1
            output.append(int(digits, 8) & 0xFF)
        else:
            output.extend(marker.encode("utf-8", "surrogateescape"))
            index += 1
    return bytes(output).decode("utf-8", "surrogateescape")


def _parse_new_file_header(line: str):
    if not line.startswith("+++ "):
        return None
    raw = line[4:].split("\t")[0]
    if (raw.startswith("b/") or raw.startswith("a/")) and len(raw) > 2 and raw[2] == '"':
        path = raw[:2] + _unquote_git_path(raw[2:])
    else:
        path = _unquote_git_path(raw)
    if path == "/dev/null":
        return {"file": None}
    if path.startswith("b/") or path.startswith("a/"):
        return {"file": path[2:]}
    return {"file": path}


_HUNK_HEADER_RE = re.compile(r"^@@\s+-\d+(?:,\d+)?\s+\+(\d+)(?:,\d+)?\s+@@")


def scan_diff(
    diff_text: str,
    *,
    detectors=None,
    severity: Optional[str] = None,
    ignore_comments: bool = True,
    allow_placeholder: bool = False,
) -> ScanResult:
    """Scan only added lines in a unified git diff with exact new-file lines."""

    if not isinstance(diff_text, str):
        raise TypeError("scan_diff expects a string")

    findings = []
    lines = [line[:-1] if line.endswith("\r") else line for line in diff_text.split("\n")]
    current_file = "<stdin>"
    in_hunk = False
    new_line = 0
    block_lines = []
    block_map = []

    def flush_block() -> None:
        nonlocal block_lines, block_map
        if not block_lines:
            return
        text = "\n".join(block_lines)
        result = scan_text(
            text,
            filename=current_file or "<stdin>",
            detectors=detectors,
            severity=severity,
            ignore_comments=ignore_comments,
            allow_placeholder=allow_placeholder,
        )
        for finding in result.findings:
            local_line = max(1, min(finding.line, len(block_map)))
            mapped_line = block_map[local_line - 1] if block_map else new_line
            findings.append(replace(finding, file=current_file or "<stdin>", line=mapped_line))
        block_lines = []
        block_map = []

    index = 0
    while index < len(lines):
        line = lines[index]
        if line.startswith("diff --git "):
            flush_block()
            current_file = "<stdin>"
            in_hunk = False
            new_line = 0
            index += 1
            continue

        if not in_hunk:
            header = _parse_new_file_header(line)
            if header is not None:
                current_file = header["file"]
                index += 1
                continue
            hunk = _HUNK_HEADER_RE.match(line)
            if hunk:
                in_hunk = True
                new_line = int(hunk.group(1))
            index += 1
            continue

        next_hunk = _HUNK_HEADER_RE.match(line)
        if next_hunk:
            flush_block()
            new_line = int(next_hunk.group(1))
            index += 1
            continue
        if line.startswith("+"):
            if current_file is not None:
                block_lines.append(line[1:])
                block_map.append(new_line)
            new_line += 1
            index += 1
            continue
        if line.startswith("-"):
            index += 1
            continue
        if line.startswith(" ") or line == "":
            flush_block()
            new_line += 1
            index += 1
            continue
        if line.startswith("\\"):
            index += 1
            continue

        flush_block()
        in_hunk = False
        continue

    flush_block()
    return ScanResult(findings=sort_findings(findings), scanned_files=0)
