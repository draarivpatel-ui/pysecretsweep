"""Gitignore-style ignore rules with bounded memory and no regex backtracking."""

import os
import stat
from dataclasses import dataclass
from typing import Iterable, List, Optional

ALWAYS_IGNORED = {
    ".git", "node_modules", ".svn", ".hg", "vendor", "dist", "build",
    ".next", ".cache", ".venv", "__pycache__", ".idea", ".vscode",
}
MAX_PATTERN_CHARS = 1024
MAX_IGNORE_FILE_BYTES = 1024 * 1024
MAX_IGNORE_RULES = 10000


@dataclass(frozen=True)
class IgnoreRule:
    text: str
    parts: tuple
    negate: bool
    dir_only: bool
    anchored: bool


def _is_escaped(text: str, index: int) -> bool:
    count = 0
    cursor = index - 1
    while cursor >= 0 and text[cursor] == "\\":
        count += 1
        cursor -= 1
    return count % 2 == 1


def _strip_unescaped_trailing_spaces(line: str) -> str:
    end = len(line)
    while end > 0 and line[end - 1] == " " and not _is_escaped(line, end - 1):
        end -= 1
    return line[:end]


def parse_pattern(line: str) -> Optional[IgnoreRule]:
    text = _strip_unescaped_trailing_spaces(line)
    if not text or text.startswith("#"):
        return None

    literal_first = False
    if text.startswith("\\#") or text.startswith("\\!"):
        text = text[1:]
        literal_first = True

    negate = False
    if not literal_first and text.startswith("!"):
        negate = True
        text = text[1:]

    dir_only = False
    if text.endswith("/"):
        dir_only = True
        text = text[:-1]

    anchored = False
    if text.startswith("/"):
        anchored = True
        text = text[1:]
    if not text or len(text) > MAX_PATTERN_CHARS:
        return None

    leading_globstar = text.startswith("**/")
    has_slash = "/" in text
    root_anchored = anchored or (has_slash and not leading_globstar)
    return IgnoreRule(text=text, parts=tuple(text.split("/")), negate=negate, dir_only=dir_only, anchored=root_anchored)


def compile_ignore_rules(lines: Iterable[str]) -> List[IgnoreRule]:
    rules = []
    for line in lines:
        rule = parse_pattern(str(line).rstrip("\r\n"))
        if rule is not None:
            if len(rules) >= MAX_IGNORE_RULES:
                raise ValueError("ignore files exceed {} rules".format(MAX_IGNORE_RULES))
            rules.append(rule)
    return rules


def _read_ignore_file(path: str) -> Optional[str]:
    try:
        with open(path, "rb") as handle:
            data = handle.read(MAX_IGNORE_FILE_BYTES + 1)
    except OSError:
        return None
    if len(data) > MAX_IGNORE_FILE_BYTES:
        raise ValueError("ignore file {} exceeds {} bytes".format(os.path.basename(path), MAX_IGNORE_FILE_BYTES))
    return data.decode("utf-8", "replace")


def load_ignore_files(root: str, filenames=None, include_gitignore: bool = True) -> List[IgnoreRule]:
    """Load root-level ignore files with a strict 1 MiB cap.

    Nested ignore files are intentionally outside the documented model. A
    symlinked ignore file is followed only when its real target remains inside
    the real scan root.
    """

    if filenames is None:
        filenames = []
        if include_gitignore:
            filenames.append(".gitignore")
        filenames.append(".secretsweepignore")

    root_real = os.path.realpath(root)
    lines = []
    for filename in filenames:
        path = os.path.join(root, filename)
        try:
            info = os.lstat(path)
        except OSError:
            continue
        if stat.S_ISLNK(info.st_mode):
            identity = os.path.realpath(path)
            try:
                if os.path.commonpath([root_real, identity]) != root_real:
                    continue
            except (ValueError, OSError):
                continue
        elif not stat.S_ISREG(info.st_mode):
            continue
        try:
            if os.stat(path).st_size > MAX_IGNORE_FILE_BYTES:
                raise ValueError("ignore file {} exceeds {} bytes".format(filename, MAX_IGNORE_FILE_BYTES))
        except OSError:
            continue
        content = _read_ignore_file(path)
        if content is not None:
            lines.extend(content.splitlines())
    return compile_ignore_rules(lines)


def _class_token(pattern: str, start: int, char: str):
    index = start + 1
    negate = False
    if index < len(pattern) and pattern[index] in "!^":
        negate = True
        index += 1

    first = True
    matched = False
    closed = False
    while index < len(pattern):
        if pattern[index] == "]" and not first:
            closed = True
            index += 1
            break

        if pattern[index] == "\\" and index + 1 < len(pattern):
            low = pattern[index + 1]
            index += 2
        else:
            low = pattern[index]
            index += 1

        if index < len(pattern) and pattern[index] == "-" and index + 1 < len(pattern) and pattern[index + 1] != "]":
            if pattern[index + 1] == "\\" and index + 2 < len(pattern):
                high = pattern[index + 2]
                index += 3
            else:
                high = pattern[index + 1]
                index += 2
            if low <= char <= high:
                matched = True
        elif char == low:
            matched = True
        first = False

    if not closed:
        return char == "[", start + 1
    return (not matched if negate else matched), index


def _token_at(pattern: str, index: int):
    if index >= len(pattern):
        return None, index + 1
    char = pattern[index]
    if char == "\\" and index + 1 < len(pattern):
        return pattern[index + 1], index + 2
    return char, index + 1


def match_segment(pattern: str, text: str) -> bool:
    """Match one path segment using glob semantics in linear time."""

    if len(pattern) > MAX_PATTERN_CHARS or len(text) > 4096:
        return False
    pattern_index = 0
    text_index = 0
    star_index = -1
    star_text_index = 0

    while text_index < len(text):
        if pattern_index < len(pattern) and pattern[pattern_index] == "*":
            while pattern_index < len(pattern) and pattern[pattern_index] == "*":
                pattern_index += 1
            star_index = pattern_index - 1
            star_text_index = text_index
            continue

        matched = False
        next_pattern = pattern_index + 1
        if pattern_index < len(pattern):
            char = pattern[pattern_index]
            if char == "?":
                matched = True
                next_pattern = pattern_index + 1
            elif char == "[":
                matched, next_pattern = _class_token(pattern, pattern_index, text[text_index])
            else:
                literal, next_pattern = _token_at(pattern, pattern_index)
                matched = literal == text[text_index]

        if matched:
            pattern_index = next_pattern
            text_index += 1
            continue

        if star_index != -1:
            star_text_index += 1
            text_index = star_text_index
            pattern_index = star_index + 1
            continue
        return False

    while pattern_index < len(pattern) and pattern[pattern_index] == "*":
        pattern_index += 1
    return pattern_index == len(pattern)


def match_parts(pattern_parts, path_parts) -> bool:
    """Match path components, with globstar spanning zero or more components."""

    pattern_length = len(pattern_parts)
    path_length = len(path_parts)
    dp = [[False] * (path_length + 1) for _ in range(pattern_length + 1)]
    dp[pattern_length][path_length] = True

    for pattern_index in range(pattern_length - 1, -1, -1):
        for path_index in range(path_length, -1, -1):
            part = pattern_parts[pattern_index]
            if part == "**":
                if pattern_index == pattern_length - 1:
                    # A trailing /** matches contents, not the parent itself.
                    dp[pattern_index][path_index] = path_index < path_length
                else:
                    dp[pattern_index][path_index] = dp[pattern_index + 1][path_index]
                    if path_index < path_length:
                        dp[pattern_index][path_index] = dp[pattern_index][path_index] or dp[pattern_index][path_index + 1]
            elif path_index < path_length:
                dp[pattern_index][path_index] = (
                    match_segment(part, path_parts[path_index])
                    and dp[pattern_index + 1][path_index + 1]
                )
    return dp[0][0]


def matches_rule(rel_path: str, is_directory: bool, rule: IgnoreRule) -> bool:
    parts = [part for part in rel_path.replace("\\", "/").split("/") if part]
    if not parts:
        return False

    if not rule.anchored and len(rule.parts) == 1:
        for index, part in enumerate(parts):
            component_is_directory = index < len(parts) - 1 or is_directory
            if rule.dir_only and not component_is_directory:
                continue
            if match_segment(rule.parts[0], part):
                return True
        return False

    for end in range(1, len(parts) + 1):
        candidate_is_directory = end < len(parts) or is_directory
        if rule.dir_only and not candidate_is_directory:
            continue
        if match_parts(rule.parts, parts[:end]):
            return True
    return False


def is_ignored(rel_path: str, is_directory: bool, rules: Iterable[IgnoreRule]) -> bool:
    ignored = False
    for rule in rules:
        if matches_rule(rel_path, is_directory, rule):
            ignored = not rule.negate
    return ignored


def is_always_ignored(name: str) -> bool:
    return name in ALWAYS_IGNORED
