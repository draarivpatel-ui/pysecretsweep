"""Utility functions for redaction, entropy, placeholders, and pattern safety."""

import hashlib
import math
import re
import unicodedata
from typing import Dict, Pattern, Union

VERSION = "1.0.0"
SEVERITIES = ("low", "medium", "high", "critical")
SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def fingerprint(value: str) -> str:
    """Return the deterministic SHA-256 fingerprint of a value."""

    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def mask_value(value: str) -> str:
    """Return a short masked preview that exposes at most a small fraction.

    Values up to 16 characters are fully masked. Medium values expose two
    edge characters at each side. Long values expose four edge characters at
    each side and never more than one quarter of the value in total.
    """

    text = str(value)
    if len(text) <= 16:
        return "*" * len(text)
    if len(text) < 32:
        return text[:2] + "*" * min(12, len(text) - 4) + text[-2:]
    return text[:4] + "*" * min(12, len(text) - 8) + text[-4:]


def shannon_entropy(value: str) -> float:
    """Return Shannon entropy in bits per character."""

    text = str(value)
    if not text:
        return 0.0
    counts = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    entropy = 0.0
    for count in counts.values():
        probability = count / len(text)
        entropy -= probability * math.log2(probability)
    return entropy


_PLACEHOLDER_WORDS = {
    "example", "sample", "placeholder", "changeme", "change_me", "change-me",
    "yourapikey", "yourapitoken", "yourkey", "yourtoken", "yoursecret", "token",
    "apikey", "apitoken", "accesskey", "secretkey", "dummy", "fake", "test",
    "testing", "redacted", "replace", "replaceme", "insert", "here", "none",
    "null", "undefined", "todo", "tbd", "xxxx", "yyyy", "zzzz", "abcdef",
    "abc123", "password", "passwd", "string", "value", "literal", "notreal",
    "notarealkey", "sanitized", "masked", "hidden", "foo", "bar", "baz", "qux",
}

_ASCII_SEQUENCE = "abcdefghijklmnopqrstuvwxyz"
_DIGIT_SEQUENCE = "0123456789"


def _normalized(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def _is_simple_sequence(compact: str) -> bool:
    if not compact:
        return True
    for sequence in (_ASCII_SEQUENCE, _ASCII_SEQUENCE[::-1], _DIGIT_SEQUENCE, _DIGIT_SEQUENCE[::-1]):
        if len(compact) >= 4 and compact in sequence:
            return True
        if len(compact) >= len(sequence) * 2 and len(compact) % len(sequence) == 0:
            if compact == sequence * (len(compact) // len(sequence)):
                return True
    return False


def is_placeholder(value: str) -> bool:
    """Return true for documentation placeholders and other non-secret values."""

    text = str(value)
    if not text:
        return True
    if len(text) > 256:
        return False

    compact = _normalized(text)
    if not compact:
        return True
    if len(set(text)) == 1:
        return True
    if _is_simple_sequence(compact):
        return True
    if compact == "0" * len(compact):
        return True
    if "..." in text or "${" in text or "$(" in text:
        return True
    if len(text) >= 2 and ((text[0] == "<" and text[-1] == ">") or (text[0] == "{" and text[-1] == "}")):
        return True

    for word in _PLACEHOLDER_WORDS:
        normalized_word = re.sub(r"[^a-z0-9]+", "", word)
        if compact == normalized_word:
            return True
        if compact.startswith(normalized_word) and len(compact) - len(normalized_word) <= 4:
            return True
        if compact.startswith(normalized_word + "key") or compact.endswith("key" + normalized_word):
            return True

    words = [part for part in re.split(r"[^a-z0-9]+", text.lower()) if part]
    if len(words) >= 3 and all(word in _PLACEHOLDER_WORDS for word in words):
        return True
    return False


def safe_display(value: object) -> str:
    """Render terminal control characters as visible escape sequences."""

    output = []
    for char in str(value):
        code = ord(char)
        if char == "\n":
            output.append("\\n")
        elif char == "\r":
            output.append("\\r")
        elif char == "\t":
            output.append("\\t")
        elif code < 32 or 127 <= code < 160 or code in (0x2028, 0x2029):
            output.append("\\x{:02x}".format(code) if code <= 0xFF else "\\u{:04x}".format(code))
        elif unicodedata.category(char) in ("Cf", "Cs"):
            output.append("\\u{:04x}".format(code))
        else:
            output.append(char)
    return "".join(output)


def _pattern_source(pattern: Union[str, Pattern[str]]) -> str:
    return pattern.pattern if hasattr(pattern, "pattern") else str(pattern)


def _quantifier_end(source: str, index: int):
    if index >= len(source):
        return None
    char = source[index]
    if char in "*+?":
        end = index + 1
        if end < len(source) and source[end] in "?+":
            end += 1
        return end
    if char != "{":
        return None
    match = re.match(r"\{\d+(?:,\d*)?\}", source[index:])
    if not match:
        return None
    end = index + match.end()
    if end < len(source) and source[end] in "?+":
        end += 1
    return end


def _skip_class(source: str, index: int) -> int:
    index += 1
    if index < len(source) and source[index] in "!^":
        index += 1
    if index < len(source) and source[index] == "]":
        index += 1
    while index < len(source):
        if source[index] == "\\":
            index += 2
            continue
        if source[index] == "]":
            return index + 1
        index += 1
    return index


def analyze_pattern(pattern: Union[str, Pattern[str]]) -> Dict[str, object]:
    """Statically assess a detector regex for common superlinear shapes.

    This is a conservative defense in depth lint, not a proof about every
    possible regex. It rejects backreferences, lookbehind, stacked quantifiers,
    and repeated groups that themselves contain repeats.
    """

    source = _pattern_source(pattern)
    reasons = set()
    if len(source) > 4096:
        reasons.add("pattern too long")
    if re.search(r"\\[1-9]", source) or "(?P=" in source or "\\k<" in source or "\\k'" in source:
        reasons.add("backreference")

    groups = []
    last_was_quantifier = False
    index = 0
    while index < len(source):
        char = source[index]
        if char == "\\":
            index += 2
            last_was_quantifier = False
            continue
        if char == "[":
            index = _skip_class(source, index)
            last_was_quantifier = False
            continue
        if char == "(":
            kind = "group"
            if source.startswith("(?<=", index) or source.startswith("(?<!", index):
                kind = "lookbehind"
                reasons.add("lookbehind")
                index += 4
            elif source.startswith("(?>", index):
                kind = "atomic"
                index += 3
            elif source.startswith("(?:", index) or source.startswith("(?=", index) or source.startswith("(?!", index):
                index += 3
            elif source.startswith("(?P<", index):
                close = source.find(">", index + 4)
                index = close + 1 if close != -1 else index + 4
            elif source.startswith("(?", index):
                cursor = index + 2
                while cursor < len(source) and source[cursor] in "aiLmsux-":
                    cursor += 1
                if cursor < len(source) and source[cursor] in ":)":
                    cursor += 1
                index = max(cursor, index + 2)
            else:
                index += 1
            groups.append({"kind": kind, "has_repeat": False})
            last_was_quantifier = False
            continue
        if char == ")":
            info = groups.pop() if groups else {"kind": "group", "has_repeat": False}
            following = _quantifier_end(source, index + 1)
            if following is not None and info.get("has_repeat"):
                reasons.add("repeated group containing a repeat")
            index += 1
            last_was_quantifier = False
            continue

        quant_end = _quantifier_end(source, index)
        if quant_end is not None:
            if last_was_quantifier:
                reasons.add("stacked quantifiers")
            for group in groups:
                group["has_repeat"] = True
            last_was_quantifier = True
            index = quant_end
            continue

        last_was_quantifier = False
        index += 1

    return {"safe": not reasons, "reasons": sorted(reasons)}


def ensure_linear(pattern: Union[str, Pattern[str]], detector_id: str) -> Union[str, Pattern[str]]:
    """Return ``pattern`` or raise when the static lint rejects it."""

    report = analyze_pattern(pattern)
    if not report["safe"]:
        reasons = ", ".join(str(reason) for reason in report["reasons"])
        raise ValueError("detector {} is not linear-time safe: {}".format(detector_id, reasons))
    return pattern
