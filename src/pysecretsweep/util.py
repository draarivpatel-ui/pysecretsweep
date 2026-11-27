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

    Values shorter than 32 characters are fully masked. Longer values expose
    four edge characters at each side and never more than one quarter of the
    value in total, leaving enough of the value concealed that the preview
    and fingerprint cannot be combined for a practical offline reconstruction.
    """

    text = str(value)
    if len(text) < 32:
        return "*" * len(text)
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


def _quantifier_details(source: str, index: int):
    if index >= len(source):
        return None
    char = source[index]
    if char in "*+?":
        end = index + 1
        if end < len(source) and source[end] in "?+":
            end += 1
        if char == "*":
            minimum, maximum = 0, None
        elif char == "+":
            minimum, maximum = 1, None
        else:
            minimum, maximum = 0, 1
        return end, minimum, maximum
    if char != "{":
        return None
    match = re.match(r"\{(\d+)(?:,(\d*))?\}", source[index:])
    if not match:
        return None
    minimum = int(match.group(1))
    if "," not in match.group(0):
        maximum = minimum
    elif match.group(2):
        maximum = int(match.group(2))
    else:
        maximum = None
    end = index + match.end()
    if end < len(source) and source[end] in "?+":
        end += 1
    return end, minimum, maximum


def _quantifier_end(source: str, index: int):
    details = _quantifier_details(source, index)
    return details[0] if details else None


def _skip_class(source: str, index: int) -> int:
    index += 1
    if index < len(source) and source[index] == "^":
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


def _positive_spec(literals=None, ranges=None, categories=None, complement_categories=None):
    return {
        "kind": "positive",
        "literals": set(literals or ()),
        "ranges": list(ranges or ()),
        "categories": set(categories or ()),
        "complement_categories": set(complement_categories or ()),
        "negated": False,
    }


def _negative_spec(base):
    spec = dict(base)
    spec["literals"] = set(base["literals"])
    spec["ranges"] = list(base["ranges"])
    spec["categories"] = set(base["categories"])
    spec["complement_categories"] = set(base["complement_categories"])
    spec["kind"] = "negative"
    spec["negated"] = True
    return spec


def _unknown_spec():
    return {"kind": "unknown"}


def _category_allows(category: str, char: str) -> bool:
    if category == "d":
        return unicodedata.category(char) == "Nd"
    if category == "s":
        return char.isspace()
    if category == "w":
        return char == "_" or char.isalnum()
    return False


def _base_allows(spec, char: str) -> bool:
    if char in spec.get("literals", ()):
        return True
    for low, high in spec.get("ranges", ()):
        if low <= char <= high:
            return True
    for category in spec.get("categories", ()):
        if _category_allows(category, char):
            return True
    for category in spec.get("complement_categories", ()):
        if not _category_allows(category, char):
            return True
    return False


def _spec_allows(spec, char: str) -> bool:
    if spec.get("kind") == "unknown":
        return True
    allowed = _base_allows(spec, char)
    return not allowed if spec.get("negated") else allowed


def _finite_chars(spec):
    if spec.get("kind") != "positive" or spec.get("categories") or spec.get("complement_categories"):
        return None
    chars = set(spec.get("literals", ()))
    total = len(chars)
    for low, high in spec.get("ranges", ()):
        width = ord(high) - ord(low) + 1
        if width > 1024 or total + width > 4096:
            return None
        chars.update(chr(value) for value in range(ord(low), ord(high) + 1))
        total = len(chars)
    return chars


def _positive_overlap(first, second) -> bool:
    first_finite = _finite_chars(first)
    second_finite = _finite_chars(second)
    if first_finite is not None and second_finite is not None:
        return bool(first_finite.intersection(second_finite))
    if first_finite is not None:
        return any(_base_allows(second, char) for char in first_finite)
    if second_finite is not None:
        return any(_base_allows(first, char) for char in second_finite)

    first_ranges = first.get("ranges", ())
    second_ranges = second.get("ranges", ())
    for first_low, first_high in first_ranges:
        for second_low, second_high in second_ranges:
            if first_low <= second_high and second_low <= first_high:
                return True

    candidates = {"a", "Z", "0", "_", " ", "\t", "\n", "\r", "\v", "\f", "\u00e9", "\u0660", "\u00a0"}
    for low, high in list(first_ranges) + list(second_ranges):
        candidates.add(low)
        candidates.add(high)
        middle = ord(low) + ((ord(high) - ord(low)) // 2)
        candidates.add(chr(middle))
    for char in candidates:
        if _base_allows(first, char) and _base_allows(second, char):
            return True
    return True


def _positive_subset_of_base(positive, negative) -> bool:
    if positive.get("complement_categories"):
        return False
    for char in positive.get("literals", ()):
        if not _base_allows(negative, char):
            return False
    negative_categories = set(negative.get("categories", ()))
    for category in positive.get("categories", ()):
        if category in negative_categories:
            continue
        if category == "d" and "w" in negative_categories:
            continue
        return False
    for low, high in positive.get("ranges", ()):
        width = ord(high) - ord(low) + 1
        if width > 1024:
            return False
        for value in range(ord(low), ord(high) + 1):
            if not _base_allows(negative, chr(value)):
                return False
    return True


def charsets_overlap(first, second) -> bool:
    """Conservatively assess whether two regex character atoms intersect."""

    if first.get("kind") == "unknown" or second.get("kind") == "unknown":
        return True
    first_negative = first.get("negated")
    second_negative = second.get("negated")
    if not first_negative and not second_negative:
        return _positive_overlap(first, second)
    if first_negative and second_negative:
        return True

    positive = second if first_negative else first
    negative = first if first_negative else second
    return not _positive_subset_of_base(positive, negative)


def _parse_escape(source: str, index: int, in_class: bool = False):
    if index + 1 >= len(source):
        return _positive_spec(literals={"\\"}), index + 1, False
    char = source[index + 1]
    end = index + 2
    escaped_literals = {
        "a": "\a", "b": "\b", "f": "\f", "n": "\n", "r": "\r",
        "t": "\t", "v": "\v", "\\": "\\",
    }
    if char in "dsw":
        return _positive_spec(categories={char}), end, False
    if char in "DSW":
        return _positive_spec(complement_categories={char.lower()}), end, False
    if not in_class and char in "AZzbBG":
        return None, end, True
    if char in escaped_literals:
        return _positive_spec(literals={escaped_literals[char]}), end, False
    if char == "x" and index + 3 < len(source):
        digits = source[index + 2:index + 4]
        if re.match(r"^[0-9a-fA-F]{2}$", digits):
            return _positive_spec(literals={chr(int(digits, 16))}), index + 4, False
    if char == "u" and index + 5 < len(source):
        digits = source[index + 2:index + 6]
        if re.match(r"^[0-9a-fA-F]{4}$", digits):
            return _positive_spec(literals={chr(int(digits, 16))}), index + 6, False
    return _positive_spec(literals={char}), end, False


def _parse_class(source: str, index: int):
    end = index + 1
    negated = False
    if end < len(source) and source[end] == "^":
        negated = True
        end += 1

    literals = set()
    ranges = []
    categories = set()
    complement_categories = set()
    first = True
    closed = False
    while end < len(source):
        if source[end] == "]" and not first:
            closed = True
            end += 1
            break

        if source[end] == "\\":
            atom, atom_end, _zero_width = _parse_escape(source, end, in_class=True)
            end = atom_end
            if atom is None:
                first = False
                continue
            low_literal = next(iter(atom["literals"]), None) if len(atom.get("literals", ())) == 1 else None
            low_categories = set(atom.get("categories", ()))
            low_complements = set(atom.get("complement_categories", ()))
            low_ranges = list(atom.get("ranges", ()))
        else:
            low_literal = source[end]
            low_categories = set()
            low_complements = set()
            low_ranges = []
            end += 1

        if (
            low_literal is not None
            and end < len(source)
            and source[end] == "-"
            and end + 1 < len(source)
            and source[end + 1] != "]"
        ):
            end += 1
            if source[end] == "\\":
                high_atom, end, _zero_width = _parse_escape(source, end, in_class=True)
                high_literal = next(iter(high_atom["literals"]), None) if high_atom and len(high_atom.get("literals", ())) == 1 else None
            else:
                high_literal = source[end]
                end += 1
            if high_literal is not None and ord(low_literal) <= ord(high_literal):
                ranges.append((low_literal, high_literal))
            elif high_literal is not None:
                ranges.append((high_literal, low_literal))
            else:
                literals.add(low_literal)
                literals.add("-")
        else:
            if low_literal is not None:
                literals.add(low_literal)
            categories.update(low_categories)
            complement_categories.update(low_complements)
            ranges.extend(low_ranges)
        first = False

    if not closed:
        return _positive_spec(literals={"["}), index + 1
    base = _positive_spec(literals, ranges, categories, complement_categories)
    return (_negative_spec(base) if negated else base), end


def _new_atom(spec):
    return {
        "charset": spec if spec is not None else _unknown_spec(),
        "quantified": False,
        "variable": False,
        "minimum": 0,
        "maximum": 0,
    }


def _new_group_frame(kind):
    return {
        "kind": kind,
        "has_repeat": False,
        "has_alternation": False,
        "previous": None,
        "current": None,
    }


def _push_atom(frame, atom) -> None:
    frame["previous"] = frame["current"]
    frame["current"] = atom


def _reset_adjacency(frame) -> None:
    frame["previous"] = None
    frame["current"] = None


def _repeat_is_variable(minimum, maximum) -> bool:
    return maximum is None or minimum != maximum


def _repeat_is_limited_optional(minimum, maximum) -> bool:
    return minimum in (0, 1) and maximum == 1


def analyze_pattern(pattern: Union[str, Pattern[str]]) -> Dict[str, object]:
    """Statically assess a detector regex for common superlinear shapes.

    This is a conservative defense in depth lint, not a proof about every
    possible regex. It rejects backreferences, lookbehind, stacked quantifiers,
    oversized repeats, repeated groups that themselves contain repeats or
    alternation, and adjacent variable repeats with overlapping character sets.
    """

    source = _pattern_source(pattern)
    reasons = set()
    if len(source) > 4096:
        reasons.add("pattern too long")
    if re.search(r"\\[1-9]", source) or "(?P=" in source or "\\k<" in source or "\\k'" in source:
        reasons.add("backreference")

    groups = []
    root = _new_group_frame("root")
    stack = [root]
    index = 0
    while index < len(source):
        char = source[index]
        frame = stack[-1]
        if char == "\\":
            spec, end, zero_width = _parse_escape(source, index)
            if zero_width:
                _reset_adjacency(frame)
            else:
                _push_atom(frame, _new_atom(spec))
            index = end
            continue
        if char == "[":
            spec, end = _parse_class(source, index)
            _push_atom(frame, _new_atom(spec))
            index = end
            continue
        if char == "(":
            kind = "group"
            push_group = True
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
                if cursor < len(source) and source[cursor] == ")":
                    push_group = False
                    index = cursor + 1
                elif cursor < len(source) and source[cursor] == ":":
                    index = cursor + 1
                else:
                    index = max(cursor, index + 2)
            else:
                index += 1
            if push_group:
                child = _new_group_frame(kind)
                groups.append(child)
                stack.append(child)
            continue
        if char == ")":
            if len(stack) > 1:
                info = stack.pop()
                groups.remove(info)
                following = _quantifier_details(source, index + 1)
                if following is not None:
                    _end, minimum, maximum = following
                    expandable = (
                        not _repeat_is_limited_optional(minimum, maximum)
                        and (maximum is None or maximum != 1 or minimum != 1)
                    )
                    if expandable and info.get("has_repeat"):
                        reasons.add("repeated group containing a repeat")
                    if expandable and info.get("has_alternation"):
                        reasons.add("repeated group containing alternation")
                _push_atom(stack[-1], _new_atom(_unknown_spec()))
            else:
                _push_atom(frame, _new_atom(_unknown_spec()))
            index += 1
            continue
        if char == "|":
            for group in stack[1:]:
                group["has_alternation"] = True
            _reset_adjacency(frame)
            index += 1
            continue

        quantifier = _quantifier_details(source, index) if char in "*+?{" else None
        if quantifier is not None:
            end, minimum, maximum = quantifier
            atom = frame["current"]
            if atom is not None:
                if atom["quantified"]:
                    reasons.add("stacked quantifiers")
                if minimum > 1024 or (maximum is not None and maximum > 1024):
                    reasons.add("large repeat")
                variable = _repeat_is_variable(minimum, maximum)
                previous = frame["previous"]
                if (
                    previous is not None
                    and previous["quantified"]
                    and previous["variable"]
                    and variable
                    and not _repeat_is_limited_optional(previous["minimum"], previous["maximum"])
                    and not _repeat_is_limited_optional(minimum, maximum)
                    and charsets_overlap(previous["charset"], atom["charset"])
                ):
                    reasons.add("ambiguous adjacent repeats")
                atom["quantified"] = True
                atom["variable"] = variable
                atom["minimum"] = minimum
                atom["maximum"] = maximum
                for group in stack[1:]:
                    group["has_repeat"] = True
            index = end
            continue

        if char in "^$":
            _reset_adjacency(frame)
            index += 1
            continue
        if char == ".":
            _push_atom(frame, _new_atom(_unknown_spec()))
        else:
            _push_atom(frame, _new_atom(_positive_spec(literals={char})))
        index += 1

    return {"safe": not reasons, "reasons": sorted(reasons)}

def ensure_linear(pattern: Union[str, Pattern[str]], detector_id: str) -> Union[str, Pattern[str]]:
    """Return ``pattern`` or raise when the static lint rejects it."""

    report = analyze_pattern(pattern)
    if not report["safe"]:
        reasons = ", ".join(str(reason) for reason in report["reasons"])
        raise ValueError("detector {} is not linear-time safe: {}".format(detector_id, reasons))
    return pattern
