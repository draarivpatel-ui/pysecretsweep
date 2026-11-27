"""Detector registry and built-in high-precision detectors."""

import re
from dataclasses import dataclass
from typing import Callable, Iterable, List, Optional, Pattern, Union

from .errors import UsageError
from .util import SEVERITIES, ensure_linear, shannon_entropy

Hit = dict
CheckFunction = Callable[[str], Iterable[Hit]]
ValueFunction = Callable[[re.Match], Optional[str]]


@dataclass(frozen=True)
class Detector:
    id: str
    provider: str
    name: str
    severity: str
    check: CheckFunction
    pattern: Optional[Pattern[str]] = None


_REGISTRY: List[Detector] = []
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")


def _compile_pattern(pattern: Union[str, Pattern[str]], flags: int = 0) -> Pattern[str]:
    if hasattr(pattern, "pattern") and hasattr(pattern, "finditer"):
        if flags:
            raise UsageError("flags cannot be added to an already compiled pattern")
        return pattern  # type: ignore[return-value]
    try:
        return re.compile(str(pattern), flags)
    except re.error as exc:
        raise UsageError("invalid detector pattern") from exc


def register_detector(descriptor=None, **kwargs) -> Detector:
    """Register a custom detector after validating its id, severity, and pattern.

    The detector check callable receives the full text and returns mappings
    with ``value`` and ``index`` entries. Raw values are used only in memory
    to calculate redacted previews and fingerprints.
    """

    if isinstance(descriptor, dict):
        merged = dict(descriptor)
        merged.update(kwargs)
        kwargs = merged
    elif descriptor is not None:
        raise TypeError("register_detector expects keyword arguments or a descriptor mapping")

    detector_id = str(kwargs.get("id") or "")
    if not _ID_RE.match(detector_id):
        raise UsageError("invalid detector id: {}".format(detector_id))
    if any(entry.id == detector_id for entry in _REGISTRY):
        raise UsageError("duplicate detector id: {}".format(detector_id))

    severity = kwargs.get("severity") or "high"
    if not isinstance(severity, str) or severity not in SEVERITIES:
        raise UsageError("detector {} has invalid severity".format(detector_id))

    check = kwargs.get("check")
    if not callable(check):
        raise UsageError("detector {} has no check function".format(detector_id))

    pattern = kwargs.get("pattern")
    compiled = None
    if pattern is not None:
        ensure_linear(pattern, detector_id)
        compiled = _compile_pattern(pattern, int(kwargs.get("flags") or 0))

    entry = Detector(
        id=detector_id,
        provider=str(kwargs.get("provider") or detector_id),
        name=str(kwargs.get("name") or kwargs.get("provider") or detector_id),
        severity=severity,
        check=check,
        pattern=compiled,
    )
    _REGISTRY.append(entry)
    return entry


def unregister_detector(detector_id: str) -> bool:
    """Remove a detector. This is primarily useful for isolated tests."""

    for index, entry in enumerate(_REGISTRY):
        if entry.id == detector_id:
            del _REGISTRY[index]
            return True
    return False


def list_detectors() -> List[dict]:
    """Return detector metadata without exposing check callables."""

    return [
        {
            "id": entry.id,
            "provider": entry.provider,
            "name": entry.name,
            "severity": entry.severity,
        }
        for entry in _REGISTRY
    ]


def get_detector(detector_id: str) -> Optional[Detector]:
    for entry in _REGISTRY:
        if entry.id == detector_id:
            return entry
    return None


def create_pattern_detector(descriptor=None, **kwargs) -> Detector:
    """Create a regex detector whose hits come from a match or capture group."""

    if isinstance(descriptor, dict):
        merged = dict(descriptor)
        merged.update(kwargs)
        kwargs = merged
    elif descriptor is not None:
        raise TypeError("create_pattern_detector expects keyword arguments or a descriptor mapping")

    detector_id = str(kwargs.get("id") or "")
    pattern = kwargs.get("pattern")
    if pattern is None:
        raise UsageError("detector {} has no pattern".format(detector_id))
    ensure_linear(pattern, detector_id)
    flags = int(kwargs.get("flags") or 0)
    compiled = _compile_pattern(pattern, flags)
    value_function = kwargs.get("value")
    value_group = kwargs.get("value_group", 0)
    if value_function is not None and not callable(value_function):
        raise UsageError("detector {} value must be callable".format(detector_id))
    if value_function is None:
        if isinstance(value_group, int):
            if value_group < 0 or value_group > compiled.groups:
                raise UsageError("detector {} value_group is out of range".format(detector_id))
        elif value_group not in compiled.groupindex:
            raise UsageError("detector {} value_group is unknown".format(detector_id))

    def check(text: str) -> Iterable[Hit]:
        hits = []
        for match in compiled.finditer(text):
            value = None
            index = -1
            if value_function is not None:
                value = value_function(match)
                if isinstance(value, str) and value:
                    offset = match.group(0).find(value)
                    index = match.start() + offset if offset >= 0 else match.start()
            else:
                try:
                    value = match.group(value_group)
                    index = match.start(value_group)
                except (IndexError, re.error):
                    value = None
            if isinstance(value, str) and value and index >= 0:
                hits.append({"value": value, "index": index})
        return hits

    return register_detector(
        id=detector_id,
        provider=kwargs.get("provider"),
        name=kwargs.get("name"),
        severity=kwargs.get("severity") or "high",
        pattern=compiled,
        check=check,
    )


# Built-in detectors. Patterns use bounded or simple character classes and are
# checked by the static lint during registration.

create_pattern_detector(
    id="aws-access-key-id", provider="AWS", name="AWS access key ID", severity="high",
    pattern=r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
)

create_pattern_detector(
    id="aws-secret-access-key", provider="AWS", name="AWS secret access key", severity="critical",
    pattern=r"\baws_secret_access_key\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})[\"']?",
    flags=re.IGNORECASE, value_group=1,
)

create_pattern_detector(
    id="github-pat", provider="GitHub", name="GitHub classic personal access token", severity="high",
    pattern=r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b",
)

create_pattern_detector(
    id="github-fine-grained-pat", provider="GitHub", name="GitHub fine-grained personal access token", severity="high",
    pattern=r"\bgithub_pat_[A-Za-z0-9_]{40,255}\b",
)

create_pattern_detector(
    id="github-oauth-token", provider="GitHub", name="GitHub OAuth token", severity="high",
    pattern=r"\bgho_[A-Za-z0-9]{36}\b",
)

create_pattern_detector(
    id="stripe-secret-key", provider="Stripe", name="Stripe secret key", severity="critical",
    pattern=r"\bsk_(?:live|test)_[A-Za-z0-9]{16,40}\b",
)

create_pattern_detector(
    id="stripe-restricted-key", provider="Stripe", name="Stripe restricted key", severity="high",
    pattern=r"\brk_(?:live|test)_[A-Za-z0-9]{16,40}\b",
)

create_pattern_detector(
    id="stripe-publishable-key", provider="Stripe", name="Stripe publishable key", severity="medium",
    pattern=r"\bpk_(?:live|test)_[A-Za-z0-9]{16,40}\b",
)

create_pattern_detector(
    id="slack-webhook", provider="Slack", name="Slack incoming webhook URL", severity="high",
    pattern=r"https://hooks\.slack\.com/services/[A-Za-z0-9/_-]{20,}",
)

create_pattern_detector(
    id="slack-token", provider="Slack", name="Slack bot or user token", severity="high",
    pattern=r"\bxox[baprs]-[A-Za-z0-9-]{10,48}\b",
)

create_pattern_detector(
    id="google-api-key", provider="Google", name="Google API key", severity="high",
    pattern=r"\bAIza[A-Za-z0-9_-]{35}\b",
)

create_pattern_detector(
    id="google-oauth-client-secret", provider="Google", name="Google OAuth client secret", severity="high",
    pattern=r"\bGOCSPX-[A-Za-z0-9_-]{20,}\b",
)

create_pattern_detector(
    id="google-refresh-token", provider="Google", name="Google OAuth refresh token", severity="high",
    pattern=r"\b1//0[A-Za-z0-9_-]{30,}\b",
)

create_pattern_detector(
    id="openai-api-key", provider="OpenAI", name="OpenAI API key", severity="critical",
    pattern=r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b",
)

create_pattern_detector(
    id="anthropic-api-key", provider="Anthropic", name="Anthropic API key", severity="critical",
    pattern=r"\bsk-ant-[A-Za-z0-9_-]{20,}\b",
)

create_pattern_detector(
    id="huggingface-token", provider="Hugging Face", name="Hugging Face access token", severity="high",
    pattern=r"\bhf_[A-Za-z0-9]{30,}\b",
)

create_pattern_detector(
    id="npm-token", provider="npm", name="npm access token", severity="high",
    pattern=r"\bnpm_[A-Za-z0-9]{36}\b",
)

create_pattern_detector(
    id="pypi-token", provider="PyPI", name="PyPI API token", severity="high",
    pattern=r"\bpypi-[A-Za-z0-9_-]{40,}\b",
)

create_pattern_detector(
    id="docker-token", provider="Docker", name="Docker Hub personal access token", severity="high",
    pattern=r"\bdckr_pat_[A-Za-z0-9_-]{20,}\b",
)

create_pattern_detector(
    id="twilio-api-key", provider="Twilio", name="Twilio API key", severity="high",
    pattern=r"\bSK[0-9a-f]{32}\b",
)

create_pattern_detector(
    id="sendgrid-api-key", provider="SendGrid", name="SendGrid API key", severity="high",
    pattern=r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b",
)

create_pattern_detector(
    id="discord-bot-token", provider="Discord", name="Discord bot token", severity="high",
    pattern=r"\b[A-Za-z0-9_-]{23,28}\.[A-Za-z0-9_-]{6,7}\.[A-Za-z0-9_-]{27,}\b",
)

create_pattern_detector(
    id="telegram-bot-token", provider="Telegram", name="Telegram bot token", severity="high",
    pattern=r"\b[0-9]{8,12}:[A-Za-z0-9_-]{30,}\b",
)

create_pattern_detector(
    id="mailgun-api-key", provider="Mailgun", name="Mailgun API key", severity="high",
    pattern=r"\bkey-[0-9a-fA-F]{32}\b",
)

create_pattern_detector(
    id="mailchimp-api-key", provider="Mailchimp", name="Mailchimp API key", severity="high",
    pattern=r"\b[0-9a-f]{32}-us[0-9]{1,2}\b",
)

create_pattern_detector(
    id="square-access-token", provider="Square", name="Square access token", severity="high",
    pattern=r"\bsq0atp-[A-Za-z0-9_-]{20,}\b",
)

create_pattern_detector(
    id="datadog-api-key", provider="Datadog", name="Datadog API key", severity="high",
    pattern=r"\b(?:dd|datadog)[A-Za-z0-9_]{0,16}\s*[:=]\s*[\"']?([0-9a-f]{32})[\"']?",
    flags=re.IGNORECASE, value_group=1,
)

create_pattern_detector(
    id="new-relic-license-key", provider="New Relic", name="New Relic license key", severity="high",
    pattern=r"\b(?:new_relic|newrelic|license_key)\s*[:=]\s*[\"']?([A-Za-z0-9]{32,40})[\"']?",
    flags=re.IGNORECASE, value_group=1,
)

create_pattern_detector(
    id="sonarqube-token", provider="SonarQube", name="SonarQube user token", severity="high",
    pattern=r"\bsqu_[A-Za-z0-9]{40}\b",
)

create_pattern_detector(
    id="db-uri-password", provider="Database", name="Database URI with password", severity="high",
    pattern=r"\b([a-z][a-z0-9+.-]{0,31})://([^:\s/@]{1,128}):([^@\s/]{3,512})@",
    flags=re.IGNORECASE, value_group=3,
)

create_pattern_detector(
    id="jwt-in-config", provider="JWT", name="JSON Web Token in configuration", severity="medium",
    pattern=r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
)


_PEM_PAIRS = [
    ("-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----"),
    ("-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----"),
    ("-----BEGIN EC PRIVATE KEY-----", "-----END EC PRIVATE KEY-----"),
    ("-----BEGIN DSA PRIVATE KEY-----", "-----END DSA PRIVATE KEY-----"),
    ("-----BEGIN OPENSSH PRIVATE KEY-----", "-----END OPENSSH PRIVATE KEY-----"),
    ("-----BEGIN ENCRYPTED PRIVATE KEY-----", "-----END ENCRYPTED PRIVATE KEY-----"),
]
_PEM_BEGIN_RE = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----")


def _pem_private_key_check(text: str) -> Iterable[Hit]:
    hits = []
    end_positions = []
    for _begin, end_marker in _PEM_PAIRS:
        positions = []
        at = 0
        while True:
            found = text.find(end_marker, at)
            if found == -1:
                break
            positions.append(found)
            at = found + len(end_marker)
        end_positions.append(positions)

    end_pointers = [0] * len(_PEM_PAIRS)
    pair_by_begin = {begin: index for index, (begin, _end) in enumerate(_PEM_PAIRS)}
    cursor = 0
    for match in _PEM_BEGIN_RE.finditer(text):
        begin_at = match.start()
        if begin_at < cursor:
            continue
        pair_index = pair_by_begin[match.group(0)]
        begin_marker, end_marker = _PEM_PAIRS[pair_index]
        body_start = begin_at + len(begin_marker)
        positions = end_positions[pair_index]
        pointer = end_pointers[pair_index]
        while pointer < len(positions) and positions[pointer] < body_start:
            pointer += 1
        end_pointers[pair_index] = pointer
        if pointer >= len(positions):
            continue
        end_at = positions[pointer]
        body_length = end_at - body_start
        if body_length < 1 or body_length > 20000:
            continue
        end_inclusive = end_at + len(end_marker)
        hits.append({"value": text[begin_at:end_inclusive], "index": begin_at})
        cursor = end_inclusive
    return hits


register_detector(
    id="pem-private-key", provider="PEM", name="PEM encoded private key", severity="critical",
    pattern=r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
    check=_pem_private_key_check,
)


_ASSIGNMENT_PATTERN = re.compile(
    r"([A-Za-z0-9_.-]{0,40}(?:secret|token|password|passwd|api[_-]?key|access[_-]?key|private[_-]?key|auth)[A-Za-z0-9_.-]{0,40})"
    r"\s*[:=]\s*[\"']?([^\s\"',;]{8,200})[\"']?",
    re.IGNORECASE,
)


def _generic_secret_assignment_check(text: str) -> Iterable[Hit]:
    hits = []
    for match in _ASSIGNMENT_PATTERN.finditer(text):
        value = match.group(2)
        if not value or shannon_entropy(value) < 3.2:
            continue
        hits.append({"value": value, "index": match.start(2)})
    return hits


register_detector(
    id="generic-secret-assignment", provider="Generic", name="High-entropy secret assignment", severity="medium",
    pattern=_ASSIGNMENT_PATTERN,
    check=_generic_secret_assignment_check,
)


_WORD_RE = re.compile(r"[A-Za-z0-9+/_-]{32,200}")
_ASSIGNED_BEFORE_RE = re.compile(r"(?:[\"'=:]|^)\s*$")


def _high_entropy_generic_check(text: str) -> Iterable[Hit]:
    hits = []
    for match in _WORD_RE.finditer(text):
        value = match.group(0)
        if shannon_entropy(value) < 4.3:
            continue
        before = text[max(0, match.start() - 24):match.start()]
        after = text[match.end():match.end() + 2]
        assigned = bool(_ASSIGNED_BEFORE_RE.search(before)) or after.startswith(('"', "'"))
        if assigned:
            hits.append({"value": value, "index": match.start()})
    return hits


register_detector(
    id="high-entropy-generic", provider="Generic", name="High-entropy unlabelled token", severity="medium",
    pattern=_WORD_RE,
    check=_high_entropy_generic_check,
)


def _luhn_valid(digits: str) -> bool:
    total = 0
    double = False
    for char in reversed(digits):
        value = ord(char) - 48
        if double:
            value *= 2
            if value > 9:
                value -= 9
        total += value
        double = not double
    return total % 10 == 0


def _credit_card_check(text: str) -> Iterable[Hit]:
    hits = []
    length = len(text)
    index = 0
    while index < length:
        if text[index] not in "0123456789" or (index and (text[index - 1] in "0123456789" or text[index - 1].isalpha() or text[index - 1] == "_")):
            index += 1
            continue
        start = index
        cursor = index
        digit_count = 0
        last_end = index
        while cursor < length:
            char = text[cursor]
            if char in "0123456789":
                digit_count += 1
                cursor += 1
                last_end = cursor
                continue
            if char in " -" and cursor + 1 < length and text[cursor + 1] in "0123456789":
                if cursor > start and text[cursor - 1] in " -":
                    break
                cursor += 1
                continue
            break
        candidate = text[start:last_end]
        digits = "".join(char for char in candidate if char in "0123456789")
        next_char = text[last_end] if last_end < length else ""
        bounded_after = not next_char or (next_char not in "0123456789" and not next_char.isalpha() and next_char != "_")
        if 13 <= digit_count <= 19 and len(digits) == digit_count and bounded_after and _luhn_valid(digits):
            hits.append({"value": candidate, "index": start})
        index = max(cursor, index + 1)
    return hits


register_detector(
    id="pii-credit-card", provider="PII", name="Luhn-verified payment card number", severity="high",
    check=_credit_card_check,
)


_SSN_RE = re.compile(r"\b([0-9]{3})-([0-9]{2})-([0-9]{4})\b")


def _ssn_check(text: str) -> Iterable[Hit]:
    hits = []
    for match in _SSN_RE.finditer(text):
        area, group, serial = match.groups()
        area_number = int(area)
        if area == "000" or group == "00" or serial == "0000":
            continue
        if area == "666" or area_number >= 900:
            continue
        if area + group + serial in {"078051120", "219099999"}:
            continue
        hits.append({"value": match.group(0), "index": match.start()})
    return hits


register_detector(
    id="pii-us-ssn", provider="PII", name="US Social Security number", severity="high",
    pattern=_SSN_RE,
    check=_ssn_check,
)
