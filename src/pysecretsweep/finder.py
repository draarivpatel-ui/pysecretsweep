"""Finding engine: detector application, suppression, redaction, and ordering."""

import bisect
import re
from typing import Iterable, List, Optional, Sequence, Set, Union

from .detectors import Detector, _REGISTRY, get_detector
from .errors import DetectorError, UsageError
from .types import Finding, ScanResult
from .util import SEVERITY_RANK, fingerprint, is_placeholder, mask_value

_INLINE_IGNORE_RE = re.compile(r"(?:#|//|/\*)\s*secretsweep:ignore\b(.*)$")


def _line_starts(text: str) -> List[int]:
    starts = [0]
    index = text.find("\n")
    while index != -1:
        starts.append(index + 1)
        index = text.find("\n", index + 1)
    return starts


def _inline_suppressions(text: str, starts: Sequence[int]):
    suppressions = {}
    for line_index, line_start in enumerate(starts):
        if line_index + 1 < len(starts):
            line_end = starts[line_index + 1]
        else:
            line_end = len(text)
        if line_end > line_start and text[line_end - 1] == "\n":
            line_end -= 1
        if line_end > line_start and text[line_end - 1] == "\r":
            line_end -= 1
        match = _INLINE_IGNORE_RE.search(text[line_start:line_end])
        if not match:
            continue
        suffix = re.sub(r"\*/\s*$", "", match.group(1) or "").strip()
        if suffix.startswith("="):
            suffix = suffix[1:].strip()
        if not suffix:
            suppressions[line_index] = True
        else:
            suppressions[line_index] = {part for part in re.split(r"[\s,]+", suffix) if part}
    return suppressions


def _select_detectors(detector_selection: Optional[Iterable[Union[str, Detector]]]) -> List[Detector]:
    if detector_selection is None:
        return list(_REGISTRY)
    selected = []
    seen = set()
    for item in detector_selection:
        if isinstance(item, Detector):
            detector = item
        else:
            detector_id = str(item)
            detector = get_detector(detector_id)
            if detector is None:
                raise UsageError("unknown detector: {}".format(detector_id))
        if detector.id not in seen:
            selected.append(detector)
            seen.add(detector.id)
    if not selected:
        raise UsageError("detector selection is empty")
    return selected


def scan_text(
    text: str,
    *,
    filename: str = "<stdin>",
    detectors: Optional[Iterable[Union[str, Detector]]] = None,
    severity: Optional[str] = None,
    ignore_comments: bool = True,
    allow_placeholder: bool = False,
) -> ScanResult:
    """Scan text and return a structured result containing only safe metadata.

    ``severity`` is a minimum severity threshold. Inline suppression applies
    only on the same line and can either be broad (``# secretsweep:ignore``)
    or rule scoped (``# secretsweep:ignore github-pat``).
    """

    if not isinstance(text, str):
        raise TypeError("scan_text expects a string")
    if severity is not None and severity not in SEVERITY_RANK:
        raise UsageError("unknown severity: {}".format(severity))

    enabled = _select_detectors(detectors)
    starts = _line_starts(text)
    suppressions = _inline_suppressions(text, starts) if ignore_comments else {}
    findings: List[Finding] = []

    for detector in enabled:
        if severity is not None and SEVERITY_RANK[detector.severity] < SEVERITY_RANK[severity]:
            continue
        try:
            hits = list(detector.check(text) or [])
        except Exception as exc:
            raise DetectorError("detector {} failed".format(detector.id)) from None

        for hit in hits:
            if not isinstance(hit, dict):
                continue
            value = hit.get("value")
            if not isinstance(value, str) or not value:
                continue
            index = hit.get("index")
            if not isinstance(index, int) or isinstance(index, bool):
                index = text.find(value)
            if index < 0 or index > len(text):
                continue
            if not allow_placeholder and is_placeholder(value):
                continue

            line_index = bisect.bisect_right(starts, index) - 1
            suppression = suppressions.get(line_index)
            if suppression is True or (isinstance(suppression, set) and detector.id in suppression):
                continue
            line = line_index + 1
            column = index - starts[line_index] + 1
            findings.append(
                Finding(
                    detector=detector.id,
                    provider=detector.provider,
                    name=detector.name,
                    severity=detector.severity,
                    file=str(filename),
                    line=line,
                    column=column,
                    redacted=mask_value(value),
                    fingerprint=fingerprint(value),
                )
            )

    findings.sort(key=lambda item: (item.line, item.column, item.detector in {"generic-secret-assignment", "high-entropy-generic"}, item.detector, item.fingerprint))
    deduplicated = []
    seen = set()
    for finding in findings:
        key = (finding.line, finding.column, finding.fingerprint)
        if key in seen:
            continue
        seen.add(key)
        deduplicated.append(finding)
    return ScanResult(findings=deduplicated, scanned_files=1)
