"""Structured result types for pysecretsweep."""

from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional


@dataclass(frozen=True)
class Finding:
    """A redacted secret or PII finding.

    This type deliberately has no field for the matched value. The raw bytes
    exist only transiently inside the scanning engine. Reports receive a
    masked preview and a SHA-256 fingerprint.
    """

    detector: str
    provider: str
    name: str
    severity: str
    file: str
    line: int
    column: int
    redacted: str
    fingerprint: str

    def to_dict(self) -> Dict[str, object]:
        return {
            "detector": self.detector,
            "provider": self.provider,
            "name": self.name,
            "severity": self.severity,
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "redacted": self.redacted,
            "fingerprint": self.fingerprint,
        }


@dataclass
class ScanResult:
    """Structured scan output.

    ``findings`` contains only redacted findings. ``skipped`` records files
    that were not scanned and the machine-readable reason. ``root`` is the
    absolute scan target for filesystem scans and is not emitted in SARIF.
    """

    findings: List[Finding] = field(default_factory=list)
    skipped: List[Dict[str, str]] = field(default_factory=list)
    root: Optional[str] = None
    scanned_files: int = 0

    def __iter__(self) -> Iterator[Finding]:
        return iter(self.findings)

    def __len__(self) -> int:
        return len(self.findings)

    def __bool__(self) -> bool:
        return bool(self.findings)

    def to_dict(self) -> Dict[str, object]:
        return {
            "count": len(self.findings),
            "findings": [finding.to_dict() for finding in self.findings],
            "skipped": list(self.skipped),
            "scanned_files": self.scanned_files,
        }
