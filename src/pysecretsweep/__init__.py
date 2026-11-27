"""pysecretsweep public API. Zero runtime dependencies."""

from .baseline import apply_baseline, baseline_key, read_baseline, write_baseline
from .detectors import (
    Detector,
    create_pattern_detector,
    get_detector,
    list_detectors,
    register_detector,
    unregister_detector,
)
from .errors import DetectorError, SecretSweepError, UsageError
from .finder import scan_text
from .output import format_json, format_output, format_sarif, format_terminal, format_text, sort_findings
from .scanner import DEFAULT_MAX_FILE_BYTES, is_binary_path, looks_binary, scan_diff, scan_path
from .types import Finding, ScanResult
from .util import VERSION, analyze_pattern, fingerprint, is_placeholder, mask_value, shannon_entropy

__version__ = VERSION

__all__ = [
    "VERSION", "__version__", "Detector", "DetectorError", "Finding", "ScanResult",
    "SecretSweepError", "UsageError", "DEFAULT_MAX_FILE_BYTES", "analyze_pattern",
    "apply_baseline", "baseline_key", "create_pattern_detector", "fingerprint",
    "format_json", "format_output", "format_sarif", "format_terminal", "format_text",
    "get_detector", "is_binary_path", "is_placeholder", "list_detectors", "looks_binary",
    "mask_value", "read_baseline", "register_detector", "scan_diff", "scan_path",
    "scan_text", "shannon_entropy", "sort_findings", "unregister_detector", "write_baseline",
]
