"""Baseline suppression using deterministic secret fingerprints only."""

import json
import os
import tempfile
from typing import List, Set, Union

from .errors import UsageError, SecretSweepError
from .types import Finding, ScanResult
from .util import fingerprint, safe_display


def baseline_key(finding: Finding) -> str:
    """Return the stable baseline key for a redacted finding."""

    return fingerprint("{}:{}:{}".format(finding.file or "", finding.detector, finding.fingerprint))


def _finding_list(findings) -> List[Finding]:
    if isinstance(findings, ScanResult):
        return list(findings.findings)
    return list(findings)


def read_baseline(path: Union[str, os.PathLike]) -> Set[str]:
    """Read and strictly validate a baseline file.

    Accepted forms are a JSON array of non-empty key strings or an object with
    an ``entries`` array. Entries may also be objects with a non-empty string
    ``key``. No raw secret value is ever part of the format.
    """

    display = safe_display(os.fspath(path))
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise SecretSweepError("cannot read baseline {}".format(display)) from exc

    if isinstance(data, list):
        values = data
    elif isinstance(data, dict) and isinstance(data.get("entries"), list):
        values = data["entries"]
    else:
        raise UsageError("invalid baseline format in {}".format(display))

    keys = set()
    for entry in values:
        if isinstance(entry, str) and entry:
            keys.add(entry)
            continue
        if isinstance(entry, dict) and isinstance(entry.get("key"), str) and entry.get("key"):
            keys.add(entry["key"])
            continue
        raise UsageError("invalid baseline entry in {}".format(display))
    return keys


def apply_baseline(findings, keys):
    """Suppress findings whose stable keys appear in ``keys``.

    Lists return lists. A ScanResult returns a new ScanResult with the same
    skipped metadata, root, and scanned file count.
    """

    if keys is None:
        return findings
    key_set = set(keys)
    if isinstance(findings, ScanResult):
        filtered = [finding for finding in findings.findings if baseline_key(finding) not in key_set]
        return ScanResult(
            findings=filtered,
            skipped=list(findings.skipped),
            root=findings.root,
            scanned_files=findings.scanned_files,
        )
    return [finding for finding in findings if baseline_key(finding) not in key_set]


def write_baseline(path: Union[str, os.PathLike], findings) -> int:
    """Atomically write a deterministic baseline and return its entry count."""

    values = sorted({baseline_key(finding) for finding in _finding_list(findings)})
    payload = json.dumps({"version": 1, "entries": values}, indent=2, sort_keys=True) + "\n"
    destination = os.fspath(path)
    directory = os.path.dirname(os.path.abspath(destination)) or "."
    temporary = None
    try:
        fd, temporary = tempfile.mkstemp(prefix=".pysecretsweep-baseline-", dir=directory)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(payload)
        os.replace(temporary, destination)
        temporary = None
    except OSError as exc:
        raise SecretSweepError("cannot write baseline {}".format(safe_display(destination))) from exc
    finally:
        if temporary:
            try:
                os.unlink(temporary)
            except OSError:
                pass
    return len(values)
