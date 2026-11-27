"""Deterministic terminal, JSON, and SARIF 2.1.0 output formats."""

import json
import re
from urllib.parse import quote_from_bytes

from .types import ScanResult
from .util import SEVERITY_RANK, VERSION, safe_display

SARIF_LEVEL = {"low": "warning", "medium": "warning", "high": "error", "critical": "error"}


def _finding_list(findings):
    if isinstance(findings, ScanResult):
        return list(findings.findings)
    return list(findings)


def _skipped(findings, options):
    if options and "skipped" in options:
        return options.get("skipped")
    if isinstance(findings, ScanResult):
        return findings.skipped
    return None


def sarif_artifact_uri(file_value) -> str:
    """Convert a finding path into a safe relative POSIX SARIF artifact URI."""

    text = str(file_value or "").replace("\\", "/")
    if not text or text in ("<text>", "<stdin>"):
        return "stdin"

    if re.match(r"^(?:[A-Za-z]:/|/)", text):
        parts = [part for part in text.split("/") if part]
        text = parts[-1] if parts else "artifact"
    else:
        segments = []
        for segment in text.split("/"):
            if not segment or segment == ".":
                continue
            if segment == "..":
                if segments:
                    segments.pop()
                continue
            segments.append(segment)
        text = "/".join(segments) or "artifact"
    return "/".join(quote_from_bytes(segment.encode("utf-8", "surrogateescape"), safe="") for segment in text.split("/"))


def format_terminal(findings, **options) -> str:
    values = _finding_list(findings)
    if not values:
        return options.get("clean_message") or "pysecretsweep: no secrets found\n"
    lines = [
        "pysecretsweep: {} potential secret{} found".format(len(values), "" if len(values) == 1 else "s")
    ]
    for finding in values:
        where = "{}:{}:{}".format(safe_display(finding.file or "<text>"), finding.line, finding.column)
        lines.append(
            "{} [{}] {} ({}) {} sha256:{}".format(
                where,
                safe_display(finding.severity),
                safe_display(finding.provider),
                safe_display(finding.detector),
                safe_display(finding.redacted),
                finding.fingerprint[:12],
            )
        )
    return "\n".join(lines) + "\n"


def format_json(findings, **options) -> str:
    values = _finding_list(findings)
    payload = {
        "tool": "pysecretsweep",
        "version": VERSION,
        "count": len(values),
        "findings": [finding.to_dict() for finding in values],
    }
    skipped = _skipped(findings, options)
    if skipped is not None:
        payload["skipped"] = skipped
    return json.dumps(payload, indent=2) + "\n"


def format_sarif(findings, **options) -> str:
    values = _finding_list(findings)
    rules = []
    seen_rules = set()
    results = []
    for finding in values:
        if finding.detector not in seen_rules:
            seen_rules.add(finding.detector)
            rules.append(
                {
                    "id": finding.detector,
                    "name": finding.detector,
                    "shortDescription": {"text": finding.name or finding.provider},
                    "defaultConfiguration": {"level": SARIF_LEVEL.get(finding.severity, "warning")},
                    "properties": {"tags": ["security", "secrets", finding.provider]},
                }
            )
        results.append(
            {
                "ruleId": finding.detector,
                "level": SARIF_LEVEL.get(finding.severity, "warning"),
                "message": {
                    "text": "{}: potential {} ({})".format(
                        finding.provider,
                        finding.name or "secret",
                        finding.redacted,
                    )
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": sarif_artifact_uri(finding.file)},
                            "region": {
                                "startLine": max(1, int(finding.line or 1)),
                                "startColumn": max(1, int(finding.column or 1)),
                            },
                        }
                    }
                ],
                "partialFingerprints": {"pysecretsweepFingerprint": finding.fingerprint},
            }
        )
    rules.sort(key=lambda rule: rule["id"])
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "columnKind": "unicodeCodePoints",
                "tool": {
                    "driver": {
                        "name": "pysecretsweep",
                        "version": VERSION,
                        "informationUri": "https://github.com/draarivpatel-ui/pysecretsweep",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    if options.get("originalUriBaseIds"):
        payload["runs"][0]["originalUriBaseIds"] = options["originalUriBaseIds"]
    return json.dumps(payload, indent=2) + "\n"


def format_output(findings, format_name: str, **options) -> str:
    if format_name == "text":
        return format_terminal(findings, **options)
    if format_name == "json":
        return format_json(findings, **options)
    if format_name == "sarif":
        return format_sarif(findings, **options)
    raise ValueError("unknown output format: {}".format(format_name))


format_text = format_terminal


def sort_findings(findings):
    return sorted(
        findings,
        key=lambda item: (
            item.file or "",
            item.line,
            item.column,
            -SEVERITY_RANK.get(item.severity, 0),
            item.detector,
            item.fingerprint,
        ),
    )
