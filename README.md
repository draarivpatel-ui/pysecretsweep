# pysecretsweep

pysecretsweep is a zero-dependency Python library and command line scanner for secrets and selected PII in source trees, standard input, and unified git diffs. It targets Python 3.9 through 3.13 and uses only the standard library at runtime.

Reports never contain raw matched secret values. Every finding carries a masked preview and a SHA-256 fingerprint, with SARIF 2.1.0 output for code scanning systems and deterministic baselines for suppressing reviewed findings.

## Security posture

- Raw secret values are never written to terminal, JSON, SARIF, baseline files, or expected error output.
- Values up to 16 characters are fully masked. Longer values expose only a bounded edge preview, never more than one quarter of the value.
- Filesystem scans use `os.lstat` and real-path containment. Symlinks escaping the scan root are rejected, symlink loops are nonfatal, and FIFOs, devices, sockets, and other special files are never opened.
- File content is classified by byte evidence. A NUL anywhere in the bounded file buffer or dense control bytes marks a file binary. A binary-looking extension does not hide readable text.
- Files are capped at 1,048,576 bytes by default. Root-level `.gitignore` and `.secretsweepignore` files are capped at 1 MiB.
- The gitignore matcher implements `*`, `?`, character classes, globstars, anchoring, directory rules, negation, and escapes without regex backtracking.
- Unified diff scanning parses hunks and scans only added lines with their target-file line numbers. Consecutive added lines are scanned together so multi-line PEM blocks can be detected.
- Custom detector patterns pass a conservative static lint for backreferences, lookbehind, stacked quantifiers, overlong patterns, and repeated groups containing repeats.
- Built-in scanning is designed around bounded or simple patterns and linear input-size behavior. There are no per-detector hit caps that could hide a late distinct secret.
- Baseline files contain only deterministic hashes of file, detector, and secret fingerprint tuples. They do not contain raw secrets or direct secret fingerprints.
- Terminal output escapes control characters in filenames and detector metadata so repository-controlled names cannot forge terminal control sequences.
- SARIF artifact URIs are relative POSIX paths with dot segments removed and unsafe bytes percent encoded. Absolute host paths are reduced to artifact names.

## Scope and limitations

pysecretsweep is a high-precision text scanner, not proof that a tree is clean. It can miss secrets in encodings, compressed files, binary formats, generated formats, split strings, or vendor forms it does not model. It can also flag test material that looks like a real credential.

Nested `.gitignore` files are outside the documented model. Only root-level `.gitignore` and `.secretsweepignore` are read. Inline suppression is textual and does not parse every host language; a string that looks like a suppression marker on the same line acts as a marker.

Standard input and diff input are read into memory. Filesystem file size is capped, but callers remain responsible for resource limits on very large streams. Symlink checks are designed for a scan tree that is not concurrently modified by an attacker.

SHA-256 fingerprints are deterministic so baselines are stable. For very low entropy secrets, any deterministic fingerprint is inherently offline-guessable. Fingerprints are not encryption and must not be treated as protection for a real exposed credential. Rotate exposed credentials instead of only baselining them.

## Installation

```bash
python3 -m pip install pysecretsweep
```

For a source checkout:

```bash
python3 -m pip install .
```

## Command line use

Scan the current directory:

```bash
pysecretsweep
```

Scan paths, standard input, or a unified diff:

```bash
pysecretsweep src config
pysecretsweep --stdin < input.txt
git diff --cached | pysecretsweep --diff
```

Select JSON or SARIF:

```bash
pysecretsweep --format json src
pysecretsweep --format sarif src > results.sarif
```

Other options:

```text
--detectors github-pat,pem-private-key
--severity high
--exclude generated
--max-file-bytes 1048576
--baseline .secretsweep-baseline.json
--write-baseline .secretsweep-baseline.json
--list-detectors
```

Exit codes are `0` for clean or successful baseline writing, `1` when findings remain, and `2` for usage or input errors.

## Python API

```python
from pysecretsweep import scan_path, scan_text, format_sarif

result = scan_text('token = "paste-your-token"')
print(result.to_dict())

tree = scan_path("src", max_file_bytes=1048576)
for finding in tree.findings:
    print(finding.file, finding.line, finding.detector, finding.redacted)

sarif_document = format_sarif(tree)
```

`scan_text`, `scan_path`, and `scan_diff` return `ScanResult`. Findings contain detector metadata, file, line, column, redacted preview, and fingerprint. They intentionally do not contain the raw matched value.

## Inline suppression

A same-line broad marker suppresses all detectors on that line:

```python
example_value = "paste-your-token"  # secretsweep:ignore
```

A scoped marker suppresses only the named detector:

```python
example_value = "paste-your-token"  # secretsweep:ignore generic-secret-assignment
```

`#`, `//`, and `/*` comment forms are recognized. Markers on previous or following lines do not apply.

## Baselines

Write a baseline after reviewing current findings:

```bash
pysecretsweep --write-baseline .secretsweep-baseline.json
```

Use it on later scans:

```bash
pysecretsweep --baseline .secretsweep-baseline.json
```

A baseline suppresses only exact deterministic matches. Changed secrets, moved findings, and findings from a different detector are still reported. A baseline is a review workflow, not remediation.

## Custom detectors

```python
import re
from pysecretsweep import create_pattern_detector, scan_text

create_pattern_detector(
    id="internal-example-token",
    provider="Internal",
    name="Example internal token",
    severity="high",
    pattern=r"\bexamplecorp_[A-Za-z0-9]{32}\b",
)

result = scan_text("example input", detectors=["internal-example-token"])
```

Detector ids use lowercase letters, digits, and hyphens. Severities are restricted to `low`, `medium`, `high`, and `critical`. Custom regexes are statically linted before registration. The lint is conservative defense in depth, not a mathematical proof about every possible regular expression.

## Built-in detectors

The detector registry currently contains 36 built-in detectors. Coverage includes AWS access keys, GitHub token forms, Stripe keys, Slack webhooks and tokens, Google keys and OAuth secrets, OpenAI and Anthropic keys, Hugging Face, npm, PyPI, Docker, Twilio, SendGrid, Discord, Telegram, Mailgun, Mailchimp, Square, Datadog, New Relic, SonarQube, database URIs with passwords, JWT-shaped configuration values, PEM private keys, high-entropy assignments, unlabelled high-entropy tokens, Luhn-verified payment card numbers, and structurally valid US Social Security numbers.

PII detection is intentionally narrow. Payment card numbers must pass Luhn validation, and Social Security numbers must use formatted fields that pass structural exclusions. These checks reduce noise but do not prove that a value is real or sensitive.

## Test evidence and development

The offline unittest suite currently contains 512 real tests covering all 36 detectors, redaction, placeholders, inline suppression, custom detector validation, gitignore behavior, symlink and special-file safety, binary detection, unified diff line mapping, baseline validation, SARIF structure, CLI exit codes, performance shapes, packaging, and repository hygiene. All 512 tests passed in the local verification run for this commit.

Run the suite with:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests
```

The project has no runtime dependencies and no third-party test dependencies.
