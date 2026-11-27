# Security Policy

## Supported versions

Version 1.x receives security fixes.

## Reporting a vulnerability

Please use the private security advisory form for this repository:

https://github.com/draarivpatel-ui/pysecretsweep/security/advisories/new

Do not open a public issue for an undisclosed vulnerability.

Include the affected version, a minimal input or command reproduction, the expected behavior, and the observed behavior. Do not include real secrets, private keys, production tokens, or personal data. Reports are acknowledged within 3 business days. Initial triage is targeted within 14 days. A fix, mitigation, or documented resolution is targeted within 90 days. Fixes are released as patch versions with a changelog entry.

## In scope

- Raw secret values appearing in terminal, JSON, SARIF, baseline, or expected error output
- Symlink escapes that scan files outside the scan root during a directory scan
- Special-file handling that opens a FIFO, device, socket, or other non-regular file
- Ignore-file handling that exceeds documented size or rule-count bounds
- Git-diff line mapping errors that hide added secrets or scan removed secrets as added
- SARIF artifact URIs that disclose absolute host paths or permit path traversal
- Baseline validation or fingerprint behavior that stores raw secrets
- Custom detector registration that accepts clearly superlinear regex structures rejected by the documented lint
- Practical denial of service within documented input size limits
- Terminal control injection through filenames or detector metadata

## Out of scope

- Secrets outside the documented detector model or hidden in compressed or binary formats
- False positives in synthetic, example, or already revoked values
- Denial of service from caller-controlled stdin or diff streams above practical memory limits
- Residual race conditions in scan trees concurrently modified by an attacker after the documented file-open hardening is accounted for
- Vulnerabilities in applications embedding the library
- Social engineering or physical access

## Operational notes

pysecretsweep performs no network access, subprocess execution, browser interaction, package publishing, or credential lookup. It scans only the input it is given. A reported secret must be treated as exposed regardless of redaction. Rotate the credential with its provider and then use a baseline only for reviewed residual test material.
