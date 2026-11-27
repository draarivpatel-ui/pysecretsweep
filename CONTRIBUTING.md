# Contributing

Thanks for helping improve pysecretsweep. The project has zero runtime dependencies and targets Python 3.9 through 3.13.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Running tests

```bash
PYTHONPATH=src python3 -m unittest discover -s tests
```

Every change must keep the suite green using Python 3.9 syntax. No third-party test packages are required.

## Security invariants

- Keep `dependencies = []` in `pyproject.toml`.
- Never print or serialize a raw matched secret value.
- Keep baseline files limited to deterministic fingerprints.
- Do not weaken symlink containment, special-file rejection, binary detection, or ignore-file size limits.
- Validate custom detector ids, severities, and patterns.
- Keep error messages free of input secrets.
- Construct every synthetic vendor-shaped test token dynamically in tests.
- Add regression tests for every validation rule or bug fix.
- Do not add em dashes or en dashes to source, docs, tests, or workflow files.

## Code guidelines

- Use only the Python standard library at runtime.
- Use type annotations on public functions.
- Preserve Python 3.9 compatibility.
- Keep scanning deterministic and bounded by documented input limits.
- Prefer precise detectors with explicit validation over broad high-noise matching.
- Do not add network access, subprocess execution, or publishing behavior to the library.

## Pull requests

1. Fork the repository and create a focused branch.
2. Describe the security impact of the change.
3. Add or update regression tests.
4. Run the full suite and paste the result.
5. Keep commits small and self-contained.

## Good first issues

See [docs/good-first-issues.md](docs/good-first-issues.md) for ten modular starter tasks.
