# Good first issues

Ten modular starter tasks for new contributors. Each is scoped to one file or one focused behavior. Every task must preserve the zero runtime dependency rule and Python 3.9 compatibility.

1. **Add detector precision fixtures** in `tests/test_detector_matrix.py` for one provider, including a near miss that must not match.
2. **Add a gitignore comparison matrix** in `tests/test_ignore.py` for character classes, escaped literals, and globstar edge cases not already covered.
3. **Add diff parser fixtures** in `tests/test_diff.py` for renamed files, mode-only changes, and quoted non-ASCII filenames.
4. **Add baseline interoperability examples** in `README.md` showing reviewed suppression without storing raw secrets.
5. **Write `docs/threat-model.md`** describing attacker-controlled repositories, scan input trust boundaries, baseline risks, and caller responsibilities.
6. **Add a standard-input resource guide** in `docs/` that explains memory behavior and safe ways to chunk large untrusted streams without dropping matches.
7. **Add SARIF consumer fixtures** in `tests/test_baseline_output.py` for URI encoding of Unicode and surrogateescape filenames.
8. **Add a detector proposal template** under `.github/ISSUE_TEMPLATE/` that requires precision evidence, false-positive analysis, and safe synthetic examples.
9. **Add package build verification** in `tests/test_package.py` using only stdlib tooling to inspect the generated wheel file list when a wheel is present.
10. **Improve custom detector documentation** in `README.md` with a capture-group example, value offsets, severity selection, and performance responsibilities.

Before starting one, open an issue or comment on the existing issue so work is not duplicated. Add tests with every code change.
