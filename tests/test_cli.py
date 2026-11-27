import io
import json
import os
import subprocess
import sys
import tempfile
import unittest

import _support as s
from pysecretsweep import VERSION, write_baseline, scan_path
from pysecretsweep.cli import EXIT_CLEAN, EXIT_FINDINGS, EXIT_USAGE, main, parse_args
from pysecretsweep.errors import UsageError


def run_cli(args, input_text=""):
    stdout = io.StringIO()
    stderr = io.StringIO()
    code = main(args, stdin=io.StringIO(input_text), stdout=stdout, stderr=stderr)
    return code, stdout.getvalue(), stderr.getvalue()


class CliBasicTests(unittest.TestCase):
    def test_help_exits_zero(self):
        code, out, err = run_cli(["--help"])
        self.assertEqual(EXIT_CLEAN, code)
        self.assertIn("Usage:", out)
        self.assertEqual("", err)

    def test_short_help_exits_zero(self):
        code, out, _err = run_cli(["-h"])
        self.assertEqual(EXIT_CLEAN, code)
        self.assertIn("pysecretsweep", out)

    def test_version_exits_zero(self):
        code, out, err = run_cli(["--version"])
        self.assertEqual(EXIT_CLEAN, code)
        self.assertEqual("pysecretsweep {}\n".format(VERSION), out)
        self.assertEqual("", err)

    def test_short_version_exits_zero(self):
        code, out, _err = run_cli(["-v"])
        self.assertEqual(EXIT_CLEAN, code)
        self.assertIn(VERSION, out)

    def test_list_detectors_exits_zero(self):
        code, out, err = run_cli(["--list-detectors"])
        self.assertEqual(EXIT_CLEAN, code)
        lines = [line for line in out.splitlines() if line]
        self.assertEqual(36, len(lines))
        self.assertIn("github-pat\tGitHub\thigh", out)
        self.assertEqual("", err)

    def test_stdin_clean_exits_zero(self):
        code, out, err = run_cli(["--stdin"], "ordinary text\n")
        self.assertEqual(EXIT_CLEAN, code)
        self.assertEqual("pysecretsweep: no secrets found\n", out)
        self.assertEqual("", err)

    def test_stdin_finding_exits_one_without_raw_secret(self):
        token = s.github_pat()
        code, out, err = run_cli(["--stdin"], token + "\n")
        self.assertEqual(EXIT_FINDINGS, code)
        self.assertIn("1 potential secret", out)
        self.assertNotIn(token, out)
        self.assertEqual("", err)

    def test_stdin_json_format(self):
        token = s.github_pat()
        code, out, _err = run_cli(["--stdin", "--format", "json"], token)
        self.assertEqual(EXIT_FINDINGS, code)
        payload = json.loads(out)
        self.assertEqual(1, payload["count"])
        self.assertNotIn(token, out)

    def test_stdin_sarif_format(self):
        token = s.github_pat()
        code, out, _err = run_cli(["--stdin", "--format", "sarif"], token)
        self.assertEqual(EXIT_FINDINGS, code)
        payload = json.loads(out)
        self.assertEqual("2.1.0", payload["version"])
        self.assertNotIn(token, out)

    def test_equals_style_format(self):
        token = s.github_pat()
        code, out, _err = run_cli(["--stdin", "--format=json"], token)
        self.assertEqual(EXIT_FINDINGS, code)
        self.assertEqual("pysecretsweep", json.loads(out)["tool"])

    def test_diff_mode_scans_added_line(self):
        token = s.github_pat()
        diff = "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -1 +8 @@\n+{}\n".format(token)
        code, out, _err = run_cli(["--diff"], diff)
        self.assertEqual(EXIT_FINDINGS, code)
        self.assertIn("a.py:8:", out)
        self.assertNotIn(token, out)

    def test_detector_selection(self):
        token = s.github_pat()
        code, out, _err = run_cli(["--stdin", "--detectors", "jwt-in-config"], token)
        self.assertEqual(EXIT_CLEAN, code)
        self.assertIn("no secrets", out)

    def test_severity_filter(self):
        token = s.github_pat()
        code, out, _err = run_cli(["--stdin", "--severity", "critical"], token)
        self.assertEqual(EXIT_CLEAN, code)
        self.assertIn("no secrets", out)


class CliUsageErrorTests(unittest.TestCase):
    def assert_usage(self, args, input_text=""):
        code, out, err = run_cli(args, input_text)
        self.assertEqual(EXIT_USAGE, code)
        self.assertEqual("", out)
        self.assertIn("pysecretsweep:", err)
        self.assertNotIn("Traceback", err)
        return err

    def test_unknown_option(self):
        self.assert_usage(["--wat"])

    def test_missing_format_value(self):
        self.assert_usage(["--format"])

    def test_unknown_format(self):
        self.assert_usage(["--stdin", "--format", "xml"])

    def test_unknown_severity(self):
        self.assert_usage(["--stdin", "--severity", "urgent"])

    def test_unknown_detector(self):
        self.assert_usage(["--stdin", "--detectors", "missing-detector"])

    def test_empty_detector_selection(self):
        self.assert_usage(["--stdin", "--detectors", ","])

    def test_conflicting_stdin_and_diff(self):
        self.assert_usage(["--stdin", "--diff"])

    def test_conflicting_stdin_and_path(self):
        self.assert_usage(["--stdin", "somepath"])

    def test_conflicting_diff_and_path(self):
        self.assert_usage(["--diff", "somepath"])

    def test_invalid_max_file_bytes_text(self):
        self.assert_usage(["--max-file-bytes", "abc"])

    def test_invalid_max_file_bytes_zero(self):
        self.assert_usage(["--max-file-bytes", "0"])

    def test_error_message_escapes_control_characters(self):
        err = self.assert_usage(["--bad\x1boption"])
        self.assertNotIn("\x1b", err)
        self.assertIn("\\x1b", err)


class CliFilesystemTests(unittest.TestCase):
    def test_path_scan_finding(self):
        token = s.github_pat()
        with tempfile.TemporaryDirectory() as root:
            with open(os.path.join(root, "a.txt"), "w") as handle:
                handle.write(token)
            code, out, err = run_cli([root])
        self.assertEqual(EXIT_FINDINGS, code)
        self.assertIn("a.txt:1:1", out)
        self.assertNotIn(token, out)
        self.assertEqual("", err)

    def test_path_scan_clean(self):
        with tempfile.TemporaryDirectory() as root:
            with open(os.path.join(root, "a.txt"), "w") as handle:
                handle.write("clean")
            code, out, _err = run_cli([root])
        self.assertEqual(EXIT_CLEAN, code)
        self.assertIn("no secrets", out)

    def test_missing_path_is_usage_error(self):
        with tempfile.TemporaryDirectory() as root:
            code, out, err = run_cli([os.path.join(root, "missing")])
        self.assertEqual(EXIT_USAGE, code)
        self.assertEqual("", out)
        self.assertIn("cannot read", err)
        self.assertNotIn("Traceback", err)

    def test_exclude_cli_prefix(self):
        token = s.github_pat()
        with tempfile.TemporaryDirectory() as root:
            os.mkdir(os.path.join(root, "excluded"))
            with open(os.path.join(root, "excluded", "a.txt"), "w") as handle:
                handle.write(token)
            code, out, _err = run_cli([root, "--exclude", "excluded"])
        self.assertEqual(EXIT_CLEAN, code)
        self.assertIn("no secrets", out)

    def test_max_file_bytes_cli(self):
        token = s.github_pat()
        with tempfile.TemporaryDirectory() as root:
            with open(os.path.join(root, "a.txt"), "w") as handle:
                handle.write(token)
            code, out, _err = run_cli([root, "--max-file-bytes", "5"])
        self.assertEqual(EXIT_CLEAN, code)
        self.assertIn("no secrets", out)

    def test_multiple_paths_are_scanned(self):
        token = s.github_pat()
        with tempfile.TemporaryDirectory() as root:
            one = os.path.join(root, "one.txt")
            two = os.path.join(root, "two.txt")
            for path in (one, two):
                with open(path, "w") as handle:
                    handle.write(token)
            code, out, _err = run_cli([one, two])
        self.assertEqual(EXIT_FINDINGS, code)
        self.assertEqual(2, out.count("github-pat"))

    def test_write_baseline_exits_zero_and_writes_hashes(self):
        token = s.github_pat()
        with tempfile.TemporaryDirectory() as root:
            with open(os.path.join(root, "a.txt"), "w") as handle:
                handle.write(token)
            baseline = os.path.join(root, "baseline.json")
            code, out, err = run_cli([root, "--write-baseline", baseline])
            self.assertEqual(EXIT_CLEAN, code)
            self.assertIn("wrote 1 baseline entries", out)
            with open(baseline) as handle:
                content = handle.read()
            self.assertNotIn(token, content)
            self.assertEqual("", err)

    def test_write_baseline_failure_is_usage_error(self):
        token = s.github_pat()
        with tempfile.TemporaryDirectory() as root:
            with open(os.path.join(root, "a.txt"), "w") as handle:
                handle.write(token)
            baseline = os.path.join(root, "missing", "baseline.json")
            code, out, err = run_cli([root, "--write-baseline", baseline])
        self.assertEqual(EXIT_USAGE, code)
        self.assertEqual("", out)
        self.assertIn("cannot write baseline", err)
        self.assertNotIn("Traceback", err)

    def test_baseline_suppresses_finding(self):
        token = s.github_pat()
        with tempfile.TemporaryDirectory() as root:
            with open(os.path.join(root, "a.txt"), "w") as handle:
                handle.write(token)
            scan = scan_path(root)
            baseline = os.path.join(root, "baseline.json")
            write_baseline(baseline, scan)
            code, out, err = run_cli([root, "--baseline", baseline])
        self.assertEqual(EXIT_CLEAN, code)
        self.assertIn("no secrets", out)
        self.assertEqual("", err)

    def test_malformed_baseline_is_usage_error(self):
        with tempfile.TemporaryDirectory() as root:
            baseline = os.path.join(root, "baseline.json")
            with open(baseline, "w") as handle:
                handle.write("[null]")
            with open(os.path.join(root, "a.txt"), "w") as handle:
                handle.write("clean")
            code, out, err = run_cli([root, "--baseline", baseline])
        self.assertEqual(EXIT_USAGE, code)
        self.assertEqual("", out)
        self.assertIn("invalid baseline entry", err)
        self.assertNotIn("Traceback", err)


class CliModuleTests(unittest.TestCase):
    def test_python_module_entrypoint(self):
        root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        env = dict(os.environ)
        env["PYTHONPATH"] = os.path.join(root, "src")
        proc = subprocess.run(
            [sys.executable, "-m", "pysecretsweep", "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            env=env,
            cwd=root,
        )
        self.assertEqual(0, proc.returncode)
        self.assertIn(VERSION, proc.stdout)
        self.assertEqual("", proc.stderr)

    def test_parse_args_defaults(self):
        options = parse_args([])
        self.assertEqual([], options["paths"])
        self.assertFalse(options["diff"])
        self.assertFalse(options["stdin"])

    def test_parse_args_rejects_value_for_diff(self):
        with self.assertRaises(UsageError):
            parse_args(["--diff=yes"])
