import json
import os
import tempfile
import unittest

import _support as s
import pysecretsweep
from pysecretsweep import (
    Finding,
    ScanResult,
    SecretSweepError,
    UsageError,
    apply_baseline,
    baseline_key,
    format_json,
    format_output,
    format_sarif,
    format_terminal,
    read_baseline,
    scan_text,
    sort_findings,
    write_baseline,
)
from pysecretsweep.output import sarif_artifact_uri

USERS_PREFIX = "/" + "Users" + "/"


def one_result():
    token = s.github_pat()
    return scan_text(token, filename="a.txt", detectors=["github-pat"]), token


class BaselineTests(unittest.TestCase):
    def test_baseline_key_is_deterministic_sha256(self):
        result, _token = one_result()
        key = baseline_key(result.findings[0])
        self.assertEqual(64, len(key))
        self.assertEqual(key, baseline_key(result.findings[0]))

    def test_baseline_key_depends_on_file(self):
        token = s.github_pat()
        first = scan_text(token, filename="a.txt", detectors=["github-pat"]).findings[0]
        second = scan_text(token, filename="b.txt", detectors=["github-pat"]).findings[0]
        self.assertNotEqual(baseline_key(first), baseline_key(second))

    def test_baseline_roundtrip_suppresses(self):
        result, _token = one_result()
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "baseline.json")
            count = write_baseline(path, result)
            self.assertEqual(1, count)
            keys = read_baseline(path)
            self.assertEqual([], apply_baseline(result.findings, keys))

    def test_baseline_file_contains_no_raw_secret_or_secret_fingerprint(self):
        result, token = one_result()
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "baseline.json")
            write_baseline(path, result)
            with open(path) as handle:
                content = handle.read()
            self.assertNotIn(token, content)
            self.assertNotIn(s.fp(token), content)

    def test_baseline_write_is_sorted_and_deduplicated(self):
        result, _token = one_result()
        findings = result.findings + result.findings
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "baseline.json")
            self.assertEqual(1, write_baseline(path, findings))
            with open(path) as handle:
                data = json.load(handle)
            self.assertEqual(1, len(data["entries"]))

    def test_read_baseline_accepts_string_array(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "baseline.json")
            with open(path, "w") as handle:
                handle.write('["abc"]\n')
            self.assertEqual({"abc"}, read_baseline(path))

    def test_read_baseline_accepts_key_objects(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "baseline.json")
            with open(path, "w") as handle:
                handle.write('{"version":1,"entries":[{"key":"abc"}]}\n')
            self.assertEqual({"abc"}, read_baseline(path))

    def test_malformed_top_level_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "baseline.json")
            with open(path, "w") as handle:
                handle.write('{"entries":{}}\n')
            with self.assertRaises(UsageError):
                read_baseline(path)

    def test_null_entry_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "baseline.json")
            with open(path, "w") as handle:
                handle.write('[null]\n')
            with self.assertRaises(UsageError):
                read_baseline(path)

    def test_non_string_key_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "baseline.json")
            with open(path, "w") as handle:
                handle.write('[{"key":7}]\n')
            with self.assertRaises(UsageError):
                read_baseline(path)

    def test_empty_key_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "baseline.json")
            with open(path, "w") as handle:
                handle.write('[""]\n')
            with self.assertRaises(UsageError):
                read_baseline(path)

    def test_invalid_json_rejected_cleanly(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "baseline.json")
            with open(path, "w") as handle:
                handle.write('{not json')
            with self.assertRaises(SecretSweepError):
                read_baseline(path)

    def test_missing_baseline_rejected_cleanly(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(SecretSweepError):
                read_baseline(os.path.join(root, "missing.json"))

    def test_write_to_missing_directory_rejected_cleanly(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(SecretSweepError):
                write_baseline(os.path.join(root, "missing", "baseline.json"), [])

    def test_apply_baseline_scan_result_preserves_metadata(self):
        result, _token = one_result()
        result.skipped.append({"path": "binary.bin", "reason": "binary"})
        result.scanned_files = 3
        keys = {baseline_key(result.findings[0])}
        filtered = apply_baseline(result, keys)
        self.assertEqual([], filtered.findings)
        self.assertEqual(result.skipped, filtered.skipped)
        self.assertEqual(3, filtered.scanned_files)

    def test_apply_baseline_none_returns_input(self):
        result, _token = one_result()
        self.assertIs(result, apply_baseline(result, None))


class TerminalOutputTests(unittest.TestCase):
    def test_clean_terminal_message(self):
        self.assertEqual("pysecretsweep: no secrets found\n", format_terminal([]))

    def test_terminal_contains_redacted_and_short_hash(self):
        result, token = one_result()
        output = format_terminal(result)
        self.assertIn("pysecretsweep: 1 potential secret found", output)
        self.assertIn(result.findings[0].redacted, output)
        self.assertIn(result.findings[0].fingerprint[:12], output)
        self.assertNotIn(token, output)
        self.assertNotIn(result.findings[0].fingerprint[12:], output)

    def test_terminal_escapes_control_characters_in_filename(self):
        finding = Finding(
            detector="github-pat", provider="GitHub", name="token", severity="high",
            file="bad\x1b[2j\nname.txt", line=1, column=1, redacted="****", fingerprint="a" * 64,
        )
        output = format_terminal([finding])
        self.assertNotIn("\x1b", output)
        self.assertNotIn("bad\x1b[2j\nname.txt", output)
        self.assertIn("\\x1b", output)
        self.assertIn("\\n", output)

    def test_terminal_escapes_custom_provider_control_characters(self):
        finding = Finding(
            detector="x", provider="bad\x1bprovider", name="x", severity="high",
            file="a", line=1, column=1, redacted="****", fingerprint="a" * 64,
        )
        self.assertNotIn("\x1b", format_terminal([finding]))


class JsonOutputTests(unittest.TestCase):
    def test_json_shape(self):
        result, _token = one_result()
        payload = json.loads(format_json(result))
        self.assertEqual("pysecretsweep", payload["tool"])
        self.assertEqual(pysecretsweep.VERSION, payload["version"])
        self.assertEqual(1, payload["count"])
        self.assertEqual(1, len(payload["findings"]))

    def test_json_includes_skipped_when_supplied(self):
        payload = json.loads(format_json([], skipped=[{"path": "x", "reason": "binary"}]))
        self.assertEqual("binary", payload["skipped"][0]["reason"])

    def test_json_scan_result_includes_skipped_automatically(self):
        result = ScanResult(skipped=[{"path": "x", "reason": "binary"}])
        payload = json.loads(format_json(result))
        self.assertEqual("binary", payload["skipped"][0]["reason"])

    def test_json_has_no_raw_secret(self):
        result, token = one_result()
        self.assertNotIn(token, format_json(result))


class SarifOutputTests(unittest.TestCase):
    def test_sarif_version_and_schema(self):
        payload = json.loads(format_sarif([]))
        self.assertEqual("2.1.0", payload["version"])
        self.assertEqual("https://json.schemastore.org/sarif-2.1.0.json", payload["$schema"])
        self.assertIn("runs", payload)

    def test_sarif_driver_rules(self):
        result, _token = one_result()
        payload = json.loads(format_sarif(result))
        driver = payload["runs"][0]["tool"]["driver"]
        self.assertEqual("pysecretsweep", driver["name"])
        self.assertEqual("github-pat", driver["rules"][0]["id"])
        self.assertIn("security", driver["rules"][0]["properties"]["tags"])

    def test_sarif_result_location_and_fingerprint(self):
        result, token = one_result()
        payload = json.loads(format_sarif(result))
        item = payload["runs"][0]["results"][0]
        self.assertEqual("github-pat", item["ruleId"])
        self.assertEqual(s.fp(token), item["partialFingerprints"]["pysecretsweepFingerprint"])
        location = item["locations"][0]["physicalLocation"]
        self.assertEqual("a.txt", location["artifactLocation"]["uri"])
        self.assertEqual(1, location["region"]["startLine"])
        self.assertEqual(1, location["region"]["startColumn"])

    def test_sarif_contains_no_raw_secret(self):
        result, token = one_result()
        self.assertNotIn(token, format_sarif(result))

    def test_sarif_rules_are_sorted(self):
        first = scan_text(s.github_pat(), filename="a", detectors=["github-pat"]).findings[0]
        second = scan_text(s.jwt_token(), filename="a", detectors=["jwt-in-config"]).findings[0]
        payload = json.loads(format_sarif([first, second]))
        ids = [rule["id"] for rule in payload["runs"][0]["tool"]["driver"]["rules"]]
        self.assertEqual(sorted(ids), ids)

    def test_sarif_levels(self):
        high = scan_text(s.github_pat(), filename="a", detectors=["github-pat"]).findings[0]
        medium = scan_text(s.jwt_token(), filename="a", detectors=["jwt-in-config"]).findings[0]
        payload = json.loads(format_sarif([high, medium]))
        levels = {item["ruleId"]: item["level"] for item in payload["runs"][0]["results"]}
        self.assertEqual("error", levels["github-pat"])
        self.assertEqual("warning", levels["jwt-in-config"])


class ArtifactUriMatrixTests(unittest.TestCase):
    pass


URI_CASES = [
    (USERS_PREFIX + "example/repo/secret.txt", "secret.txt"),
    ("/home/example/repo/a b.txt", "a%20b.txt"),
    ("C:/" + "Users" + "/example/secret.txt", "secret.txt"),
    ("dir/../secret.txt", "secret.txt"),
    ("./secret.txt", "secret.txt"),
    ("../../secret.txt", "secret.txt"),
    ("dir/file name.txt", "dir/file%20name.txt"),
    ("dir\\file.txt", "dir/file.txt"),
    ("<stdin>", "stdin"),
    ("", "stdin"),
    ("dir/100%.txt", "dir/100%25.txt"),
    ("dir/plus+at@.txt", "dir/plus%2Bat%40.txt"),
]


def make_uri_case(value, expected):
    def test(self):
        self.assertEqual(expected, sarif_artifact_uri(value))
    return test


for index, (VALUE, EXPECTED) in enumerate(URI_CASES):
    setattr(ArtifactUriMatrixTests, "test_uri_{:02d}".format(index), make_uri_case(VALUE, EXPECTED))


class SortAndFormatTests(unittest.TestCase):
    def test_sort_findings_orders_file_line_column(self):
        def finding(file, line, column):
            return Finding("d", "p", "n", "high", file, line, column, "****", "a" * 64)
        values = [finding("b", 1, 1), finding("a", 2, 1), finding("a", 1, 3), finding("a", 1, 2)]
        ordered = sort_findings(values)
        self.assertEqual([("a", 1, 2), ("a", 1, 3), ("a", 2, 1), ("b", 1, 1)], [(x.file, x.line, x.column) for x in ordered])

    def test_format_output_dispatches_text(self):
        self.assertEqual(format_terminal([]), format_output([], "text"))

    def test_format_output_dispatches_json(self):
        self.assertEqual(format_json([]), format_output([], "json"))

    def test_format_output_dispatches_sarif(self):
        self.assertEqual(format_sarif([]), format_output([], "sarif"))

    def test_unknown_output_format_rejected(self):
        with self.assertRaises(ValueError):
            format_output([], "xml")
