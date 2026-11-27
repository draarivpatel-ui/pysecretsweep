import unittest

import _support as s
import pysecretsweep
from pysecretsweep import (
    DetectorError,
    UsageError,
    analyze_pattern,
    fingerprint,
    is_placeholder,
    mask_value,
    scan_text,
    shannon_entropy,
)


class ScanTextStructureTests(unittest.TestCase):
    def test_returns_scan_result(self):
        result = scan_text("plain text")
        self.assertEqual([], result.findings)
        self.assertEqual([], result.skipped)
        self.assertEqual(1, result.scanned_files)
        self.assertFalse(result)

    def test_scan_result_is_iterable(self):
        token = s.github_pat()
        result = scan_text(token)
        self.assertEqual([result.findings[0]], list(result))
        self.assertEqual(1, len(result))
        self.assertTrue(result)

    def test_filename_is_attached(self):
        result = scan_text(s.github_pat(), filename="config.py")
        self.assertEqual("config.py", result.findings[0].file)

    def test_line_and_column_for_second_line(self):
        token = s.github_pat()
        result = scan_text("first\nxx=" + token, detectors=["github-pat"])
        self.assertEqual(2, result.findings[0].line)
        self.assertEqual(4, result.findings[0].column)

    def test_column_after_crlf(self):
        token = s.github_pat()
        result = scan_text("first\r\nxx=" + token, detectors=["github-pat"])
        self.assertEqual(2, result.findings[0].line)
        self.assertEqual(4, result.findings[0].column)

    def test_multiple_lines_have_independent_positions(self):
        first = s.github_pat()
        second = s.cat("g", "h", "p_") + "Q" + s.seeded(35)
        result = scan_text(first + "\nxxxx=" + second, detectors=["github-pat"])
        self.assertEqual([1, 2], [finding.line for finding in result.findings])
        self.assertEqual([1, 6], [finding.column for finding in result.findings])

    def test_cr_only_line_endings_have_correct_positions(self):
        token = s.github_pat()
        result = scan_text("first\rxx=" + token, detectors=["github-pat"])
        self.assertEqual(2, result.findings[0].line)
        self.assertEqual(4, result.findings[0].column)

    def test_crlf_remains_one_line_ending(self):
        token = s.github_pat()
        result = scan_text("first\r\nxx=" + token, detectors=["github-pat"])
        self.assertEqual(2, result.findings[0].line)
        self.assertEqual(4, result.findings[0].column)

    def test_non_string_input_rejected(self):
        with self.assertRaises(TypeError):
            scan_text(b"bytes")

    def test_unknown_detector_rejected(self):
        with self.assertRaises(UsageError):
            scan_text("text", detectors=["not-a-detector"])

    def test_empty_detector_selection_rejected(self):
        with self.assertRaises(UsageError):
            scan_text("text", detectors=[])

    def test_unknown_severity_rejected(self):
        with self.assertRaises(UsageError):
            scan_text("text", severity="urgent")

    def test_severity_high_excludes_medium(self):
        result = scan_text(s.jwt_token(), severity="high")
        self.assertEqual([], result.findings)

    def test_severity_medium_includes_medium(self):
        result = scan_text(s.jwt_token(), severity="medium")
        self.assertEqual(1, len(result.findings))

    def test_severity_critical_includes_critical(self):
        result = scan_text(s.openai_key(), severity="critical")
        self.assertEqual(1, len(result.findings))

    def test_severity_critical_excludes_high(self):
        result = scan_text(s.github_pat(), severity="critical")
        self.assertEqual([], result.findings)

    def test_detector_selection_limits_scanning(self):
        text = s.github_pat() + "\n" + s.jwt_token()
        result = scan_text(text, detectors=["jwt-in-config"])
        self.assertEqual(["jwt-in-config"], [finding.detector for finding in result.findings])

    def test_detector_object_selection_is_accepted(self):
        detector = pysecretsweep.get_detector("github-pat")
        result = scan_text(s.github_pat(), detectors=[detector])
        self.assertEqual(1, len(result.findings))

    def test_duplicate_detector_selection_is_stable(self):
        result = scan_text(s.github_pat(), detectors=["github-pat", "github-pat"])
        self.assertEqual(1, len(result.findings))


class InlineSuppressionTests(unittest.TestCase):
    def secret_line(self, marker=""):
        return 'api_token = "{}" {}'.format(s.high_entropy_value(44), marker)

    def test_hash_ignore_suppresses_same_line(self):
        result = scan_text(self.secret_line("# secretsweep:ignore"), detectors=["generic-secret-assignment"])
        self.assertEqual([], result.findings)

    def test_slash_ignore_suppresses_same_line(self):
        result = scan_text(self.secret_line("// secretsweep:ignore"), detectors=["generic-secret-assignment"])
        self.assertEqual([], result.findings)

    def test_block_comment_ignore_suppresses_same_line(self):
        result = scan_text(self.secret_line("/* secretsweep:ignore */"), detectors=["generic-secret-assignment"])
        self.assertEqual([], result.findings)

    def test_scoped_ignore_suppresses_named_detector(self):
        result = scan_text(
            self.secret_line("# secretsweep:ignore generic-secret-assignment"),
            detectors=["generic-secret-assignment"],
        )
        self.assertEqual([], result.findings)

    def test_scoped_ignore_does_not_suppress_other_detector(self):
        result = scan_text(
            self.secret_line("# secretsweep:ignore github-pat"),
            detectors=["generic-secret-assignment"],
        )
        self.assertEqual(1, len(result.findings))

    def test_comma_scoped_ignore_suppresses_named_detector(self):
        result = scan_text(
            self.secret_line("# secretsweep:ignore github-pat,generic-secret-assignment"),
            detectors=["generic-secret-assignment"],
        )
        self.assertEqual([], result.findings)

    def test_equals_scoped_ignore_is_accepted(self):
        result = scan_text(
            self.secret_line("# secretsweep:ignore = generic-secret-assignment"),
            detectors=["generic-secret-assignment"],
        )
        self.assertEqual([], result.findings)

    def test_ignore_on_previous_line_does_not_suppress(self):
        text = "# secretsweep:ignore\n" + self.secret_line()
        result = scan_text(text, detectors=["generic-secret-assignment"])
        self.assertEqual(1, len(result.findings))

    def test_ignore_on_next_line_does_not_suppress(self):
        text = self.secret_line() + "\n# secretsweep:ignore"
        result = scan_text(text, detectors=["generic-secret-assignment"])
        self.assertEqual(1, len(result.findings))

    def test_ignore_comments_false_disables_suppression(self):
        result = scan_text(
            self.secret_line("# secretsweep:ignore"),
            detectors=["generic-secret-assignment"],
            ignore_comments=False,
        )
        self.assertEqual(1, len(result.findings))

    def test_suppression_does_not_affect_other_line(self):
        suppressed = self.secret_line("# secretsweep:ignore")
        visible = self.secret_line()
        result = scan_text(suppressed + "\n" + visible, detectors=["generic-secret-assignment"])
        self.assertEqual(1, len(result.findings))
        self.assertEqual(2, result.findings[0].line)


class PlaceholderMatrixTests(unittest.TestCase):
    pass


PLACEHOLDERS = [
    "example", "sample", "placeholder", "changeme", "change_me", "yourapikey",
    "yourtoken", "yoursecret", "dummy", "fake", "test", "testing", "redacted",
    "replaceme", "none", "null", "undefined", "todo", "tbd", "xxxx", "abc123",
    "password", "foo", "bar", "zzzzzzzz", "abcdefghij", "<token>", "${TOKEN}",
    "token here", "notarealkey", "masked", "hidden",
]


def make_placeholder_test(value):
    def test(self):
        self.assertTrue(is_placeholder(value), value)
    return test


for index, VALUE in enumerate(PLACEHOLDERS):
    setattr(PlaceholderMatrixTests, "test_placeholder_{:02d}".format(index), make_placeholder_test(VALUE))


class PlaceholderBehaviorTests(unittest.TestCase):
    def test_template_assignment_is_suppressed(self):
        result = scan_text('api_token = "${TOKEN_VALUE}"', detectors=["generic-secret-assignment"])
        self.assertEqual([], result.findings)

    def test_exact_example_assignment_is_suppressed(self):
        result = scan_text('api_token = "passwordZx7Q"', detectors=["generic-secret-assignment"])
        self.assertEqual([], result.findings)

    def test_repeated_character_assignment_is_suppressed(self):
        result = scan_text('api_token = "zzzzzzzzzzzzzzzz"', detectors=["generic-secret-assignment"])
        self.assertEqual([], result.findings)

    def test_high_entropy_value_is_not_placeholder(self):
        value = s.high_entropy_value(44)
        self.assertFalse(is_placeholder(value))

    def test_long_random_value_is_not_placeholder(self):
        self.assertFalse(is_placeholder(s.high_entropy_value(260)))


    def test_brace_inside_high_entropy_value_is_not_placeholder(self):
        value = "Zx7{9Lm2Vp4Rs8"
        self.assertFalse(is_placeholder(value))
        result = scan_text('api_token = "{}"'.format(value), detectors=["generic-secret-assignment"])
        self.assertEqual(1, len(result.findings))

    def test_allow_placeholder_disables_filter(self):
        result = scan_text(
            'api_token = "${TOKEN_VALUE}"',
            detectors=["generic-secret-assignment"],
            allow_placeholder=True,
        )
        self.assertEqual(1, len(result.findings))


class UtilityTests(unittest.TestCase):
    def test_short_mask_is_fully_masked(self):
        self.assertEqual("********", mask_value("abcdefgh"))

    def test_sixteen_character_mask_is_fully_masked(self):
        self.assertEqual("*" * 16, mask_value("a" * 16))

    def test_medium_mask_is_fully_masked(self):
        value = "abcdefghijklmnopqrstu"
        masked = mask_value(value)
        self.assertEqual("*" * len(value), masked)
        self.assertNotIn("ab", masked)
        self.assertNotIn("tu", masked)

    def test_long_mask_exposes_four_edge_characters(self):
        value = s.high_entropy_value(48)
        masked = mask_value(value)
        self.assertTrue(masked.startswith(value[:4]))
        self.assertTrue(masked.endswith(value[-4:]))
        self.assertLessEqual(8, len(value) // 4)

    def test_mask_never_exposes_more_than_quarter_long_value(self):
        value = s.high_entropy_value(100)
        masked = mask_value(value)
        exposed = value[:4] + value[-4:]
        self.assertEqual(8, len(exposed))
        self.assertLessEqual(len(exposed), len(value) // 4)
        self.assertNotIn(value[8:-8], masked)

    def test_fingerprint_is_sha256(self):
        self.assertEqual(64, len(fingerprint("abc")))
        self.assertEqual(fingerprint("abc"), fingerprint("abc"))

    def test_entropy_empty_is_zero(self):
        self.assertEqual(0.0, shannon_entropy(""))

    def test_entropy_repeated_is_zero(self):
        self.assertEqual(0.0, shannon_entropy("aaaa"))

    def test_entropy_high_for_varied_text(self):
        self.assertGreater(shannon_entropy(s.high_entropy_value(64)), 4.0)


class PatternLintTests(unittest.TestCase):
    def test_safe_simple_pattern(self):
        self.assertTrue(analyze_pattern(r"\babc[A-Z0-9]{8}\b")["safe"])

    def test_nested_repeat_rejected(self):
        report = analyze_pattern(r"(a+)+")
        self.assertFalse(report["safe"])
        self.assertIn("repeated group containing a repeat", report["reasons"])

    def test_backreference_rejected(self):
        report = analyze_pattern(r"(a)\1")
        self.assertFalse(report["safe"])
        self.assertIn("backreference", report["reasons"])

    def test_named_backreference_rejected(self):
        report = analyze_pattern(r"(?P<x>a)(?P=x)")
        self.assertFalse(report["safe"])
        self.assertIn("backreference", report["reasons"])

    def test_lookbehind_rejected(self):
        report = analyze_pattern(r"(?<=abc)token")
        self.assertFalse(report["safe"])
        self.assertIn("lookbehind", report["reasons"])

    def test_stacked_quantifier_rejected(self):
        report = analyze_pattern(r"a**")
        self.assertFalse(report["safe"])

    def test_overlong_pattern_rejected(self):
        report = analyze_pattern("a" * 4100)
        self.assertFalse(report["safe"])
        self.assertIn("pattern too long", report["reasons"])

    def test_repeatable_alternation_rejected(self):
        for pattern in (r"(a|aa)+$", r"(?:a|aa)+$", r"(?i)(a|aa)+$"):
            report = analyze_pattern(pattern)
            self.assertFalse(report["safe"])
            self.assertIn("repeated group containing alternation", report["reasons"])

    def test_ambiguous_adjacent_character_repeats_rejected(self):
        report = analyze_pattern(r"[a-z]+[a-z]+$")
        self.assertFalse(report["safe"])
        self.assertIn("ambiguous adjacent repeats", report["reasons"])

    def test_disjoint_adjacent_repeats_allowed(self):
        self.assertTrue(analyze_pattern(r"\s*[\"']?")["safe"])
        self.assertTrue(analyze_pattern(r"\s+[^\s]+")["safe"])

    def test_large_repeat_rejected(self):
        report = analyze_pattern(r"a{2000}")
        self.assertFalse(report["safe"])
        self.assertIn("large repeat", report["reasons"])

    def test_all_builtin_patterns_pass_lint(self):
        import pysecretsweep.detectors as detector_module

        checked = 0
        for metadata in detector_module.list_detectors():
            detector = detector_module.get_detector(metadata["id"])
            if detector.pattern is not None:
                self.assertTrue(analyze_pattern(detector.pattern)["safe"], metadata["id"])
                checked += 1
        self.assertGreaterEqual(checked, 30)


class CustomDetectorTests(unittest.TestCase):
    def tearDown(self):
        pysecretsweep.unregister_detector("custom-test-token")
        pysecretsweep.unregister_detector("custom-bad-error")

    def test_register_pattern_detector(self):
        pysecretsweep.create_pattern_detector(
            id="custom-test-token",
            provider="Custom",
            name="Custom token",
            severity="low",
            pattern=r"\bcustom_[A-Za-z0-9]{8}\b",
        )
        result = scan_text("custom_Zx7Qa9Lm", detectors=["custom-test-token"])
        self.assertEqual(1, len(result.findings))
        self.assertEqual("low", result.findings[0].severity)

    def test_duplicate_registration_rejected(self):
        pysecretsweep.create_pattern_detector(
            id="custom-test-token", pattern=r"abc", check=None,
        ) if False else None
        with self.assertRaises(UsageError):
            pysecretsweep.register_detector(id="github-pat", check=lambda text: [])

    def test_invalid_id_rejected(self):
        with self.assertRaises(UsageError):
            pysecretsweep.register_detector(id="Bad_ID", check=lambda text: [])

    def test_invalid_severity_rejected(self):
        with self.assertRaises(UsageError):
            pysecretsweep.register_detector(id="custom-test-token", severity="urgent", check=lambda text: [])

    def test_missing_check_rejected(self):
        with self.assertRaises(UsageError):
            pysecretsweep.register_detector(id="custom-test-token")


    def test_invalid_capture_group_rejected(self):
        with self.assertRaises(UsageError):
            pysecretsweep.create_pattern_detector(id="custom-test-token", pattern=r"abc", value_group=1)

    def test_redos_pattern_rejected(self):
        with self.assertRaises(ValueError):
            pysecretsweep.create_pattern_detector(id="custom-test-token", pattern=r"(a+)+")

    def test_invalid_regex_rejected(self):
        with self.assertRaises(UsageError):
            pysecretsweep.create_pattern_detector(id="custom-test-token", pattern=r"(unclosed")

    def test_custom_detector_error_is_sanitized(self):
        secret = s.github_pat()

        def broken(text):
            raise ValueError("raw input was {}".format(text))

        pysecretsweep.register_detector(id="custom-bad-error", check=broken)
        with self.assertRaises(DetectorError) as caught:
            scan_text(secret, detectors=["custom-bad-error"])
        self.assertNotIn(secret, str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)

    def test_custom_hit_without_index_falls_back_to_find(self):
        pysecretsweep.register_detector(
            id="custom-test-token",
            check=lambda text: [{"value": "needle"}],
        )
        result = scan_text("aa needle", detectors=["custom-test-token"])
        self.assertEqual(4, result.findings[0].column)


class PerformanceShapeTests(unittest.TestCase):
    def test_100kb_single_line_scans_linear_shape(self):
        token = s.github_pat()
        text = "x" * 99999 + "=" + token
        result = scan_text(text, detectors=["github-pat"])
        self.assertEqual(1, len(result.findings))
        self.assertEqual(100001, result.findings[0].column)

    def test_unterminated_pem_flood_completes(self):
        begin = s.cat("-----", "BEGIN ", "PRIVATE KEY", "-----")
        text = (begin + "\n") * 3000
        result = scan_text(text, detectors=["pem-private-key"])
        self.assertEqual([], result.findings)

    def test_scheme_like_input_flood_completes(self):
        text = "postgres" + "x" * 120000 + "://"
        result = scan_text(text, detectors=["db-uri-password"])
        self.assertEqual([], result.findings)

    def test_dense_findings_on_one_line_are_all_reported(self):
        tokens = []
        for index in range(120):
            tokens.append(s.cat("g", "h", "p_") + "{:03d}".format(index) + s.seeded(33))
        result = scan_text(" ".join(tokens), detectors=["github-pat"])
        self.assertEqual(120, len(result.findings))

    def test_dense_findings_remain_ordered_by_column(self):
        tokens = [s.cat("g", "h", "p_") + "{:03d}".format(index) + s.seeded(33) for index in range(30)]
        result = scan_text(" ".join(tokens), detectors=["github-pat"])
        columns = [finding.column for finding in result.findings]
        self.assertEqual(sorted(columns), columns)

    def test_repeated_decoys_do_not_hide_unique_late_secret(self):
        first = s.github_pat()
        late = s.cat("g", "h", "p_") + "Z" + s.seeded(35)
        text = "\n".join([first] * 1000 + [late])
        result = scan_text(text, detectors=["github-pat"])
        self.assertEqual(s.fp(late), result.findings[-1].fingerprint)
