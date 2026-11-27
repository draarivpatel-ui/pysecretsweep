import json
import unittest

import _support as s
import pysecretsweep
from pysecretsweep import format_sarif, scan_diff, scan_text
from pysecretsweep.output import sarif_artifact_uri
from pysecretsweep.util import safe_display


class RegressionTests(unittest.TestCase):
    def tearDown(self):
        pysecretsweep.unregister_detector("custom-full-match")
        pysecretsweep.unregister_detector("custom-capture-match")

    def test_pattern_detector_defaults_to_full_match_even_with_group(self):
        pysecretsweep.create_pattern_detector(
            id="custom-full-match",
            pattern=r"\bcustom-(group)-[0-9]{4}\b",
        )
        result = scan_text("custom-group-1234", detectors=["custom-full-match"])
        self.assertEqual(s.fp("custom-group-1234"), result.findings[0].fingerprint)

    def test_pattern_detector_explicit_capture_group(self):
        pysecretsweep.create_pattern_detector(
            id="custom-capture-match",
            pattern=r"\bcustom-(group)-[0-9]{4}\b",
            value_group=1,
        )
        result = scan_text("custom-group-1234", detectors=["custom-capture-match"])
        self.assertEqual(s.fp("group"), result.findings[0].fingerprint)

    def test_unicode_digits_do_not_count_as_ssn_digits(self):
        value = "137-42-896" + "\u0665"
        result = scan_text(value, detectors=["pii-us-ssn"])
        self.assertEqual([], result.findings)

    def test_unicode_digits_do_not_count_as_card_digits(self):
        value = "4111 1111 1111 111" + "\u0661"
        result = scan_text(value, detectors=["pii-credit-card"])
        self.assertEqual([], result.findings)

    def test_vertical_tab_inside_diff_line_does_not_split_record(self):
        token = s.github_pat()
        diff = (
            "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n"
            "@@ -1 +5 @@\n+prefix\v{}\n".format(token)
        )
        result = scan_diff(diff, detectors=["github-pat"])
        self.assertEqual(1, len(result.findings))
        self.assertEqual(5, result.findings[0].line)

    def test_unicode_quoted_git_path_decodes_utf8_bytes(self):
        token = s.github_pat()
        diff = (
            "diff --git a/x b/x\n--- /dev/null\n+++ \"b/dir/file\\303\\251.py\"\n"
            "@@ -0,0 +3,1 @@\n+{}\n".format(token)
        )
        result = scan_diff(diff, detectors=["github-pat"])
        self.assertEqual("dir/file\u00e9.py", result.findings[0].file)
        self.assertEqual(3, result.findings[0].line)

    def test_surrogateescape_artifact_uri_is_percent_encoded(self):
        uri = sarif_artifact_uri("bad\udcff.txt")
        self.assertEqual("bad%FF.txt", uri)

    def test_safe_display_escapes_surrogates(self):
        rendered = safe_display("bad\udcff")
        self.assertNotIn("\udcff", rendered)
        self.assertIn("\\udcff", rendered)

    def test_safe_display_escapes_bidi_controls(self):
        rendered = safe_display("bad\u202ename")
        self.assertNotIn("\u202e", rendered)
        self.assertIn("\\u202e", rendered)

    def test_pem_with_crlf_is_detected(self):
        pem = s.pem_private_key().replace("\n", "\r\n")
        result = scan_text(pem, detectors=["pem-private-key"])
        self.assertEqual(1, len(result.findings))

    def test_pem_redaction_exposes_only_generic_edge_dashes(self):
        pem = s.pem_private_key()
        result = scan_text(pem, detectors=["pem-private-key"])
        redacted = result.findings[0].redacted
        self.assertTrue(redacted.startswith("----"))
        self.assertTrue(redacted.endswith("----"))
        body = pem.split("\n", 1)[1].rsplit("\n", 1)[0]
        self.assertNotIn(body, redacted)

    def test_sarif_absolute_path_is_reduced(self):
        payload = json.loads(format_sarif(scan_text(s.github_pat(), filename="/" + "Users" + "/example/secret.txt")))
        uri = payload["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        self.assertEqual("secret.txt", uri)
        self.assertNotIn("Users", uri)

    def test_format_sarif_handles_surrogateescape_filename(self):
        result = scan_text(s.github_pat(), filename="bad\udcff.txt", detectors=["github-pat"])
        payload = json.loads(format_sarif(result))
        uri = payload["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        self.assertEqual("bad%FF.txt", uri)

    def test_openai_specific_shape_still_detects_generic_openai(self):
        result = scan_text(s.openai_key())
        self.assertEqual("openai-api-key", result.findings[0].detector)

    def test_github_oauth_prefers_oauth_detector_over_pat(self):
        result = scan_text(s.github_oauth())
        self.assertEqual("github-oauth-token", result.findings[0].detector)

    def test_datadog_uppercase_key_assignment(self):
        text = 'DATADOG="{}"'.format(s.hex32())
        result = scan_text(text, detectors=["datadog-api-key"])
        self.assertEqual(1, len(result.findings))


    def test_datadog_common_api_key_name(self):
        text = 'DD_API_KEY = "{}"'.format(s.hex32())
        result = scan_text(text, detectors=["datadog-api-key"])
        self.assertEqual(1, len(result.findings))

    def test_card_embedded_in_underscore_word_is_not_reported(self):
        result = scan_text("x_" + s.card_number(), detectors=["pii-credit-card"])
        self.assertEqual([], result.findings)

    def test_new_relic_mixed_case_key_assignment(self):
        text = 'New_Relic = "{}"'.format(s.seeded(34))
        result = scan_text(text, detectors=["new-relic-license-key"])
        self.assertEqual(1, len(result.findings))

    def test_aws_uppercase_assignment(self):
        text = 'AWS_SECRET_ACCESS_KEY = "{}"'.format(s.aws_secret_value())
        result = scan_text(text, detectors=["aws-secret-access-key"])
        self.assertEqual(1, len(result.findings))

    def test_database_password_index_inside_url(self):
        uri, password = s.db_uri()
        result = scan_text("prefix " + uri, detectors=["db-uri-password"])
        self.assertEqual(("prefix " + uri).index(password) + 1, result.findings[0].column)

    def test_generic_assignment_low_entropy_is_not_reported(self):
        result = scan_text('api_token = "aaaaaaaaaaaaaaaaaaaaaaaa"', detectors=["generic-secret-assignment"])
        self.assertEqual([], result.findings)

    def test_unlabelled_low_entropy_is_not_reported(self):
        result = scan_text('value = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"', detectors=["high-entropy-generic"])
        self.assertEqual([], result.findings)

    def test_unlabelled_entropy_requires_assignment_context(self):
        result = scan_text("prefix " + s.high_entropy_value(48), detectors=["high-entropy-generic"])
        self.assertEqual([], result.findings)

    def test_database_uri_without_password_is_not_reported(self):
        result = scan_text("postgresql://user@db.example.invalid/app", detectors=["db-uri-password"])
        self.assertEqual([], result.findings)

    def test_short_database_password_is_masked_fully(self):
        uri = "postgresql://user:{}@db.example.invalid/app".format("Zx7")
        result = scan_text(uri, detectors=["db-uri-password"])
        self.assertEqual("***", result.findings[0].redacted)

    def test_control_characters_do_not_reach_terminal_output(self):
        result = scan_text(s.github_pat(), filename="bad\x1bname.txt", detectors=["github-pat"])
        rendered = pysecretsweep.format_terminal(result)
        self.assertNotIn("\x1b", rendered)
        self.assertIn("\\x1b", rendered)
