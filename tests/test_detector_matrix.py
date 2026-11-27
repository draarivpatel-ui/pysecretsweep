import json
import unittest

import _support as s
from pysecretsweep import format_json, format_sarif, format_terminal, scan_text


def simple(builder):
    def make():
        value = builder()
        return value, value
    return make


def assignment(name, value_builder, uppercase=False):
    def make():
        value = value_builder()
        key = name.upper() if uppercase else name
        return '{} = "{}"'.format(key, value), value
    return make


def datadog_case():
    value = s.hex32()
    return 'DATADOG="{}"'.format(value), value


def database_case():
    return s.db_uri()


CASES = [
    {"id": "aws-access-key-id", "make": simple(s.aws_access_key)},
    {"id": "aws-secret-access-key", "make": assignment("aws_secret_access_key", s.aws_secret_value, uppercase=True)},
    {"id": "github-pat", "make": simple(s.github_pat)},
    {"id": "github-fine-grained-pat", "make": simple(s.github_fine_pat)},
    {"id": "github-oauth-token", "make": simple(s.github_oauth)},
    {"id": "stripe-secret-key", "make": simple(s.stripe_secret)},
    {"id": "stripe-restricted-key", "make": simple(s.stripe_restricted)},
    {"id": "stripe-publishable-key", "make": simple(s.stripe_publishable)},
    {"id": "slack-webhook", "make": simple(s.slack_webhook)},
    {"id": "slack-token", "make": simple(s.slack_token)},
    {"id": "google-api-key", "make": simple(s.google_api_key)},
    {"id": "google-oauth-client-secret", "make": simple(s.google_client_secret)},
    {"id": "google-refresh-token", "make": simple(s.google_refresh_token)},
    {"id": "openai-api-key", "make": simple(s.openai_key)},
    {"id": "anthropic-api-key", "make": simple(s.anthropic_key)},
    {"id": "huggingface-token", "make": simple(s.huggingface_token)},
    {"id": "npm-token", "make": simple(s.npm_token)},
    {"id": "pypi-token", "make": simple(s.pypi_token)},
    {"id": "docker-token", "make": simple(s.docker_token)},
    {"id": "twilio-api-key", "make": simple(s.twilio_key)},
    {"id": "sendgrid-api-key", "make": simple(s.sendgrid_key)},
    {"id": "discord-bot-token", "make": simple(s.discord_token)},
    {"id": "telegram-bot-token", "make": simple(s.telegram_token)},
    {"id": "mailgun-api-key", "make": simple(s.mailgun_key)},
    {"id": "mailchimp-api-key", "make": simple(s.mailchimp_key)},
    {"id": "square-access-token", "make": simple(s.square_token)},
    {"id": "datadog-api-key", "make": datadog_case},
    {"id": "new-relic-license-key", "make": assignment("new_relic", lambda: s.seeded(34), uppercase=True)},
    {"id": "sonarqube-token", "make": simple(s.sonarqube_token)},
    {"id": "db-uri-password", "make": database_case},
    {"id": "jwt-in-config", "make": simple(s.jwt_token)},
    {"id": "pem-private-key", "make": simple(s.pem_private_key)},
    {"id": "generic-secret-assignment", "make": assignment("api_token", lambda: s.high_entropy_value(44))},
    {"id": "high-entropy-generic", "make": assignment("value", lambda: s.high_entropy_value(48))},
    {"id": "pii-credit-card", "make": simple(s.formatted_card_number)},
    {"id": "pii-us-ssn", "make": simple(s.ssn_value)},
]


def method_name(prefix, detector_id):
    return "test_{}_{}".format(prefix, detector_id.replace("-", "_"))


class DetectorPositiveTests(unittest.TestCase):
    pass


class DetectorNegativeTests(unittest.TestCase):
    pass


class DetectorRedactionTests(unittest.TestCase):
    pass


def make_positive(case):
    def test(self):
        text, secret = case["make"]()
        result = scan_text(text, detectors=[case["id"]])
        self.assertEqual(1, len(result.findings))
        finding = result.findings[0]
        self.assertEqual(case["id"], finding.detector)
        self.assertEqual(s.fp(secret), finding.fingerprint)
        self.assertNotEqual(secret, finding.redacted)
    return test


def make_negative(case):
    def test(self):
        result = scan_text("ordinary prose without machine credentials\n", detectors=[case["id"]])
        self.assertEqual(0, len(result.findings))
    return test


def make_redaction(case):
    def test(self):
        text, secret = case["make"]()
        result = scan_text(text, detectors=[case["id"]])
        self.assertEqual(1, len(result.findings))
        for rendered in (format_terminal(result), format_json(result), format_sarif(result)):
            self.assertNotIn(secret, rendered)
            self.assertIn(result.findings[0].redacted, rendered)
        payload = json.loads(format_json(result))
        self.assertEqual(s.fp(secret), payload["findings"][0]["fingerprint"])
    return test


for CASE in CASES:
    setattr(DetectorPositiveTests, method_name("positive", CASE["id"]), make_positive(CASE))
    setattr(DetectorNegativeTests, method_name("negative", CASE["id"]), make_negative(CASE))
    setattr(DetectorRedactionTests, method_name("redaction", CASE["id"]), make_redaction(CASE))


class DetectorMatrixShapeTests(unittest.TestCase):
    def test_case_matrix_covers_every_builtin_detector(self):
        import pysecretsweep

        matrix_ids = {case["id"] for case in CASES}
        builtin_ids = {detector["id"] for detector in pysecretsweep.list_detectors()}
        self.assertEqual(builtin_ids, matrix_ids)
        self.assertEqual(36, len(matrix_ids))

    def test_overlapping_openai_and_anthropic_prefers_specific_detector(self):
        result = scan_text(s.anthropic_key())
        self.assertEqual(1, len(result.findings))
        self.assertEqual("anthropic-api-key", result.findings[0].detector)

    def test_capture_group_column_points_at_secret_value(self):
        text, secret = database_case()
        result = scan_text(text, detectors=["db-uri-password"])
        self.assertEqual(text.index(secret) + 1, result.findings[0].column)

    def test_aws_capture_group_column_points_after_assignment(self):
        text, secret = CASES[1]["make"]()
        result = scan_text(text, detectors=["aws-secret-access-key"])
        self.assertEqual(text.index(secret) + 1, result.findings[0].column)

    def test_luhn_rejects_near_card_number(self):
        digits = s.card_number()
        altered = digits[:-1] + ("0" if digits[-1] != "0" else "1")
        result = scan_text(altered, detectors=["pii-credit-card"])
        self.assertEqual(0, len(result.findings))

    def test_ssn_rejects_zero_area(self):
        result = scan_text("000-42-8965", detectors=["pii-us-ssn"])
        self.assertEqual(0, len(result.findings))

    def test_ssn_rejects_zero_group(self):
        result = scan_text("137-00-8965", detectors=["pii-us-ssn"])
        self.assertEqual(0, len(result.findings))

    def test_ssn_rejects_zero_serial(self):
        result = scan_text("137-42-0000", detectors=["pii-us-ssn"])
        self.assertEqual(0, len(result.findings))

    def test_ssn_rejects_666_area(self):
        result = scan_text("666-42-8965", detectors=["pii-us-ssn"])
        self.assertEqual(0, len(result.findings))

    def test_ssn_rejects_900_series(self):
        result = scan_text("900-42-8965", detectors=["pii-us-ssn"])
        self.assertEqual(0, len(result.findings))

    def test_unterminated_pem_does_not_hide_later_key(self):
        broken = s.cat("-----", "BEGIN ", "PRIVATE KEY", "-----") + "\n" + s.urlsafe(30)
        text = broken + "\n" + s.pem_private_key()
        result = scan_text(text, detectors=["pem-private-key"])
        self.assertEqual(1, len(result.findings))

    def test_empty_pem_body_is_not_reported(self):
        begin = s.cat("-----", "BEGIN ", "PRIVATE KEY", "-----")
        end = s.cat("-----", "END ", "PRIVATE KEY", "-----")
        result = scan_text(begin + end, detectors=["pem-private-key"])
        self.assertEqual(0, len(result.findings))

    def test_oversized_pem_body_is_not_reported(self):
        begin = s.cat("-----", "BEGIN ", "PRIVATE KEY", "-----")
        end = s.cat("-----", "END ", "PRIVATE KEY", "-----")
        result = scan_text(begin + s.urlsafe(20001) + end, detectors=["pem-private-key"])
        self.assertEqual(0, len(result.findings))

    def test_no_hit_cap_hides_late_distinct_tokens(self):
        tokens = []
        for index in range(1001):
            suffix = "{:04d}".format(index) + s.seeded(32)
            tokens.append(s.cat("g", "h", "p_") + suffix[:36])
        result = scan_text("\n".join(tokens), detectors=["github-pat"])
        self.assertEqual(1001, len(result.findings))
        self.assertIn(s.fp(tokens[-1]), {finding.fingerprint for finding in result.findings})
