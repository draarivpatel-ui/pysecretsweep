import unittest

import _support as s
from pysecretsweep import scan_diff


def make_diff(path, body, old_path=None, start=1):
    old_path = path if old_path is None else old_path
    return (
        "diff --git a/{} b/{}\n".format(old_path, path)
        + "--- a/{}\n".format(old_path)
        + "+++ b/{}\n".format(path)
        + "@@ -1,1 +{},1 @@ optional function text\n".format(start)
        + body
    )


class DiffParserTests(unittest.TestCase):
    def test_empty_diff_is_clean(self):
        result = scan_diff("")
        self.assertEqual([], result.findings)

    def test_non_string_rejected(self):
        with self.assertRaises(TypeError):
            scan_diff(b"diff")

    def test_basic_added_line_is_scanned(self):
        token = s.github_pat()
        result = scan_diff(make_diff("a.py", '+token = "{}"\n'.format(token)), detectors=["github-pat"])
        self.assertEqual(1, len(result.findings))
        self.assertEqual("a.py", result.findings[0].file)
        self.assertEqual(1, result.findings[0].line)

    def test_hunk_start_line_is_respected(self):
        token = s.github_pat()
        result = scan_diff(make_diff("a.py", '+token = "{}"\n'.format(token), start=42), detectors=["github-pat"])
        self.assertEqual(42, result.findings[0].line)

    def test_column_points_inside_added_line(self):
        token = s.github_pat()
        added = 'xxtoken = "{}"'.format(token)
        result = scan_diff(make_diff("a.py", "+" + added + "\n"), detectors=["github-pat"])
        self.assertEqual(added.index(token) + 1, result.findings[0].column)

    def test_context_line_increments_new_line_number(self):
        token = s.github_pat()
        body = " context\n" + '+token = "{}"\n'.format(token)
        result = scan_diff(make_diff("a.py", body), detectors=["github-pat"])
        self.assertEqual(2, result.findings[0].line)

    def test_removed_line_does_not_increment_new_line_number(self):
        token = s.github_pat()
        body = " context\n-removed\n" + '+token = "{}"\n'.format(token)
        result = scan_diff(make_diff("a.py", body), detectors=["github-pat"])
        self.assertEqual(2, result.findings[0].line)

    def test_removed_secret_is_not_scanned(self):
        token = s.github_pat()
        result = scan_diff(make_diff("a.py", '-token = "{}"\n'.format(token)), detectors=["github-pat"])
        self.assertEqual([], result.findings)

    def test_context_secret_is_not_scanned(self):
        token = s.github_pat()
        result = scan_diff(make_diff("a.py", ' token = "{}"\n'.format(token)), detectors=["github-pat"])
        self.assertEqual([], result.findings)

    def test_metadata_secret_is_not_scanned(self):
        token = s.github_pat()
        diff = "diff --git a/a.py b/a.py\nindex {}..{} 100644\n".format(token, token)
        result = scan_diff(diff, detectors=["github-pat"])
        self.assertEqual([], result.findings)

    def test_multiple_hunks_have_independent_line_numbers(self):
        first = s.github_pat()
        second = s.cat("g", "h", "p_") + "Z" + s.seeded(35)
        diff = (
            "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n"
            "@@ -1,1 +10,1 @@\n+x = \"{}\"\n".format(first)
            + "@@ -20,1 +30,1 @@\n+y = \"{}\"\n".format(second)
        )
        result = scan_diff(diff, detectors=["github-pat"])
        self.assertEqual([10, 30], [finding.line for finding in result.findings])

    def test_multiple_files_have_correct_names(self):
        first = s.github_pat()
        second = s.cat("g", "h", "p_") + "Q" + s.seeded(35)
        diff = make_diff("one.py", "+{}\n".format(first)) + make_diff("two.py", "+{}\n".format(second))
        result = scan_diff(diff, detectors=["github-pat"])
        self.assertEqual(["one.py", "two.py"], [finding.file for finding in result.findings])

    def test_filename_with_spaces(self):
        token = s.github_pat()
        result = scan_diff(make_diff("dir/file with spaces.py", "+{}\n".format(token)), detectors=["github-pat"])
        self.assertEqual("dir/file with spaces.py", result.findings[0].file)

    def test_filename_with_marker_like_text(self):
        token = s.github_pat()
        path = "diff --git strange.py"
        result = scan_diff(make_diff(path, "+{}\n".format(token)), detectors=["github-pat"])
        self.assertEqual(path, result.findings[0].file)

    def test_tab_metadata_is_not_part_of_filename(self):
        token = s.github_pat()
        diff = (
            "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\t2026-01-01\n"
            "@@ -1,1 +1,1 @@\n+{}\n".format(token)
        )
        result = scan_diff(diff, detectors=["github-pat"])
        self.assertEqual("a.py", result.findings[0].file)

    def test_quoted_octal_filename_is_decoded(self):
        token = s.github_pat()
        raw_path = '"dir/file\\040name.py"'
        diff = (
            "diff --git a/x b/x\n--- a/x\n+++ b/" + raw_path + "\n"
            "@@ -1,1 +1,1 @@\n+{}\n".format(token)
        )
        result = scan_diff(diff, detectors=["github-pat"])
        self.assertEqual("dir/file name.py", result.findings[0].file)

    def test_added_content_beginning_with_plus_plus_is_content(self):
        token = s.github_pat()
        body = "++prefix\n+{}\n".format(token)
        result = scan_diff(make_diff("a.py", body), detectors=["github-pat"])
        self.assertEqual(2, result.findings[0].line)
        self.assertEqual("a.py", result.findings[0].file)

    def test_dev_null_does_not_retain_prior_filename(self):
        token = s.github_pat()
        diff = (
            make_diff("first.py", "+{}\n".format(token))
            + "diff --git a/deleted.py b/deleted.py\n--- a/deleted.py\n+++ /dev/null\n"
            + "@@ -1,1 +0,0 @@\n-{}\n".format(token)
        )
        result = scan_diff(diff, detectors=["github-pat"])
        self.assertEqual(1, len(result.findings))
        self.assertEqual("first.py", result.findings[0].file)

    def test_additions_to_dev_null_are_not_scanned(self):
        token = s.github_pat()
        diff = (
            "diff --git a/a.py b/a.py\n--- a/a.py\n+++ /dev/null\n"
            "@@ -1,1 +1,1 @@\n+{}\n".format(token)
        )
        result = scan_diff(diff, detectors=["github-pat"])
        self.assertEqual([], result.findings)

    def test_crlf_diff_is_scanned(self):
        token = s.github_pat()
        diff = make_diff("a.py", "+{}\n".format(token)).replace("\n", "\r\n")
        result = scan_diff(diff, detectors=["github-pat"])
        self.assertEqual(1, len(result.findings))

    def test_no_newline_marker_does_not_increment_line(self):
        token = s.github_pat()
        body = "+first\n\\ No newline at end of file\n+{}\n".format(token)
        result = scan_diff(make_diff("a.py", body), detectors=["github-pat"])
        self.assertEqual(2, result.findings[0].line)

    def test_consecutive_added_pem_lines_are_joined(self):
        pem = s.pem_private_key()
        body = "".join("+" + line + "\n" for line in pem.splitlines())
        result = scan_diff(make_diff("key.txt", body), detectors=["pem-private-key"])
        self.assertEqual(1, len(result.findings))
        self.assertEqual(1, result.findings[0].line)

    def test_context_line_separates_partial_pem_blocks(self):
        pem = s.pem_private_key()
        lines = pem.splitlines()
        body = "+" + lines[0] + "\n context\n" + "\n".join("+" + line for line in lines[1:]) + "\n"
        result = scan_diff(make_diff("key.txt", body), detectors=["pem-private-key"])
        self.assertEqual([], result.findings)

    def test_inline_ignore_is_honored_in_diff(self):
        token = s.github_pat()
        body = '+token = "{}"  # secretsweep:ignore github-pat\n'.format(token)
        result = scan_diff(make_diff("a.py", body), detectors=["github-pat"])
        self.assertEqual([], result.findings)

    def test_detector_selection_is_honored_in_diff(self):
        token = s.github_pat()
        result = scan_diff(make_diff("a.py", "+{}\n".format(token)), detectors=["jwt-in-config"])
        self.assertEqual([], result.findings)

    def test_severity_is_honored_in_diff(self):
        token = s.github_pat()
        result = scan_diff(make_diff("a.py", "+{}\n".format(token)), severity="critical")
        self.assertEqual([], result.findings)

    def test_hunk_without_space_after_at_signs(self):
        token = s.github_pat()
        diff = (
            "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n"
            "@@ -1 +7 @@ def f\n+{}\n".format(token)
        )
        result = scan_diff(diff, detectors=["github-pat"])
        self.assertEqual(7, result.findings[0].line)

    def test_second_hunk_flushes_first_block(self):
        first = s.github_pat()
        second = s.cat("g", "h", "p_") + "Q" + s.seeded(35)
        diff = (
            "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n"
            "@@ -1 +2 @@\n+{}\n".format(first)
            + "@@ -1 +9 @@\n+{}\n".format(second)
        )
        result = scan_diff(diff, detectors=["github-pat"])
        self.assertEqual([2, 9], [finding.line for finding in result.findings])

    def test_malformed_metadata_line_exits_hunk_safely(self):
        token = s.github_pat()
        diff = make_diff("a.py", "+{}\n".format(token)) + "not diff metadata\n"
        result = scan_diff(diff, detectors=["github-pat"])
        self.assertEqual(1, len(result.findings))

    def test_diff_result_has_no_scanned_file_count(self):
        token = s.github_pat()
        result = scan_diff(make_diff("a.py", "+{}\n".format(token)), detectors=["github-pat"])
        self.assertEqual(0, result.scanned_files)
