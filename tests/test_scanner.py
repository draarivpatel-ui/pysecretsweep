import os
import stat
import tempfile
import unittest

from pysecretsweep.scanner import _open_read_flags, _read_regular_file

import _support as s
from pysecretsweep import (
    UsageError,
    SecretSweepError,
    is_binary_path,
    looks_binary,
    scan_path,
    write_baseline,
)


def write_file(path, content):
    mode = "wb" if isinstance(content, bytes) else "w"
    with open(path, mode) as handle:
        handle.write(content)


class FilesystemScanTests(unittest.TestCase):
    def test_scans_text_file_with_relative_name(self):
        with tempfile.TemporaryDirectory() as root:
            write_file(os.path.join(root, "a.txt"), s.github_pat())
            result = scan_path(root)
            self.assertEqual(1, len(result.findings))
            self.assertEqual("a.txt", result.findings[0].file)
            self.assertEqual(1, result.scanned_files)

    def test_scans_single_file_target(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "a.txt")
            write_file(path, s.github_pat())
            result = scan_path(path)
            self.assertEqual(1, len(result.findings))
            self.assertEqual("a.txt", result.findings[0].file)

    def test_missing_root_raises_clean_error(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(SecretSweepError):
                scan_path(os.path.join(root, "missing"))

    def test_empty_file_is_scanned_and_clean(self):
        with tempfile.TemporaryDirectory() as root:
            write_file(os.path.join(root, "empty.txt"), "")
            result = scan_path(root)
            self.assertEqual([], result.findings)
            self.assertEqual([], result.skipped)
            self.assertEqual(1, result.scanned_files)

    def test_always_ignored_directories_are_not_scanned(self):
        with tempfile.TemporaryDirectory() as root:
            for name in (".git", "node_modules", "__pycache__"):
                os.mkdir(os.path.join(root, name))
                write_file(os.path.join(root, name, "secret.txt"), s.github_pat())
            result = scan_path(root)
            self.assertEqual([], result.findings)
            self.assertEqual(0, result.scanned_files)

    def test_gitignore_rule_is_honored(self):
        with tempfile.TemporaryDirectory() as root:
            write_file(os.path.join(root, ".gitignore"), "ignored.txt\n")
            write_file(os.path.join(root, "ignored.txt"), s.github_pat())
            write_file(os.path.join(root, "visible.txt"), "clean")
            result = scan_path(root)
            self.assertEqual([], result.findings)
            self.assertEqual(2, result.scanned_files)

    def test_gitignore_can_be_disabled(self):
        with tempfile.TemporaryDirectory() as root:
            write_file(os.path.join(root, ".gitignore"), "ignored.txt\n")
            write_file(os.path.join(root, "ignored.txt"), s.github_pat())
            result = scan_path(root, use_gitignore=False)
            self.assertEqual(1, len(result.findings))

    def test_secretsweepignore_is_honored_when_gitignore_disabled(self):
        with tempfile.TemporaryDirectory() as root:
            write_file(os.path.join(root, ".secretsweepignore"), "ignored.txt\n")
            write_file(os.path.join(root, "ignored.txt"), s.github_pat())
            result = scan_path(root, use_gitignore=False)
            self.assertEqual([], result.findings)

    def test_ignore_file_over_one_mib_is_input_error(self):
        with tempfile.TemporaryDirectory() as root:
            write_file(os.path.join(root, ".gitignore"), b"x" * (1024 * 1024 + 1))
            with self.assertRaises(SecretSweepError):
                scan_path(root)

    def test_nested_gitignore_is_not_applied(self):
        with tempfile.TemporaryDirectory() as root:
            nested = os.path.join(root, "nested")
            os.mkdir(nested)
            write_file(os.path.join(nested, ".gitignore"), "secret.txt\n")
            write_file(os.path.join(nested, "secret.txt"), s.github_pat())
            result = scan_path(root)
            self.assertEqual(1, len(result.findings))

    def test_exclude_exact_file(self):
        with tempfile.TemporaryDirectory() as root:
            write_file(os.path.join(root, "secret.txt"), s.github_pat())
            result = scan_path(root, exclude=["secret.txt"])
            self.assertEqual([], result.findings)
            self.assertEqual(0, result.scanned_files)

    def test_exclude_path_prefix(self):
        with tempfile.TemporaryDirectory() as root:
            os.mkdir(os.path.join(root, "buildout"))
            write_file(os.path.join(root, "buildout", "secret.txt"), s.github_pat())
            write_file(os.path.join(root, "visible.txt"), "clean")
            result = scan_path(root, exclude=["buildout"])
            self.assertEqual([], result.findings)
            self.assertEqual(1, result.scanned_files)

    def test_max_file_bytes_skips_larger_file(self):
        with tempfile.TemporaryDirectory() as root:
            write_file(os.path.join(root, "large.txt"), "x" * 20)
            result = scan_path(root, max_file_bytes=10)
            self.assertEqual([], result.findings)
            self.assertEqual({"path": "large.txt", "reason": "too-large"}, result.skipped[0])

    def test_exact_max_file_bytes_is_scanned(self):
        with tempfile.TemporaryDirectory() as root:
            write_file(os.path.join(root, "exact.txt"), "x" * 10)
            result = scan_path(root, max_file_bytes=10)
            self.assertEqual(1, result.scanned_files)
            self.assertEqual([], result.skipped)

    def test_invalid_max_file_bytes_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(UsageError):
                scan_path(root, max_file_bytes=0)

    def test_boolean_max_file_bytes_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(UsageError):
                scan_path(root, max_file_bytes=True)

    def test_binary_nul_anywhere_is_skipped(self):
        with tempfile.TemporaryDirectory() as root:
            write_file(os.path.join(root, "late.bin"), b"a" * 9000 + b"\x00" + s.github_pat().encode())
            result = scan_path(root)
            self.assertEqual([], result.findings)
            self.assertEqual("binary", result.skipped[0]["reason"])

    def test_text_with_binary_extension_is_still_scanned(self):
        with tempfile.TemporaryDirectory() as root:
            write_file(os.path.join(root, "payload.bin"), s.github_pat())
            result = scan_path(root)
            self.assertEqual(1, len(result.findings))

    def test_dense_control_bytes_are_binary(self):
        self.assertTrue(looks_binary(bytes([1, 2, 3, 4, 5, 6, 7, 8]) * 10))

    def test_nul_is_binary(self):
        self.assertTrue(looks_binary(b"abc\x00def"))

    def test_text_is_not_binary(self):
        self.assertFalse(looks_binary("hello\n unicode text\n".encode()))

    def test_empty_bytes_are_not_binary(self):
        self.assertFalse(looks_binary(b""))

    def test_binary_path_extension_classification(self):
        self.assertTrue(is_binary_path("image.png"))
        self.assertFalse(is_binary_path("source.txt"))

    def test_invalid_utf8_is_decoded_with_replacement(self):
        with tempfile.TemporaryDirectory() as root:
            write_file(os.path.join(root, "bad.txt"), b"abc\xffdef")
            result = scan_path(root)
            self.assertEqual(1, result.scanned_files)
            self.assertEqual([], result.skipped)

    def test_unicode_filename_and_content(self):
        with tempfile.TemporaryDirectory() as root:
            write_file(os.path.join(root, "unicode-file.txt"), "hello\n" + s.github_pat())
            result = scan_path(root)
            self.assertEqual(1, len(result.findings))
            self.assertEqual(2, result.findings[0].line)

    def test_baseline_argument_suppresses_existing_finding(self):
        with tempfile.TemporaryDirectory() as root:
            write_file(os.path.join(root, "secret.txt"), s.github_pat())
            first = scan_path(root)
            baseline = os.path.join(root, "baseline.json")
            write_baseline(baseline, first)
            second = scan_path(root, baseline=baseline)
            self.assertEqual([], second.findings)

    def test_results_are_sorted_by_file(self):
        with tempfile.TemporaryDirectory() as root:
            write_file(os.path.join(root, "z.txt"), s.github_pat())
            write_file(os.path.join(root, "a.txt"), s.github_pat())
            result = scan_path(root)
            self.assertEqual(["a.txt", "z.txt"], [finding.file for finding in result.findings])


@unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
class SymlinkSafetyTests(unittest.TestCase):
    def test_symlink_escaping_root_is_rejected(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as outside:
            external = os.path.join(outside, "secret.txt")
            write_file(external, s.github_pat())
            os.symlink(external, os.path.join(root, "escape.txt"))
            result = scan_path(root)
            self.assertEqual([], result.findings)
            self.assertEqual("path-escape", result.skipped[0]["reason"])

    def test_symlink_to_inside_file_does_not_duplicate(self):
        with tempfile.TemporaryDirectory() as root:
            write_file(os.path.join(root, "secret.txt"), s.github_pat())
            os.symlink(os.path.join(root, "secret.txt"), os.path.join(root, "link.txt"))
            result = scan_path(root)
            self.assertEqual(1, len(result.findings))
            self.assertEqual("symlink-loop", result.skipped[0]["reason"])

    def test_symlink_loop_is_nonfatal(self):
        with tempfile.TemporaryDirectory() as root:
            os.symlink("loop", os.path.join(root, "loop"))
            write_file(os.path.join(root, "clean.txt"), "clean")
            result = scan_path(root)
            reasons = {entry["reason"] for entry in result.skipped}
            self.assertIn("symlink-loop", reasons)
            self.assertEqual(1, result.scanned_files)

    def test_mutual_symlinks_are_nonfatal(self):
        with tempfile.TemporaryDirectory() as root:
            os.symlink("b", os.path.join(root, "a"))
            os.symlink("a", os.path.join(root, "b"))
            result = scan_path(root)
            self.assertEqual([], result.findings)
            self.assertTrue(result.skipped)

    def test_broken_symlink_is_nonfatal(self):
        with tempfile.TemporaryDirectory() as root:
            os.symlink("missing-target", os.path.join(root, "broken"))
            result = scan_path(root)
            self.assertEqual("broken-symlink", result.skipped[0]["reason"])

    def test_symlinked_directory_inside_root_is_contained(self):
        with tempfile.TemporaryDirectory() as root:
            real = os.path.join(root, "real")
            os.mkdir(real)
            write_file(os.path.join(real, "secret.txt"), s.github_pat())
            os.symlink(real, os.path.join(root, "linked"))
            result = scan_path(root)
            self.assertEqual(1, len(result.findings))
            self.assertTrue(any(entry["reason"] == "symlink-loop" for entry in result.skipped))

    def test_single_file_symlink_target_can_be_scanned_explicitly(self):
        with tempfile.TemporaryDirectory() as root:
            real = os.path.join(root, "real.txt")
            write_file(real, s.github_pat())
            link = os.path.join(root, "link.txt")
            os.symlink(real, link)
            result = scan_path(link)
            self.assertEqual(1, len(result.findings))


class SpecialFileTests(unittest.TestCase):
    @unittest.skipUnless(hasattr(os, "mkfifo"), "fifo support required")
    def test_fifo_is_rejected_without_opening(self):
        with tempfile.TemporaryDirectory() as root:
            os.mkfifo(os.path.join(root, "pipe"))
            result = scan_path(root)
            self.assertEqual("special-file", result.skipped[0]["reason"])
            self.assertEqual(0, result.scanned_files)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "fifo support required")
    def test_low_level_fifo_open_returns_special_without_blocking(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "pipe")
            os.mkfifo(path)
            data, reason = _read_regular_file(path, 1024)
            self.assertIsNone(data)
            self.assertEqual("special-file", reason)

    def test_open_flags_use_available_platform_hardening(self):
        flags = _open_read_flags()
        self.assertTrue(flags & os.O_RDONLY == 0 or os.O_RDONLY == 0)
        for name in ("O_BINARY", "O_NOFOLLOW", "O_NONBLOCK"):
            if hasattr(os, name):
                self.assertTrue(flags & getattr(os, name), name)

    def test_directory_reason_for_unreadable_entries_is_structured(self):
        with tempfile.TemporaryDirectory() as root:
            write_file(os.path.join(root, "clean.txt"), "clean")
            result = scan_path(root)
            for entry in result.skipped:
                self.assertIn("path", entry)
                self.assertIn("reason", entry)

    def test_root_result_contains_absolute_root_for_api_caller(self):
        with tempfile.TemporaryDirectory() as root:
            result = scan_path(root)
            self.assertTrue(os.path.isabs(result.root))
