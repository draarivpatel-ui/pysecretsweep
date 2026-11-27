import os
import tempfile
import unittest

from pysecretsweep.ignore import (
    MAX_IGNORE_FILE_BYTES,
    compile_ignore_rules,
    is_always_ignored,
    is_ignored,
    load_ignore_files,
    match_segment,
    match_parts,
    parse_pattern,
)


class SegmentMatchMatrixTests(unittest.TestCase):
    pass


SEGMENT_CASES = [
    ("*", "", True), ("*", "abc", True), ("?", "", False), ("?", "a", True),
    ("?", "ab", False), ("a*c", "abc", True), ("a*c", "ac", True), ("a*c", "abbc", True),
    ("a*c", "ab", False), ("a?c", "abc", True), ("a?c", "ac", False),
    ("[abc]x", "ax", True), ("[abc]x", "cx", True), ("[abc]x", "dx", False),
    ("[!a]x", "bx", True), ("[!a]x", "ax", False), ("[a-c]x", "bx", True),
    ("[a-c]x", "dx", False), ("[^a-c]x", "dx", True), ("a**c", "abc", True),
    ("**", "abc", True), ("a\\*c", "a*c", True), ("a\\*c", "abc", False),
    ("file?.txt", "file1.txt", True), ("file?.txt", "file12.txt", False),
    ("*file*", "afileb", True), ("*file*", "afilb", False),
    ("[a-z][0-9]", "a1", True), ("[a-z][0-9]", "A1", False),
    ("x[ab]y*z", "xayqqz", True), ("x[ab]y*z", "xcyqqz", False),
    ("literal", "literal", True), ("literal", "other", False),
]


def make_segment_case(pattern, text, expected):
    def test(self):
        self.assertEqual(expected, match_segment(pattern, text), (pattern, text))
    return test


for index, (PATTERN, TEXT, EXPECTED) in enumerate(SEGMENT_CASES):
    setattr(SegmentMatchMatrixTests, "test_segment_{:02d}".format(index), make_segment_case(PATTERN, TEXT, EXPECTED))


class IgnoreRuleMatrixTests(unittest.TestCase):
    pass


RULE_CASES = [
    (["*.txt"], "a.txt", False, True),
    (["*.txt"], "dir/a.txt", False, True),
    (["*.txt"], "dir/a.py", False, False),
    (["build/"], "build", True, True),
    (["build/"], "build", False, False),
    (["build/"], "build/output.txt", False, True),
    (["/root.txt"], "root.txt", False, True),
    (["/root.txt"], "dir/root.txt", False, False),
    (["src/*.py"], "src/app.py", False, True),
    (["src/*.py"], "other/src/app.py", False, False),
    (["*.txt", "!keep.txt"], "keep.txt", False, False),
    (["*.txt", "!keep.txt"], "other.txt", False, True),
    (["foo/**"], "foo", True, False),
    (["foo/**"], "foo/bar.txt", False, True),
    (["foo/**", "!foo/keep.txt"], "foo/keep.txt", False, False),
    (["foo/**", "!foo/keep.txt"], "foo/other.txt", False, True),
    (["**/generated.txt"], "generated.txt", False, True),
    (["**/generated.txt"], "a/b/generated.txt", False, True),
    (["foo/**/bar.txt"], "foo/bar.txt", False, True),
    (["foo/**/bar.txt"], "foo/a/b/bar.txt", False, True),
    (["foo/**/bar.txt"], "foo/a/b/other.txt", False, False),
    (["file?.txt"], "file1.txt", False, True),
    (["file[ab].txt"], "filea.txt", False, True),
    (["file[!a].txt"], "fileb.txt", False, True),
    (["file[!a].txt"], "filea.txt", False, False),
    (["\\#hash.txt"], "#hash.txt", False, True),
    (["\\!bang.txt"], "!bang.txt", False, True),
    (["name\\ space.txt"], "name space.txt", False, True),
    (["node_modules/"], "node_modules", True, True),
    (["dist/*.js"], "dist/app.js", False, True),
]


def make_rule_case(lines, path, is_directory, expected):
    def test(self):
        rules = compile_ignore_rules(lines)
        self.assertEqual(expected, is_ignored(path, is_directory, rules), (lines, path, is_directory))
    return test


for index, (LINES, PATH, IS_DIRECTORY, EXPECTED) in enumerate(RULE_CASES):
    setattr(IgnoreRuleMatrixTests, "test_rule_{:02d}".format(index), make_rule_case(LINES, PATH, IS_DIRECTORY, EXPECTED))


class IgnoreParsingTests(unittest.TestCase):
    def test_comment_is_not_rule(self):
        self.assertIsNone(parse_pattern("# comment"))

    def test_empty_is_not_rule(self):
        self.assertIsNone(parse_pattern(""))

    def test_trailing_spaces_are_stripped(self):
        rule = parse_pattern("abc.txt   ")
        self.assertEqual("abc.txt", rule.text)

    def test_negation_is_recorded(self):
        rule = parse_pattern("!abc.txt")
        self.assertTrue(rule.negate)

    def test_directory_only_is_recorded(self):
        rule = parse_pattern("build/")
        self.assertTrue(rule.dir_only)

    def test_leading_slash_anchors(self):
        rule = parse_pattern("/build.txt")
        self.assertTrue(rule.anchored)

    def test_inner_slash_anchors(self):
        rule = parse_pattern("src/build.txt")
        self.assertTrue(rule.anchored)

    def test_leading_globstar_is_not_root_anchored(self):
        rule = parse_pattern("**/build.txt")
        self.assertFalse(rule.anchored)

    def test_overlong_pattern_is_discarded(self):
        self.assertIsNone(parse_pattern("a" * 1100))

    def test_globstar_trailing_requires_child(self):
        self.assertFalse(match_parts(("foo", "**"), ("foo",)))
        self.assertTrue(match_parts(("foo", "**"), ("foo", "bar")))

    def test_globstar_middle_matches_zero_components(self):
        self.assertTrue(match_parts(("foo", "**", "bar"), ("foo", "bar")))

    def test_globstar_middle_matches_many_components(self):
        self.assertTrue(match_parts(("foo", "**", "bar"), ("foo", "a", "b", "bar")))

    def test_always_ignore_names(self):
        for name in (".git", "node_modules", "__pycache__", ".venv", "dist"):
            self.assertTrue(is_always_ignored(name))
        self.assertFalse(is_always_ignored("src"))


class IgnoreFileLoadingTests(unittest.TestCase):
    def test_loads_gitignore_and_secretsweepignore(self):
        with tempfile.TemporaryDirectory() as root:
            with open(os.path.join(root, ".gitignore"), "w") as handle:
                handle.write("one.txt\n")
            with open(os.path.join(root, ".secretsweepignore"), "w") as handle:
                handle.write("two.txt\n")
            rules = load_ignore_files(root)
            self.assertTrue(is_ignored("one.txt", False, rules))
            self.assertTrue(is_ignored("two.txt", False, rules))

    def test_can_exclude_gitignore(self):
        with tempfile.TemporaryDirectory() as root:
            with open(os.path.join(root, ".gitignore"), "w") as handle:
                handle.write("one.txt\n")
            with open(os.path.join(root, ".secretsweepignore"), "w") as handle:
                handle.write("two.txt\n")
            rules = load_ignore_files(root, include_gitignore=False)
            self.assertFalse(is_ignored("one.txt", False, rules))
            self.assertTrue(is_ignored("two.txt", False, rules))

    def test_oversized_ignore_file_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            with open(os.path.join(root, ".secretsweepignore"), "wb") as handle:
                handle.write(b"x" * (MAX_IGNORE_FILE_BYTES + 1))
            with self.assertRaises(ValueError):
                load_ignore_files(root)

    def test_exactly_sized_ignore_file_is_accepted(self):
        with tempfile.TemporaryDirectory() as root:
            with open(os.path.join(root, ".secretsweepignore"), "wb") as handle:
                handle.write(b"x" * MAX_IGNORE_FILE_BYTES)
            load_ignore_files(root)

    def test_missing_ignore_files_are_clean(self):
        with tempfile.TemporaryDirectory() as root:
            self.assertEqual([], load_ignore_files(root))

    def test_nested_ignore_file_is_outside_documented_model(self):
        with tempfile.TemporaryDirectory() as root:
            nested = os.path.join(root, "nested")
            os.mkdir(nested)
            with open(os.path.join(nested, ".gitignore"), "w") as handle:
                handle.write("secret.txt\n")
            rules = load_ignore_files(root)
            self.assertFalse(is_ignored("nested/secret.txt", False, rules))

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_ignore_symlink_outside_root_is_not_followed(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as outside:
            external = os.path.join(outside, "rules")
            with open(external, "w") as handle:
                handle.write("hidden.txt\n")
            os.symlink(external, os.path.join(root, ".secretsweepignore"))
            rules = load_ignore_files(root)
            self.assertFalse(is_ignored("hidden.txt", False, rules))
