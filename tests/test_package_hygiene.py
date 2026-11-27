import os
import re
import subprocess
import unittest

import pysecretsweep

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def read_rel(path):
    with open(os.path.join(ROOT, path), "rb") as handle:
        return handle.read()


def text_rel(path):
    return read_rel(path).decode("utf-8")


def repo_files():
    values = []
    for current, dirs, files in os.walk(ROOT):
        dirs[:] = [name for name in dirs if name not in {".git", "__pycache__", ".pytest_cache"}]
        for name in files:
            if name == ".DS_Store" or name.endswith((".pyc", ".pyo")):
                continue
            values.append(os.path.relpath(os.path.join(current, name), ROOT))
    return sorted(values)


def join_parts(*parts):
    return "".join(parts)


class PackageMetadataTests(unittest.TestCase):
    def test_version_consistent(self):
        self.assertEqual(pysecretsweep.VERSION, pysecretsweep.__version__)
        self.assertIn('version = "{}"'.format(pysecretsweep.VERSION), text_rel("pyproject.toml"))

    def test_requires_python_39_plus(self):
        self.assertIn('requires-python = ">=3.9"', text_rel("pyproject.toml"))

    def test_zero_runtime_dependencies(self):
        self.assertIn("dependencies = []", text_rel("pyproject.toml"))

    def test_console_script_entrypoint(self):
        self.assertIn('pysecretsweep = "pysecretsweep.cli:main"', text_rel("pyproject.toml"))

    def test_py_typed_package_data(self):
        self.assertIn('pysecretsweep = ["py.typed"]', text_rel("pyproject.toml"))
        self.assertTrue(os.path.exists(os.path.join(ROOT, "src", "pysecretsweep", "py.typed")))

    def test_python_version_classifiers(self):
        text = text_rel("pyproject.toml")
        for version in ("3.9", "3.10", "3.11", "3.12", "3.13"):
            self.assertIn("Programming Language :: Python :: {}".format(version), text)

    def test_ci_is_pinned_to_ubuntu_2404(self):
        self.assertIn("runs-on: ubuntu-24.04", text_rel(".github/workflows/ci.yml"))

    def test_ci_matrix_covers_python_39_to_313(self):
        text = text_rel(".github/workflows/ci.yml")
        for version in ("3.9", "3.10", "3.11", "3.12", "3.13"):
            self.assertIn('"{}"'.format(version), text)

    def test_ci_runs_unittest_suite(self):
        self.assertIn("PYTHONPATH=src python3 -m unittest discover -s tests", text_rel(".github/workflows/ci.yml"))

    def test_ci_runs_cli_smoke_test(self):
        self.assertIn("PYTHONPATH=src python3 -m pysecretsweep --version", text_rel(".github/workflows/ci.yml"))

    def test_ci_runs_package_build_check(self):
        self.assertIn("python3 -m build", text_rel(".github/workflows/ci.yml"))

    def test_publish_uses_oidc_identity_permission(self):
        text = text_rel(".github/workflows/publish.yml")
        self.assertIn("id-token: write", text)
        self.assertIn("pypa/gh-action-pypi-publish@release/v1", text)

    def test_publish_has_no_password_or_repository_token(self):
        text = text_rel(".github/workflows/publish.yml").lower()
        self.assertNotIn("password:", text)
        self.assertNotIn("pypi_api_token", text)

    def test_public_api_exports_required_functions(self):
        for name in (
            "scan_text", "scan_path", "scan_diff", "register_detector",
            "read_baseline", "write_baseline", "apply_baseline",
            "format_terminal", "format_json", "format_sarif",
        ):
            self.assertTrue(hasattr(pysecretsweep, name), name)

    def test_detector_count_is_36(self):
        self.assertEqual(36, len(pysecretsweep.list_detectors()))

    def test_source_tree_has_no_subprocess_use(self):
        for path in repo_files():
            if path.startswith("src/") and path.endswith(".py"):
                self.assertNotIn("subprocess", text_rel(path), path)

    def test_library_has_no_network_client_imports(self):
        banned = ("urllib.request", "http.client", "socket", "requests")
        for path in repo_files():
            if path.startswith("src/") and path.endswith(".py"):
                text = text_rel(path)
                for item in banned:
                    self.assertNotIn(item, text, (path, item))


class RepositoryHygieneTests(unittest.TestCase):
    def test_no_em_or_en_dash_bytes_in_repository_text(self):
        em = bytes.fromhex("e28094")
        en = bytes.fromhex("e28093")
        for path in repo_files():
            data = read_rel(path)
            self.assertNotIn(em, data, path)
            self.assertNotIn(en, data, path)

    def test_no_personal_or_local_paths_in_repository_text(self):
        users_prefix = join_parts("/", "Users", "/")
        aariv_home = join_parts("/", "home", "/", "aariv")
        gmail_one = join_parts("someone", "@", "gmail", ".com")
        gmail_two = join_parts("handle-redacted286", "@", "gmail", ".com")
        street = join_parts("5019", " ", "Exampleton")
        banned = (users_prefix, aariv_home, gmail_one, gmail_two, street)
        for path in repo_files():
            text = text_rel(path)
            for item in banned:
                self.assertNotIn(item, text, (path, item))

    def test_no_vendor_shaped_secret_literals_in_tests(self):
        fragments = [
            ("A", "K", "I", "A"), ("A", "S", "I", "A"), ("g", "h", "p_"),
            ("g", "h", "o_"), ("github", "_pat_"), ("s", "k", "_live_"),
            ("s", "k", "_test_"), ("r", "k", "_live_"), ("p", "k", "_live_"),
            ("x", "o", "x"), ("A", "I", "z", "a"), ("G", "O", "C", "S", "P", "X", "-"),
            ("s", "k", "-"), ("h", "f_"), ("n", "p", "m_"), ("p", "y", "p", "i", "-"),
            ("d", "c", "k", "r", "_pat_"), ("S", "G", "."), ("s", "q", "0", "atp", "-"),
            ("s", "q", "u_"),
        ]
        prefixes = [join_parts(*parts) for parts in fragments]
        tests_dir = os.path.join(ROOT, "tests")
        for name in os.listdir(tests_dir):
            if not name.endswith(".py"):
                continue
            with open(os.path.join(tests_dir, name), "r", encoding="utf-8") as handle:
                text = handle.read()
            for prefix in prefixes:
                pattern = re.escape(prefix) + r"[A-Za-z0-9_+/=.:-]{8,}"
                self.assertIsNone(re.search(pattern, text), (name, prefix))

    def test_git_tracks_no_pycache_or_pyc_when_git_metadata_exists(self):
        git_dir = os.path.join(ROOT, ".git")
        if not os.path.exists(git_dir):
            self.skipTest("git metadata is not initialized yet")
        proc = subprocess.run(
            ["git", "ls-files"], cwd=ROOT, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, universal_newlines=True,
        )
        self.assertEqual(0, proc.returncode, proc.stderr)
        tracked = proc.stdout.splitlines()
        self.assertFalse(any("__pycache__" in path for path in tracked), tracked)
        self.assertFalse(any(path.endswith((".pyc", ".pyo")) for path in tracked), tracked)

    def test_gitignore_excludes_python_cache_files(self):
        text = text_rel(".gitignore")
        self.assertIn("__pycache__/", text)
        self.assertIn("*.py[cod]", text)

    def test_issue_templates_and_pull_request_template_exist(self):
        for path in (
            ".github/ISSUE_TEMPLATE/bug_report.md",
            ".github/ISSUE_TEMPLATE/feature_request.md",
            ".github/PULL_REQUEST_TEMPLATE.md",
        ):
            self.assertTrue(os.path.exists(os.path.join(ROOT, path)), path)

    def test_good_first_issues_has_exactly_ten_items(self):
        text = text_rel("docs/good-first-issues.md")
        count = len(re.findall(r"^\d+\. \*\*", text, re.MULTILINE))
        self.assertEqual(10, count)

    def test_readme_documents_detector_count(self):
        text = text_rel("README.md")
        self.assertIn("36 built-in detectors", text)
        self.assertIn("all 36 detectors", text)

    def test_readme_documents_exact_test_count(self):
        text = text_rel("README.md")
        match = re.search(r"contains (\d+) real tests", text)
        self.assertIsNotNone(match)
        documented = int(match.group(1))
        suite = unittest.defaultTestLoader.discover(os.path.join(ROOT, "tests"))
        self.assertEqual(suite.countTestCases(), documented)
        self.assertIn("All {} tests passed".format(documented), text)

    def test_readme_has_no_test_count_placeholder(self):
        self.assertNotIn("TEST_COUNT", text_rel("README.md"))

    def test_readme_does_not_claim_pypi_release_is_live(self):
        text = text_rel("README.md")
        self.assertIn("PyPI release is pending", text)
        self.assertIn("git+https://github.com/draarivpatel-ui/pysecretsweep.git", text)
        self.assertNotIn("python3 -m pip install pysecretsweep", text)

    def test_readme_documents_limitations(self):
        text = text_rel("README.md")
        self.assertIn("Scope and limitations", text)
        self.assertIn("Nested `.gitignore` files", text)
        self.assertIn("Rotate exposed credentials", text)

    def test_security_policy_describes_private_reporting(self):
        text = text_rel("SECURITY.md")
        self.assertIn("private security advisory", text)
        self.assertIn("Do not include real secrets", text)

    def test_license_is_mit(self):
        self.assertIn("MIT License", text_rel("LICENSE"))
