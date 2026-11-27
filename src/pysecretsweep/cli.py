"""pysecretsweep command line interface.

Exit codes: 0 means clean, 1 means findings, and 2 means usage or input error.
"""

import sys

from .baseline import apply_baseline, read_baseline, write_baseline
from .detectors import list_detectors
from .errors import SecretSweepError, UsageError
from .output import format_output, sort_findings
from .scanner import DEFAULT_MAX_FILE_BYTES, scan_diff, scan_path
from .finder import scan_text
from .util import SEVERITIES, VERSION, safe_display

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2

HELP = """pysecretsweep {version}

Usage:
  pysecretsweep [options] [path ...]
  pysecretsweep [options] --diff
  pysecretsweep [options] --stdin

Options:
  --diff                 Scan a unified git diff from standard input
  --stdin                Scan standard input as plain text
  --format <name>        text, json or sarif (default: text)
  --baseline <file>      Suppress findings already present in the baseline
  --write-baseline <file> Write current findings as a baseline and exit 0
  --detectors <list>     Comma separated detector ids (default: all)
  --severity <level>     Minimum severity: low, medium, high or critical
  --max-file-bytes <n>   Maximum file size to scan (default: {max_bytes})
  --exclude <path>       Exclude a relative path prefix (repeatable)
  --list-detectors       Print detector ids and exit
  -h, --help             Show this help
  -v, --version          Print the version

Exit codes:
  0  no findings (or baseline written)
  1  at least one finding
  2  invalid usage or input error

Reports contain masked previews and SHA-256 fingerprints only; raw secret
values are never printed. An inline "# secretsweep:ignore" comment ignores a
single line, and "# secretsweep:ignore detector-id" ignores one detector.
""".format(version=VERSION, max_bytes=DEFAULT_MAX_FILE_BYTES)


def _fail(message: str) -> UsageError:
    return UsageError(message)


def _option_value(argv, index, flag, inline):
    if inline is not None:
        if inline == "":
            raise _fail("{} requires a value".format(flag))
        return inline, index
    value_index = index + 1
    if value_index >= len(argv) or argv[value_index].startswith("--"):
        raise _fail("{} requires a value".format(flag))
    return argv[value_index], value_index


def parse_args(argv) -> dict:
    options = {
        "paths": [], "diff": False, "stdin": False, "format": "text",
        "baseline": None, "write_baseline": None, "detectors": None,
        "severity": None, "max_file_bytes": DEFAULT_MAX_FILE_BYTES,
        "exclude": [], "list_detectors": False, "help": False, "version": False,
    }
    index = 0
    while index < len(argv):
        arg = argv[index]
        inline = None
        flag = arg
        if arg.startswith("--") and "=" in arg:
            flag, inline = arg.split("=", 1)

        if flag == "--diff":
            if inline is not None:
                raise _fail("--diff does not take a value")
            options["diff"] = True
        elif flag == "--stdin":
            if inline is not None:
                raise _fail("--stdin does not take a value")
            options["stdin"] = True
        elif flag == "--format":
            value, index = _option_value(argv, index, flag, inline)
            options["format"] = value
        elif flag == "--baseline":
            value, index = _option_value(argv, index, flag, inline)
            options["baseline"] = value
        elif flag == "--write-baseline":
            value, index = _option_value(argv, index, flag, inline)
            options["write_baseline"] = value
        elif flag == "--detectors":
            value, index = _option_value(argv, index, flag, inline)
            options["detectors"] = [part.strip() for part in value.split(",") if part.strip()]
        elif flag == "--severity":
            value, index = _option_value(argv, index, flag, inline)
            options["severity"] = value
        elif flag == "--max-file-bytes":
            value, index = _option_value(argv, index, flag, inline)
            try:
                size = int(value, 10)
            except ValueError:
                raise _fail("--max-file-bytes must be a positive integer")
            if size <= 0:
                raise _fail("--max-file-bytes must be a positive integer")
            options["max_file_bytes"] = size
        elif flag == "--exclude":
            value, index = _option_value(argv, index, flag, inline)
            options["exclude"].append(value)
        elif flag == "--list-detectors":
            if inline is not None:
                raise _fail("--list-detectors does not take a value")
            options["list_detectors"] = True
        elif flag in ("-h", "--help"):
            if inline is not None:
                raise _fail("--help does not take a value")
            options["help"] = True
        elif flag in ("-v", "--version"):
            if inline is not None:
                raise _fail("--version does not take a value")
            options["version"] = True
        elif arg.startswith("-"):
            raise _fail("unknown option: {}".format(safe_display(arg)))
        else:
            options["paths"].append(arg)
        index += 1

    if options["format"] not in ("text", "json", "sarif"):
        raise _fail("unknown format: {}".format(safe_display(options["format"])))
    if options["severity"] is not None and options["severity"] not in SEVERITIES:
        raise _fail("unknown severity: {}".format(safe_display(options["severity"])))
    if options["detectors"] is not None:
        if not options["detectors"]:
            raise _fail("--detectors requires at least one detector id")
        known = {detector["id"] for detector in list_detectors()}
        unknown = [item for item in options["detectors"] if item not in known]
        if unknown:
            raise _fail("unknown detector: {}".format(",".join(safe_display(item) for item in unknown)))
    modes = (1 if options["diff"] else 0) + (1 if options["stdin"] else 0) + (1 if options["paths"] else 0)
    if modes > 1:
        raise _fail("choose exactly one input mode: paths, --diff or --stdin")
    return options


def _write_error(stderr, message: str) -> None:
    stderr.write("pysecretsweep: {}\n".format(safe_display(message)))
    stderr.write('Run "pysecretsweep --help" for usage.\n')


def main(argv=None, stdin=None, stdout=None, stderr=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    stdin = sys.stdin if stdin is None else stdin
    stdout = sys.stdout if stdout is None else stdout
    stderr = sys.stderr if stderr is None else stderr

    try:
        options = parse_args(argv)
    except UsageError as exc:
        _write_error(stderr, str(exc))
        return EXIT_USAGE

    if options["help"]:
        stdout.write(HELP)
        return EXIT_CLEAN
    if options["version"]:
        stdout.write("pysecretsweep {}\n".format(VERSION))
        return EXIT_CLEAN
    if options["list_detectors"]:
        for detector in list_detectors():
            stdout.write("{}\t{}\t{}\n".format(detector["id"], detector["provider"], detector["severity"]))
        return EXIT_CLEAN

    scan_options = {
        "detectors": options["detectors"],
        "severity": options["severity"],
        "ignore_comments": True,
    }
    findings = []
    skipped = []
    scanned_files = 0

    try:
        if options["diff"] or options["stdin"]:
            input_text = stdin.read()
            if options["diff"]:
                result = scan_diff(input_text, **scan_options)
            else:
                result = scan_text(input_text, **scan_options)
            findings = list(result.findings)
        else:
            paths = options["paths"] or ["."]
            for path in paths:
                result = scan_path(
                    path,
                    max_file_bytes=options["max_file_bytes"],
                    exclude=options["exclude"],
                    **scan_options,
                )
                findings.extend(result.findings)
                skipped.extend(result.skipped)
                scanned_files += result.scanned_files
    except SecretSweepError as exc:
        _write_error(stderr, str(exc))
        return EXIT_USAGE

    findings = sort_findings(findings)
    if options["write_baseline"]:
        try:
            count = write_baseline(options["write_baseline"], findings)
        except SecretSweepError as exc:
            _write_error(stderr, str(exc))
            return EXIT_USAGE
        stdout.write("pysecretsweep: wrote {} baseline entries\n".format(count))
        return EXIT_CLEAN

    if options["baseline"]:
        try:
            findings = apply_baseline(findings, read_baseline(options["baseline"]))
        except SecretSweepError as exc:
            _write_error(stderr, str(exc))
            return EXIT_USAGE

    stdout.write(format_output(findings, options["format"], skipped=skipped))
    return EXIT_FINDINGS if findings else EXIT_CLEAN
