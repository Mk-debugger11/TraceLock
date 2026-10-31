"""Command line.

    python -m tracelock.cli scan <path> [--json FILE] [--vex FILE] [--sarif FILE] [--offline] [--no-sources] [--fail-on reachable|uncertain]
    python -m tracelock.cli trace <path> [same output flags] [--timeout S] -- python app.py ...

`scan` never executes the project. `trace` RUNS the given command under a profiler to confirm reachability.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import report, scan
from .models import REACHABLE, UNCERTAIN


def main(argv: list[str] | None = None) -> int:
    # Everything after the first `--` is the traced command, passed through untouched
    # (argparse.REMAINDER would also swallow our own options that follow the path).
    argv = list(sys.argv[1:] if argv is None else argv)
    command: list[str] = []
    if "--" in argv:
        split = argv.index("--")
        argv, command = argv[:split], argv[split + 1:]

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("path", type=Path)
    common.add_argument("--json", type=Path, help="write full result JSON here")
    common.add_argument("--vex", type=Path, help="write an OpenVEX document here")
    common.add_argument("--sarif", type=Path, help="write a SARIF 2.1.0 file here")
    common.add_argument("--offline", action="store_true", help="never touch the network; use bundled snapshots and caches")
    common.add_argument("--fail-on", choices=["reachable", "uncertain"], default="reachable")
    common.add_argument("--quiet", action="store_true")

    parser = argparse.ArgumentParser(prog="tracelock", description="Reachability-aware vulnerability scanner for Python projects")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("scan", parents=[common], help="scan a project directory (static, never executes it)")
    p.add_argument("--no-sources", action="store_true", help="skip downloading dependency source (curated KB only)")
    t = sub.add_parser("trace", parents=[common], usage="tracelock trace path [options] -- command ...",
                       help="run the app under a profiler and confirm reachability at runtime (executes the code!)",
                       epilog="Everything after -- is run inside <path>, e.g. -- python app.py config.yaml")
    t.add_argument("--timeout", type=int, default=60, help="seconds before the traced command is killed")
    args = parser.parse_args(argv)

    if not args.path.is_dir():
        print(f"error: {args.path} is not a directory", file=sys.stderr)
        return 2
    if command and args.command != "trace":
        print("error: only `trace` takes a command after --", file=sys.stderr)
        return 2
    try:
        if args.command == "trace":
            from . import scan_with_trace

            if not command:
                print("error: give the command to run after --, e.g. -- python app.py", file=sys.stderr)
                return 2
            print(f"tracelock: executing `{' '.join(command)}` in {args.path} under the profiler", file=sys.stderr)
            result = scan_with_trace(args.path, command, offline=args.offline, timeout=args.timeout)
        else:
            result = scan(args.path, offline=args.offline, fetch_sources=not args.no_sources)
    except Exception as exc:  # tool error, never a silent 'safe'
        print(f"error: scan failed: {exc}", file=sys.stderr)
        return 2

    if not args.quiet:
        report.print_terminal(result)
    if args.json:
        args.json.write_text(report.to_json(result), encoding="utf-8")
    if args.vex:
        args.vex.write_text(report.to_openvex(result), encoding="utf-8")
    if args.sarif:
        args.sarif.write_text(report.to_sarif(result), encoding="utf-8")

    bad = {REACHABLE} if args.fail_on == "reachable" else {REACHABLE, UNCERTAIN}
    return 1 if any(f.verdict in bad for f in result.findings) else 0


if __name__ == "__main__":
    sys.exit(main())
