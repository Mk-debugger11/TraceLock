"""Command line: `python -m tracelock.cli scan <path> [--json FILE] [--vex FILE] [--sarif FILE] [--offline] [--fail-on reachable|uncertain]`."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import report, scan
from .models import REACHABLE, UNCERTAIN


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="tracelock", description="Reachability-aware vulnerability scanner for Python projects")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("scan", help="scan a project directory")
    p.add_argument("path", type=Path)
    p.add_argument("--json", type=Path, help="write full result JSON here")
    p.add_argument("--vex", type=Path, help="write an OpenVEX document here")
    p.add_argument("--sarif", type=Path, help="write a SARIF 2.1.0 file here")
    p.add_argument("--offline", action="store_true", help="never touch the network; use bundled snapshots and caches")
    p.add_argument("--no-sources", action="store_true", help="skip downloading dependency source (curated KB only)")
    p.add_argument("--fail-on", choices=["reachable", "uncertain"], default="reachable")
    p.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    if not args.path.is_dir():
        print(f"error: {args.path} is not a directory", file=sys.stderr)
        return 2
    try:
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
