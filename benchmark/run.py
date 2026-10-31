#!/usr/bin/env python3
"""Run TraceLock over every fixture folder and compare with expected.json.

    python benchmark/run.py            # offline, prints a table, exit 1 on any mismatch
    python benchmark/run.py --online   # allow OSV / PyPI network

A false NOT_REACHABLE (expected REACHABLE or UNCERTAIN, got NOT_REACHABLE) is reported
separately because it is the one failure the judges punish hardest.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "backend"))

from tracelock import scan  # noqa: E402
from tracelock.models import NOT_REACHABLE  # noqa: E402


def main() -> int:
    offline = "--online" not in sys.argv
    rows, failures, false_safe = [], 0, 0
    for fixture in sorted(p for p in HERE.iterdir() if p.is_dir() and (p / "expected.json").exists()):
        expected = json.loads((fixture / "expected.json").read_text())
        try:
            result = scan(fixture, offline=offline)
        except Exception as exc:
            for adv_id, want in expected.items():
                rows.append((fixture.name, adv_id, want, f"ERROR {exc}", "FAIL"))
                failures += 1
            continue
        got_by_id: dict[str, str] = {}
        for f in result.findings:
            for key in [f.advisory.id, *f.advisory.aliases]:
                got_by_id[key] = f.verdict
        for adv_id, want in expected.items():
            got = got_by_id.get(adv_id, "MISSING")
            ok = got == want
            if not ok:
                failures += 1
                if got == NOT_REACHABLE:
                    false_safe += 1
            rows.append((fixture.name, adv_id, want, got, "ok" if ok else "FAIL"))

    width = max(len(r[0]) for r in rows) if rows else 10
    print(f"{'fixture':<{width}}  {'advisory':<18} {'expected':<14} {'got':<14} result")
    for r in rows:
        print(f"{r[0]:<{width}}  {r[1]:<18} {r[2]:<14} {r[3]:<14} {r[4]}")
    total = len(rows)
    print(f"\n{total - failures}/{total} correct, {failures} wrong, {false_safe} FALSE SAFE (must be 0)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
