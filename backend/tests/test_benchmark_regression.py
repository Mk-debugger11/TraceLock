"""The engine benchmark is part of the test suite: any wrong verdict, and above all any false
NOT_REACHABLE, fails pytest. Runs offline against the bundled OSV snapshot and seed wheels."""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_benchmark_all_rows_correct():
    proc = subprocess.run([sys.executable, str(ROOT / "benchmark" / "run.py")], cwd=ROOT,
                          capture_output=True, text=True, timeout=600)
    tail = "\n".join(proc.stdout.splitlines()[-8:])
    assert proc.returncode == 0, f"benchmark reported failures:\n{tail}\n{proc.stderr[-800:]}"
    assert "0 FALSE SAFE" in proc.stdout, tail
