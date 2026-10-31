"""Runtime confirmation: run the application and record whether a vulnerable function executes. OWNER: Kartik.

    trace = run_trace(root, targets=["yaml.load", "yaml.full_load"], command=["python", "app.py"])
    -> {"executed": True, "hits": [...], "stack": [...], "command": "...", "returncode": 0}

Mechanism: a `sitecustomize.py` is written to a temp dir that is prepended to PYTHONPATH, so it
runs before the application. It installs `sys.setprofile`, matches every `call` event's
`<module>.<qualname>` against the targets (exact, or same package + same trailing segments), and
records the Python stack of the first few hits. The result is read back from a JSON file.

Security note: this EXECUTES the target application and its dependencies. Only use it on code
you trust (the benchmark fixtures, the demo apps); static analysis never executes anything.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional

BOOTSTRAP = r'''
import atexit, json, os, sys, traceback
_TARGETS = [t for t in os.environ.get("TRACELOCK_TARGETS", "").split(",") if t]
_OUT = os.environ.get("TRACELOCK_OUT")
_hits = []
_MAX = 20

def _matches(full):
    for t in _TARGETS:
        if full == t:
            return True
        tp, fp = t.split("."), full.split(".")
        if tp[0] == fp[0] and len(fp) >= 2 and fp[-2:] == tp[-2:]:
            return True
        if tp[0] == fp[0] and fp[-1] == tp[-1] and len(tp) <= 2:
            return True
    return False

def _prof(frame, event, arg):
    if event != "call" or len(_hits) >= _MAX:
        return
    code = frame.f_code
    if not (code.co_flags & 0x01):  # CO_OPTIMIZED is set for real functions only
        return  # module or class body executing at import time, not a function call
    mod = frame.f_globals.get("__name__", "")
    qual = getattr(code, "co_qualname", code.co_name)
    full = f"{mod}.{qual}" if mod else qual
    if _matches(full):
        stack = [{"file": fs.filename, "line": fs.lineno, "function": fs.name, "code": (fs.line or "").strip()}
                 for fs in traceback.extract_stack(frame)]
        args = {}
        for name in code.co_varnames[:code.co_argcount + code.co_kwonlyargcount]:
            v = frame.f_locals.get(name)
            qn = getattr(v, "__qualname__", None)
            args[name] = (f"{getattr(v, '__module__', '')}.{qn}" if qn else type(v).__name__)
        _hits.append({"function": full, "stack": stack, "args": args})

def _dump():
    sys.setprofile(None)
    if _OUT:
        try:
            with open(_OUT, "w") as fh:
                json.dump(_hits, fh)
        except OSError:
            pass

atexit.register(_dump)
sys.setprofile(_prof)
import threading
threading.setprofile(_prof)
'''


def _short_library_path(path: str) -> str:
    """Absolute library frame -> '<package>/file.py' so reports never leak local directories."""
    norm = path.replace("\\", "/")
    for marker in ("site-packages/", "dist-packages/", ".tracelock/cache/src/", "data/wheels/"):
        if marker in norm:
            tail = norm.split(marker)[-1]
            if marker.endswith("src/"):           # cache/src/<name>-<ver>/pkg/file.py -> pkg/file.py
                tail = tail.split("/", 1)[-1] if "/" in tail else tail
            return tail
    parts = norm.rsplit("/", 2)
    return "/".join(parts[-2:]) if len(parts) >= 2 else norm


def run_trace(root: Path, targets: list[str], command: list[str], timeout: int = 60,
              python: Optional[str] = None) -> Optional[dict]:
    """Execute `command` inside `root` with the profiler installed. Returns the trace dict, or None if it could not run."""
    if not targets or not command:
        return None
    root = Path(root).resolve()
    with tempfile.TemporaryDirectory(prefix="tracelock-") as tmp:
        boot_dir = Path(tmp) / "boot"
        boot_dir.mkdir()
        (boot_dir / "sitecustomize.py").write_text(BOOTSTRAP, encoding="utf-8")
        out = Path(tmp) / "trace.json"
        env = dict(os.environ)
        env["PYTHONPATH"] = str(boot_dir) + os.pathsep + env.get("PYTHONPATH", "")
        env["TRACELOCK_TARGETS"] = ",".join(targets)
        env["TRACELOCK_OUT"] = str(out)
        cmd = list(command)
        if cmd[0] in ("python", "python3") and python:
            cmd[0] = python
        try:
            proc = subprocess.run(cmd, cwd=str(root), env=env, capture_output=True, text=True, timeout=timeout)
            returncode, stderr = proc.returncode, proc.stderr[-2000:]
        except subprocess.TimeoutExpired:
            returncode, stderr = -1, "timed out"
        except (OSError, FileNotFoundError) as exc:
            return {"executed": False, "hits": [], "stack": [], "command": " ".join(command), "error": str(exc)}
        hits = []
        if out.exists():
            try:
                hits = json.loads(out.read_text(encoding="utf-8"))
            except ValueError:
                hits = []
    # Trim every stack to the application's own frames plus the library frames; relativise app paths.
    for hit in hits:
        trimmed = [s for s in hit["stack"] if "sitecustomize" not in s["file"] and not s["file"].startswith("<frozen")]
        for s in trimmed:
            try:
                s["file"] = str(Path(s["file"]).resolve().relative_to(root))
            except ValueError:
                s["file"] = _short_library_path(s["file"])
        hit["stack"] = trimmed
    stack = hits[0]["stack"] if hits else []
    return {
        "executed": bool(hits),
        "hits": hits,
        "stack": stack,
        "command": " ".join(command),
        "returncode": returncode,
        "stderr": stderr if not hits else "",
    }


def targets_for(spec_targets: list[str]) -> list[str]:
    """Targets to watch: the advisory's entry API and vulnerable functions, deduplicated."""
    seen, out = set(), []
    for t in spec_targets:
        if t and t not in seen:
            seen.add(t)
            out.append(t)
    return out


if __name__ == "__main__":  # python -m tracelock.tracer <root> <target,target> -- python app.py
    root, targets, _, *cmd = sys.argv[1:]
    print(json.dumps(run_trace(Path(root), targets.split(","), cmd), indent=2))
