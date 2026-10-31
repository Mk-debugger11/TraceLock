"""Runtime confirmation: run the app and record whether a target function executes. STRETCH, whoever is free first.

Scaffold status: STUB. `run_trace` returns None.

Build:
  tracelock trace <root> --targets yaml.load,yaml.full_load -- python app.py
  1. Write a bootstrap file into a temp dir:
        import sys, json, traceback, os
        TARGETS = set(os.environ["TRACELOCK_TARGETS"].split(","))
        hits = []
        def prof(frame, event, arg):
            if event == "call":
                mod = frame.f_globals.get("__name__", "")
                qual = getattr(frame.f_code, "co_qualname", frame.f_code.co_name)
                full = f"{mod}.{qual}"
                if full in TARGETS or any(full.endswith("." + t.rsplit(".",1)[-1]) and full.startswith(t.split(".",1)[0]) for t in TARGETS):
                    hits.append({"function": full, "stack": [
                        {"file": fs.filename, "line": fs.lineno, "function": fs.name, "code": fs.line}
                        for fs in traceback.extract_stack(frame)]})
        sys.setprofile(prof)
        import atexit; atexit.register(lambda: open(os.environ["TRACELOCK_OUT"], "w").write(json.dumps(hits)))
     Name it sitecustomize.py and prepend its dir to PYTHONPATH so it runs before the app.
  2. Run the user's command in a subprocess with cwd=root, timeout 60 s, env TRACELOCK_TARGETS/TRACELOCK_OUT.
  3. Return {"executed": bool(hits), "hits": hits, "stack": hits[0]["stack"] if hits else []}.
  4. tracelock.scan(trace=...) passes it to verdict.decide, which promotes the finding to REACHABLE (runtime).
  Security note for the README: this executes the target application; only use on code you trust.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional


def run_trace(root: Path, targets: list[str], command: list[str], timeout: int = 60) -> Optional[dict]:
    """Stub: no runtime evidence yet."""
    return None
