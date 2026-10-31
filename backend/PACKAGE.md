# TraceLock

Reachability-aware vulnerability scanner for Python projects. It tells you, per advisory, whether
your code can actually reach the vulnerable function (REACHABLE with the call path),
provably cannot (NOT_REACHABLE with a soundness checklist), or whether it cannot be sure
(UNCERTAIN with the reason and what to check). It never bluffs "safe".

    pip install tracelock
    tracelock scan .                      # static; never executes the project
    tracelock scan . --vex out.vex.json --sarif out.sarif --json out.json
    tracelock trace . -- python app.py    # runtime confirmation (executes the app)

Full documentation: https://github.com/Mk-debugger11/TraceLock
