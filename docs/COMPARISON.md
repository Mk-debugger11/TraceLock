# TraceLock compared with version-matching scanners

Every Python dependency scanner starts the same way: read the pinned versions, match them against an
advisory database. `pip-audit` and `safety` stop there. TraceLock continues: for each advisory it asks
whether the *application code* can actually reach the vulnerable function, and says so with evidence.

## The same project, two answers

`benchmark/real_flask_app` pins 10 packages at deliberately old versions.

| Tool | What it reports | Verdict per advisory | What a developer does next |
| --- | --- | --- | --- |
| `pip-audit` / `safety` | **108** advisories on vulnerable versions | "affected" | Read 108 advisories, or upgrade everything and hope nothing breaks |
| **TraceLock** | the same 108, triaged | **6 REACHABLE** · 7 NOT_REACHABLE · 95 UNCERTAIN | Fix the 6 first, each with a call path from an entry point to the vulnerable function |

Reproduce it:

```bash
pip install pip-audit
pip-audit -r benchmark/real_flask_app/requirements.txt --strict 2>/dev/null | grep -c GHSA   # version matching only
tracelock scan benchmark/real_flask_app                                                       # same advisories, with reachability
```

## Feature table

| | pip-audit | safety | TraceLock |
| --- | --- | --- | --- |
| Version-based matching (OSV / PyPI advisories) | yes | yes (own DB) | yes (OSV) |
| Per-advisory **reachability** verdict | no | no | **REACHABLE / NOT_REACHABLE / UNCERTAIN** |
| Evidence: entry point → call path → vulnerable function | no | no | yes, with file:line and the source line |
| Says *why* it is unsure (`unresolved_call`, `string_ref`, `dynamic`, `transitive`…) | — | — | yes, with the one thing to check |
| Never a silent "safe": NOT_REACHABLE requires a soundness checklist | — | — | yes (9 checks, all printed) |
| Safe-usage rules (`yaml.load(..., Loader=SafeLoader)` is not a hit) | no | no | yes |
| Library-side analysis (which public API leads to the patched function) | no | no | yes, from the fix commit and the library source |
| Transitive packages (`requests` → `urllib3`) | lists them | lists them | analyses the bridge: is the urllib3 path exposed through the requests API the app calls? |
| Runtime confirmation (`tracelock trace … -- python app.py`) | no | no | yes: profiler, real stack, argument-aware |
| Unpinned dependencies | skipped / all versions | all versions | all advisories, flagged `version_unpinned`, never silently safe |
| Accept a finding with an audit trail (`.tracelock.yml`: reason, by, until) | ignore list | ignore list | yes, with VEX justification and expiry |
| OpenVEX output | no | no | yes (`affected` / `not_affected` / `under_investigation`) |
| SARIF → GitHub code scanning | yes | yes | yes, one alert per finding with the path as the location |
| Plain-language explanation per finding (`--explain`, UI "Why?") | no | no | yes, including how the confidence number was built |
| Web UI with scan history | no | hosted Safety Platform | yes, local, open source |
| Executes your code? | no | no | never for the static scan; `trace` only when you ask |

## What TraceLock does *not* claim

- It is not taint analysis: it tells you a vulnerable function is reachable, not that attacker data reaches it.
  A REACHABLE verdict with a safe argument source is still your call; that is what `--explain` and the call path are for.
- NOT_REACHABLE is only issued when the checklist is fully green. Any `getattr`, `importlib`, `exec`, star import,
  unresolved receiver with the same method name, or string that names the symbol makes the verdict UNCERTAIN instead.
  On the benchmark this costs nothing (65/65, precision and recall 1.00, 0 false "safe"); on a large dynamic codebase it
  means more UNCERTAIN rows, each with the exact line to look at.
- Function data quality varies by advisory and is always shown: `curated` > `ecosystem_specific` > `fix_commit` >
  `llm_verified` > `none`. With `none` TraceLock refuses to say safe.

## Numbers behind this page

`python benchmark/run.py` prints the fixture table and writes `benchmark/RESULTS.md`; the counts above are from that run
and should be refreshed from it rather than edited by hand.
