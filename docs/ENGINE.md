# TraceLock engine — how a verdict is reached

Paste-ready section for the root README (Mukul). Everything here is true of the code on `main`.

## Pipeline

```
requirements / pyproject / venv  ->  OSV advisories (cached, offline snapshot)
                                 ->  knowledge base: which functions are dangerous, and how we know
app source  --AST-->  bindings, calls, entry points, dynamic markers, string refs
library source (downloaded, never executed)  --AST-->  exposure set: public APIs that reach the vulnerable code
                                 ->  verdict engine  ->  REACHABLE | NOT_REACHABLE | UNCERTAIN, with evidence
optional: runtime tracer runs the app under a profiler and confirms a hit with the live stack
```

## The three verdicts

**REACHABLE** — a call chain exists from application code to a vulnerable symbol. Evidence: the chain
with `file:line` for every app step, the source line of the call site, the entry kind
(`main`, `route`, `module`, or `orphan` for a function nothing calls statically — dead code is still
reachable because Python can invoke anything by name), and, when the library was analysed, the chain
continuing inside the library down to the vulnerable function. Other call sites are listed as
`also_called_at`.

**NOT_REACHABLE** — only when every item of the soundness checklist holds:

| check | meaning |
| --- | --- |
| `no_call_to_vulnerable_api` | no resolved call hits the vulnerable symbols or the exposure set |
| `all_call_sites_safe` | any hit uses a safe argument (e.g. `Loader=yaml.SafeLoader`, resolved through imports and class bases) |
| `no_unresolved_call_with_same_name` | no `obj.load()` whose receiver we could not type |
| `no_dynamic_markers` | no `getattr`/`setattr` with a variable name, `importlib`, `__import__`, `eval`, `exec`, `globals()[...]`, `sys.modules[...]`, pickle/marshal loads |
| `no_string_reference` | no string in code, templates or config naming the symbol (`"xmlattr"`, `"yaml.load"`) |
| `no_star_import` | no `from pkg import *` for the vulnerable package |
| `function_data_available` | the knowledge base knows which functions are affected |
| `not_transitively_required` | the package is not pulled in by a package the app imports (or that path was analysed) |

The checklist is printed with every NOT_REACHABLE so a reviewer can see exactly why we are allowed to say it.

**UNCERTAIN** — anything else. Every UNCERTAIN carries the reason kind, `file:line`, what we saw, and
the one thing a human should check. Reasons are ordered most specific first:
`unresolved_call`, `string_ref`, `star_import`, `transitive`, `dynamic`, `no_function_data`.

Asymmetry is deliberate: a wrong "safe" is the failure the tool is built to avoid, so doubt always
resolves toward UNCERTAIN, never toward NOT_REACHABLE.

## Finding the vulnerable functions when the advisory does not name them

| tier | source | confidence |
| --- | --- | --- |
| `curated` | hand-verified entry in `kb/curated.json` (functions, public entry API, safe-usage rules, fix commit) | 0.95 |
| `ecosystem_specific` | PyPA's `imports` field in the OSV record, when present (~5% of PyPI advisories) | 0.9 |
| `fix_commit` | the advisory's fix commit diff, each hunk mapped to its enclosing function by parsing the pre-fix file (hunk headers are not trusted) | 0.7 |
| `llm_verified` | an LLM proposes public entry points from the advisory + diff; every name is checked against the installed library source before use. The LLM never decides a verdict | 0.6 |
| `none` | nothing usable: the verdict can only be UNCERTAIN | 0 |

Tiers merge rather than replace: a curated safe-usage rule still applies when the fix-commit tier adds functions.

## Library-side analysis (exposure set)

Advisories usually point at an internal function (`jinja2.filters.do_xmlattr`,
`requests.sessions.Session.rebuild_proxies`). TraceLock parses the dependency's own source
(downloaded wheel or sdist, unpacked, never installed or imported) and walks the call graph backwards
from the vulnerable function to every public API that reaches it, following `__init__` re-exports and
registry tables (`FILTERS = {"xmlattr": do_xmlattr}`, `add_constructor(tag, fn)`). The verdict path
then continues inside the library:

```
app.main -> app.fetch -> requests.Session.get -> Session.request -> Session.send
         -> SessionRedirectMixin.resolve_redirects -> SessionRedirectMixin.rebuild_proxies
```

Transitive dependencies get the same treatment one level up: if the app imports `requests` and a
vulnerable `urllib3` is pinned, TraceLock computes which `requests` functions reach `urllib3`'s
entry API and matches the app against those. A transitive edge never yields NOT_REACHABLE; only
REACHABLE (with the stitched two-package chain) or UNCERTAIN.

## Runtime confirmation (optional)

`tracelock trace <project> -- python app.py` runs the command with a profiler hook that watches the
vulnerable symbols. A hit upgrades the finding to `REACHABLE (runtime)` with the real stack; the
profiler records call arguments, so `yaml.safe_load`, which internally calls `yaml.load(stream,
SafeLoader)`, is not mistaken for a hit. This executes the target application and is only for code
you trust; static analysis never executes anything.

## Limitations, stated plainly

- Reachable means the code can call the vulnerable function, not that attacker-controlled input
  reaches it. There is no taint analysis.
- Dispatch tables, C extensions, plugins loaded by name and monkey-patching produce UNCERTAIN, not
  NOT_REACHABLE.
- Call resolution is name-based with light typing (imports, constructors, `self`, annotations, one
  level of return types, class bases). Receivers it cannot type are reported as unresolved and block a
  "safe" verdict instead of being guessed.
- Unpinned dependency specifiers are skipped with a warning; pin your versions or scan from a venv.
