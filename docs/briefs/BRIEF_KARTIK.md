# BRIEF — Kartik — the analysis engine

## Context (read once)

TraceLock is a hackathon entry: a Python vulnerability **reachability** analyzer. Input: a Python
project folder pinned to vulnerable dependency versions. Output: for each advisory, a verdict
REACHABLE / NOT_REACHABLE / UNCERTAIN with evidence (a call chain with file:line, or a checklist,
or a reason plus what to check). Judges run it on small apps where some call the vulnerable
function and some do not. The single scoring rule: a wrong "NOT_REACHABLE" is the worst
possible outcome; UNCERTAIN with a reason is acceptable; REACHABLE must show the path.

You own the engine: `backend/tracelock/app_graph.py`, `lib_graph.py`, `verdict.py`,
`__init__.py` (the `scan()` glue) and, if time, `tracer.py`. Two teammates work in parallel:
Vaibhav on data (`deps.py`, `osv.py`, `kb/`, `benchmark/`), Mukul on platform (`pypi_source.py`,
`report.py`, `cli.py`, the FastAPI worker and the React UI). Do not edit their files; if you need
something from them, write the need in the group chat and stub around it.

`backend/tracelock/models.py` is the shared contract. Do not change field names. If you must add
a field, add it with a default, announce it, and update `to_dict` if needed.

Start by running:

```
cd backend && python -m tracelock.cli scan ../benchmark/three_hop_chain --offline
cd .. && python benchmark/run.py
```

Then read, in this order: `models.py`, `app_graph.py`, `verdict.py`, `__init__.py`, `lib_graph.py`.
The docstrings at the top of each file say what exists and what is TODO.

## Task 1 (0:15–1:15): make `app_graph.py` robust on real apps

Acceptance: every fixture in `benchmark/` keeps passing, and the new fixtures Vaibhav adds
(alias_import, method_on_object, dead_code, star_import, jinja_xmlattr_template) pass as their
`expected.json` says. Work through these, committing after each:

1. **Base-class method lookup.** `self.foo()` inside `class B(A)` where `foo` is defined on `A`
   in the same module (or an imported app module) must resolve to `A.foo`. Keep a `bases` list on
   `FunctionInfo` for classes, resolve them through the scope, and in `record_call` fall back along
   bases when `Class.method` is not in `model.functions`.
2. **Loop and with targets.** `for s in sessions:` and `with requests.Session() as s:` bind `s`.
   For `with`, bind the target to the resolved context expression. For `for`, leave unbound (an
   unresolved receiver is reported honestly by the verdict engine).
3. **Return-type propagation (one level).** If an app function's last `return` statement is a
   constructor call or a resolvable name, remember `qualname -> dotted` in a map; then
   `x = make_session()` binds `x` to that dotted name. One pass is enough; do not iterate to a fixpoint.
4. **Conditional and try imports.** An import inside `try:`/`if` still counts as imported (it is
   today, because `visit_stmt` recurses). Add a `conditional=True` note on the import hit tuple only
   if cheap; otherwise skip.
5. **Star imports.** `from yaml import *` then `load(fh)`: today `load` is unbound. If
   `pypi_source.fetch` returns the library source (Mukul), expand the star import using
   `kb.llm._symbols_in(lib_src)`-style AST listing of the module's public names; otherwise leave
   the star import as a reason for UNCERTAIN (already implemented in `verdict.py`).
6. **Entry tagging.** Make sure functions decorated with `@app.route`, `@router.get`,
   `@celery.task`, `@click.command` get `entry_kind="route"`; `if __name__ == "__main__"` marks
   the module pseudo-function `main`; everything else stays `None` and is reported as `orphan`
   when it starts a chain. Never drop an orphan path: dead code is still REACHABLE.
7. **Templates.** `app_graph.build` already pulls `|filter` names and dotted tokens from
   `.html/.jinja/.j2/.yaml/...` files into `model.strings`. Check that `{{ attrs | xmlattr }}`
   produces a `StringRef("templates/page.html", line, "xmlattr")` and that the verdict for the
   Jinja fixture becomes UNCERTAIN with a `string_ref` reason (or REACHABLE if the team decides a
   curated filter name in a template counts as a call; agree in chat, then set `expected.json`).

Known gaps you may hit: relative imports inside the app that resolve to a module not yet parsed
are fine (names are dotted strings, resolution is by string). Nested functions get
`outer.inner` qualnames; that is fine.

## Task 2 (1:15–1:45): verdict engine polish (`verdict.py`)

1. **Path choice.** When several call sites hit, pick the one whose chain reaches a recognised
   entry (`main`/`route`/`module`) over an orphan; print all other sites as
   `Reason(kind="also_called_at", ...)` so the report shows "also at x.py:12, y.py:40".
2. **Safe-argument resolution.** `_safe_usage` compares kwarg *source text*. Improve it by
   resolving the kwarg expression through the call site's scope: add `kwargs_resolved: dict` to
   `CallSite` (filled in `record_call` with `self.resolve(kw.value, scope)`) and compare that
   first. `Loader=SafeLoader` with `from yaml import SafeLoader` must count as safe.
3. **Per-target reasons.** For UNCERTAIN, only flag `string_ref`/`unresolved_call` reasons whose
   name matches *this* advisory's targets (already the case), and cap reasons at 8 per finding,
   keeping the most specific kinds first: unresolved_call, string_ref, star_import, transitive,
   dynamic, no_function_data.
4. **Confidence.** Keep it informational; never let it flip a verdict.

## Task 3 (1:45–2:45): library-side exposure set (`lib_graph.py`) — the differentiator

Goal: turn "vulnerable internal function `jinja2.filters.do_xmlattr`" into the set of public
symbols that reach it, so apps that call public APIs are caught even when the advisory's function
is internal. Mukul's `pypi_source.fetch(dep)` returns the unpacked source root (the directory that
contains `yaml/` or `jinja2/`). Until his code lands, test with any locally unpacked wheel:
`pip download pyyaml==5.3 --no-deps --only-binary :all: -d /tmp/w && unzip /tmp/w/*.whl -d /tmp/src`.

1. Call `app_graph.build(lib_src)` on the library root. It already resolves relative imports and
   `self.method` calls and records unresolved last names. Module names come out rooted at the
   package (`yaml.constructor`), which is exactly what we need.
2. Reverse BFS from each `spec.vulnerable_funcs` entry, depth ≤ 8. A caller connects when its
   resolved callee equals the target, or when the callee is unresolved and the last name matches
   the target's last name (over-approximate on purpose, this is the safe direction).
3. Follow re-exports: in `pkg/__init__.py`, `from .filters import do_xmlattr` (or
   `load = _some.load`) means `pkg.do_xmlattr` is an alias of the target. Add aliases to the set.
4. Return the reachable set plus the targets. The verdict engine already unions `exposure` into
   `targets`; public names (no `_` segment) are what the app analyzer will match by last name.
5. Cache the library `AppModel` with `pickle` under `.tracelock/cache/graph/<name>-<version>.pkl`.
6. Add a fixture with Vaibhav where the curated entry has only `vulnerable_funcs` and no
   `entry_api` (e.g. a copy of the PyYAML entry with `entry_api: []`) and confirm REACHABLE is still
   produced through the exposure set. Note the known dispatch-table gap (PyYAML constructors are
   called via a dict); that is why curated `entry_api` stays as the safety net.

Acceptance: `python benchmark/run.py` still 100%, and on the Jinja fixture the finding's
`functions:` line shows names that came from the exposure set (tier stays whatever the KB said).

## Task 4 (2:45–3:15): transitive rule, two levels

`verdict.decide` already marks UNCERTAIN when the vulnerable package is required by a package the
app imports (`Dependency.requires`, filled by Mukul's `pypi_source.fetch` from `Requires-Dist`).
Upgrade it: compute the exposure set of the *importing* package too (which `requests` public
symbols call into `urllib3`'s entry API) by running `lib_graph.exposure_set` on `requests` with
`vulnerable_funcs = urllib3 entry API`, and check the app's calls against that. If a path exists,
REACHABLE with a chain that ends `... -> requests.Session.request -> urllib3.PoolManager.urlopen`.
If not, stay UNCERTAIN (never NOT_REACHABLE across a transitive edge in this version).

## Task 5 (stretch, only if the benchmark is 100% at 3:15): runtime tracer (`tracer.py`)

The docstring in `tracer.py` has the full design (sitecustomize + `sys.setprofile`, ~80 lines).
Wire `tracelock trace <root> -- python app.py` into `cli.py` (coordinate with Mukul: he owns
`cli.py`; send him the 10-line subcommand) and pass the result into `scan(trace=...)`. The demo
line is "static says there is a path; here is the program actually hitting the function".

## Rules

- Run `python benchmark/run.py` before every commit. FALSE SAFE must be 0.
- Prefer UNCERTAIN over NOT_REACHABLE whenever a rule is in doubt.
- No new third-party dependencies in the engine; stdlib `ast` only (judges run it anywhere).
- Keep functions small and typed; the other two Claudes read your code through the docstrings.
- Commit messages: `engine: <what>`; branch `feat/kartik`; merge to `main` at 1:30, 2:15, 3:15.
