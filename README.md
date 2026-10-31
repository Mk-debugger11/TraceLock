# TraceLock

**govulncheck for Python: evidence-backed, never bluffs safe.**

`pip-audit` tells you PyYAML 5.3 has four advisories. It says exactly the same thing about an app that
calls `yaml.full_load` on uploaded files, an app that only uses `yaml.safe_load`, and an app that never
imports `yaml` at all. TraceLock answers the question that matters: **can this application reach the
vulnerable code?** For every advisory it returns REACHABLE (with the call chain, `file:line` for every
step), NOT_REACHABLE (only when a printed soundness checklist fully holds), or UNCERTAIN (with the exact
line a human should check). Doubt always resolves to UNCERTAIN, never to "safe". Results come out as
terminal text, JSON, OpenVEX and SARIF.

```
REACHABLE     GHSA-8q59-q68h-6hv4  pyyaml 5.3 -> fixed 5.4    confidence 0.95
  aliases:   CVE-2020-14343, PYSEC-2021-142
  functions: yaml.load, yaml.load_all, yaml.full_load, yaml.full_load_all, yaml.unsafe_load, ...  (curated, fix commit a001f27825)
  path:      app/main.py:5 app.main.main  ->  app/settings.py:10 app.settings.load_settings  ->  app/settings.py:5 app.settings._read  ->  yaml.full_load
             app/settings.py:5 | return y.full_load(fh)
  entry:     main
  fix:       upgrade pyyaml>=5.4
```

---

## Quick start

### CLI

The engine (`backend/tracelock/`) needs only Python 3.11+ and its standard library (`packaging` and
`rich` are used when present).

```bash
cd backend
python -m tracelock.cli scan ../benchmark/three_hop_chain --offline     # REACHABLE, 3-step chain
python -m tracelock.cli scan ../benchmark/pyyaml_safe_load --offline    # NOT_REACHABLE, with checklist
python -m tracelock.cli scan ../benchmark/getattr_dynamic --offline     # UNCERTAIN, with the line to check

# machine-readable outputs
python -m tracelock.cli scan ../benchmark/pyyaml_direct --offline \
    --json result.json --vex result.vex.json --sarif result.sarif

# runtime confirmation: EXECUTES the command inside the project (trusted code only)
python -m tracelock.cli trace ../benchmark/pyyaml_direct --offline -- python -m app.main config.yaml
```

| flag | meaning |
| --- | --- |
| `--offline` | never touch the network: OSV from the bundled snapshot/cache, dependency source from `tracelock/data/wheels/` and `.tracelock/cache/` |
| `--json FILE` / `--vex FILE` / `--sarif FILE` | write the full result, an OpenVEX document, a SARIF 2.1.0 log |
| `--no-sources` (`scan`) | skip fetching dependency source; curated knowledge base only |
| `--fail-on reachable\|uncertain` | which verdicts make the exit code 1 (default `reachable`) |
| `--timeout S` (`trace`) | kill the traced command after S seconds (default 60) |
| `--quiet` | no terminal report |

Exit codes: `0` nothing matching `--fail-on`, `1` at least one matching finding, `2` tool error (never a
silent pass). `trace` runs the command with your current interpreter and environment, so the app's own
dependencies must be importable (activate its virtualenv first). Everything after `--` is passed to the
command untouched.

### Web UI

Backend (FastAPI; the API starts the scan worker as a child process):

```bash
cd backend
python -m venv venv && venv/bin/pip install -r requirements.txt
TRACELOCK_ALLOW_LOCAL_PATHS=1 TRACELOCK_OFFLINE=1 venv/bin/python -m uvicorn app.main:app --port 5001
```

Frontend (React + Vite, http://localhost:3000):

```bash
cd frontend
npm install
npm run dev
```

Submit a GitHub URL and branch, a `.zip` of the project, or (with `TRACELOCK_ALLOW_LOCAL_PATHS=1`) an
absolute folder path on the server. The page polls the scan, then shows the summary, one card per
finding with its call path, checklist or reasons, and JSON / OpenVEX / SARIF downloads. `?scan=<id>` in
the URL reopens a result.

| environment variable | default | effect |
| --- | --- | --- |
| `TRACELOCK_ALLOW_LOCAL_PATHS` | `0` | `1` enables local-folder scans. Off by default: a local scan copies any folder the server can read into the workspace |
| `TRACELOCK_OFFLINE` | `0` | `1` keeps the worker's engine off the network (same as `--offline`). Without it, OSV is queried live and falls back to the snapshot if the network fails |
| `TRACELOCK_WORKSPACE_ROOT` | `<repo>/workspace` | where fetched projects and uploads are stored |
| `TRACELOCK_DATABASE_URL` | `sqlite:///<repo>/tracelock.db` | scan database |
| `TRACELOCK_RUN_WORKER` | `1` | `0` to run the worker yourself with `python -m app.worker` |
| `VITE_API_URL` (frontend) | `http://127.0.0.1:5001` | API base URL |

| endpoint | purpose |
| --- | --- |
| `POST /api/analyze` | form: `repo_type=github` (`repo_url`, `branch`), `upload` (`repo_file`, .zip), `local` (`path`); queues a scan |
| `POST /api/scans` | JSON `{repository_url, ref}`; queues a GitHub scan |
| `GET /api/scans/{id}` | status, stage (`queued` → `repository_fetch` → `analysis` → `analyzed`), progress, error |
| `GET /api/scans/{id}/result` | the full result JSON (`to_dict(ScanResult)`); 409 until the scan is done |
| `GET /api/scans/{id}/result.vex.json` / `result.sarif` | OpenVEX / SARIF downloads |
| `POST /api/branches` | `{repo_url}` → branch names, for the form |

Errors are always `{"error": "..."}`.

---

## How a verdict is reached

### Pipeline

```
requirements / pyproject / venv  ->  OSV advisories (cached, offline snapshot)
                                 ->  knowledge base: which functions are dangerous, and how we know
app source  --AST-->  bindings, calls, entry points, dynamic markers, string refs
library source (downloaded, never executed)  --AST-->  exposure set: public APIs that reach the vulnerable code
                                 ->  verdict engine  ->  REACHABLE | NOT_REACHABLE | UNCERTAIN, with evidence
optional: runtime tracer runs the app under a profiler and confirms a hit with the live stack
```

### The three verdicts

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

### Finding the vulnerable functions when the advisory does not name them

| tier | source | confidence |
| --- | --- | --- |
| `curated` | hand-verified entry in `kb/curated.json` (functions, public entry API, safe-usage rules, fix commit) | 0.95 |
| `ecosystem_specific` | PyPA's `imports` field in the OSV record, when present (~5% of PyPI advisories) | 0.9 |
| `fix_commit` | the advisory's fix commit diff, each hunk mapped to its enclosing function by parsing the pre-fix file (hunk headers are not trusted) | 0.7 |
| `llm_verified` | an LLM proposes public entry points from the advisory + diff; every name is checked against the installed library source before use. The LLM never decides a verdict | 0.6 |
| `none` | nothing usable: the verdict can only be UNCERTAIN | 0 |

Tiers merge rather than replace: a curated safe-usage rule still applies when the fix-commit tier adds functions.

### Library-side analysis (exposure set)

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

### Runtime confirmation (optional)

`tracelock trace <project> -- python app.py` runs the command with a profiler hook that watches the
vulnerable symbols. A hit upgrades the finding to `REACHABLE (runtime)` with the real stack; the
profiler records call arguments, so `yaml.safe_load`, which internally calls `yaml.load(stream,
SafeLoader)`, is not mistaken for a hit. This executes the target application and is only for code
you trust; static analysis never executes anything.

### Limitations, stated plainly

- Reachable means the code can call the vulnerable function, not that attacker-controlled input
  reaches it. There is no taint analysis.
- Dispatch tables, C extensions, plugins loaded by name and monkey-patching produce UNCERTAIN, not
  NOT_REACHABLE.
- Call resolution is name-based with light typing (imports, constructors, `self`, annotations, one
  level of return types, class bases). Receivers it cannot type are reported as unresolved and block a
  "safe" verdict instead of being guessed.
- Unpinned dependency specifiers are skipped with a warning; pin your versions or scan from a venv.

---

## Outputs

**Terminal** — one block per finding, REACHABLE first, then UNCERTAIN, then NOT_REACHABLE, and a
summary line. Verdict words are coloured when `rich` happens to be installed (it is not a requirement).

**JSON** (`--json`, `GET /result`) — `to_dict(ScanResult)` from `backend/tracelock/models.py`: every
dependency, and per finding the advisory (id, aliases, fixed version, fix links), the knowledge-base spec
and tier, the verdict, confidence, `path` (`qualname`, `file`, `line`, `code` per step), `entry_kind`,
`reasons`, `checklist` and `runtime`. The web UI renders exactly this.

**OpenVEX v0.2.0** (`--vex`, `GET /result.vex.json`) — one statement per finding, product
`pkg:pypi/<name>@<version>`, vulnerability = advisory id plus aliases:

| verdict | `status` | extra fields |
| --- | --- | --- |
| REACHABLE | `affected` | `action_statement`: the symbol called, the call site, and the upgrade |
| NOT_REACHABLE | `not_affected` | `justification: vulnerable_code_not_in_execute_path`, `impact_statement`: the checklist summary |
| UNCERTAIN | `under_investigation` | `action_statement`: the first reason's check |

**SARIF 2.1.0** (`--sarif`, `GET /result.sarif`) — tool `TraceLock`, one rule per advisory id (summary,
details, fix link). One result per REACHABLE finding (level `error`) at the call site, with the call path
as `codeFlows[0].threadFlows[0].locations`, and per UNCERTAIN finding (level `warning`) at the reason's
location. NOT_REACHABLE findings are omitted. App paths are relative to `%SRCROOT%` (the scanned root).

Both formats were validated against the official OpenVEX and SARIF JSON schemas.

---

## Benchmark

See [`benchmark/RESULTS.md`](benchmark/RESULTS.md) (table to be pasted here when it lands).

`python benchmark/run.py` scans every fixture in `benchmark/` offline and compares against its
`expected.json`; a false NOT_REACHABLE is counted separately as **FALSE SAFE** and must stay at 0. Five
of the fixtures pin exactly `pyyaml==5.3`, so `pip-audit` prints the same four advisories for all of
them, while TraceLock separates them into REACHABLE, NOT_REACHABLE and UNCERTAIN.

---

## Security notes

- **Scanned code is parsed, never executed.** GitHub repos are shallow-cloned with system/global git
  config and credential prompts ignored, a timeout, and symlinks checked out as plain files. Uploaded zips are extracted with absolute and `..` member paths rejected, at most
  50 MB of real (not declared) bytes and 5,000 entries, and no symlinks created. Local folders are copied
  without `.git`, virtualenvs, `node_modules` or symlinks, and are disabled unless
  `TRACELOCK_ALLOW_LOCAL_PATHS=1`.
- **Dependency source is downloaded and parsed, never installed or imported.** Wheels come from the
  bundled seeds, the cache, or `pip download --only-binary :all:`. When no wheel fits this interpreter,
  TraceLock fetches a file from the PyPI JSON API and verifies its sha256 instead of using
  `pip download --no-binary`, which would run an sdist's `setup.py`; platform wheels (e.g. pillow, aiohttp)
  are fine because only their `.py` files are read. Archives are extracted with the same path, link and
  size checks.
- **`trace` is the one command that executes code.** It runs the command you give it, with your
  interpreter and environment, and says so on stderr before it starts. Use it only on code you trust.

---

## Repository layout

```
backend/tracelock/   the engine and CLI (scan, report formats, PyPI source fetcher, tracer)
backend/app/         FastAPI API, ingestion (GitHub / zip / local), background worker
backend/tests/       pytest suite for API, ingestion, worker, PyPI source and report formats
benchmark/           fixture apps with expected verdicts, and run.py
frontend/            React + Vite results UI
docs/                team briefs, pitch slides
```

Team T032 (Mukul Kumar, Kartik Madaan, Vaibhav Vats), Problem 03: Python Vulnerability Reachability
Analyzer. See [Hackathon.md](Hackathon.md).
