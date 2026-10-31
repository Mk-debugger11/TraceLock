# BRIEF — Mukul — platform, outputs, demo surface

## Context (read once)

TraceLock is a hackathon entry: a Python vulnerability **reachability** analyzer. Input: a Python
project folder pinned to vulnerable dependency versions. Output: for each advisory, a verdict
REACHABLE / NOT_REACHABLE / UNCERTAIN with evidence. Judges run it on small apps where some call
the vulnerable function and some do not; they may hand us a folder or a zip, not a GitHub URL.

You already built the FastAPI backend (scan queue, worker, hardened GitHub fetcher, tests) and
the React form. The analysis engine now exists as a package, `backend/tracelock/`, with a working
CLI. Your job: make the engine fetch dependency source safely, produce the output formats judges
and real pipelines want, and wire the engine into your worker and UI so the demo looks like a
product. Kartik owns the engine (`app_graph.py`, `lib_graph.py`, `verdict.py`, `__init__.py`),
Vaibhav owns data (`deps.py`, `osv.py`, `kb/`, `data/`, `benchmark/`). Do not edit their files.
`models.py` is the frozen contract; read it first — the JSON you render is `to_dict(ScanResult)`.

You own: `backend/tracelock/pypi_source.py`, `report.py`, `cli.py`, everything under
`backend/app/`, `backend/tests/`, `frontend/`, the root `README.md`, and the pitch.

Start by running:

```
cd backend && python -m tracelock.cli scan ../benchmark/three_hop_chain --offline --json /tmp/r.json
cat /tmp/r.json | head -60
cd .. && python benchmark/run.py
```

Then read `models.py`, `report.py`, `pypi_source.py`, `cli.py`, `tracelock/__init__.py`.

## Task 1 (0:15–0:35): ingestion for local folders and zips (`backend/app/ingestion/`)

Add two sources beside GitHub in `fetch_repository` (or a sibling function with the same return
type `RepositoryMetadata`): a local directory path (copy it into the scan workspace, skipping
`.git`, `.venv`, `node_modules`) and an uploaded zip (extract safely: reject absolute member
paths and `..`, cap total extracted size at 50 MB and member count at 5,000, never follow
symlinks). `POST /api/analyze` currently echoes; make it create a real scan: for `repo_type=github`
call the existing path, for `repo_type=upload` save the file and queue a zip scan, and add
`repo_type=local` with a `path` field for the demo. Keep the existing tests green; add one test
per new source using a temp directory.

## Task 2 (0:35–1:15): dependency source without execution (`pypi_source.py`)

The docstring has the 5-step design. Essentials:

- Check `backend/tracelock/data/wheels/` first (pre-downloaded seed wheels, see task 2b), then
  `.tracelock/cache/src/<name>-<version>/`.
- Otherwise `python -m pip download <name>==<version> --no-deps --only-binary :all: -d <cache>`
  (timeout 60 s, `subprocess.run` with a list, never a shell). On failure retry with
  `--no-binary :all:` to get an sdist.
- Wheel = zip → extract to `.tracelock/cache/src/<name>-<version>/`, rejecting absolute or `..`
  members. Sdist = tar.gz → extract, then use the inner `<name>-<version>/src/` or
  `<name>-<version>/` directory that contains the package.
- Return the directory containing the top-level package (`yaml/__init__.py` lives directly in it).
- Side effects on the `Dependency` passed in (mutate in place; the contract allows it):
  `import_names` from `<dist>.dist-info/top_level.txt` (fallback RECORD, fallback directories
  with `__init__.py`), and `requires` from `METADATA` `Requires-Dist:` lines — name only,
  lower-cased, extras and `; markers` stripped, and **drop entries whose marker names an extra**
  (`extra == "socks"`) so optional deps do not create false transitive edges.
- `offline=True` → never call pip; return the cache or None.

2b. Pre-download wheels for the seed packages into `backend/tracelock/data/wheels/` (pyyaml 5.3,
jinja2 3.1.2, requests 2.30.0 and 2.31.0, urllib3 2.0.6, pillow 10.1.0, werkzeug 2.2.2, flask 2.2.5,
pyjwt 2.3.0, python-multipart 0.0.6, aiohttp 3.9.1, black 23.12.1, setuptools 69.0.3). Pillow,
aiohttp, cryptography and black wheels are platform-specific and large: for those download the
sdist instead (`--no-binary :all:`), or skip the binary-heavy ones and note it in chat. Keep the
folder under 60 MB; add `*.whl`/`*.tar.gz` to git LFS only if the repo rejects them, otherwise
commit them directly.

Acceptance: `python -c "from tracelock import pypi_source, models; d=models.Dependency('pyyaml','5.3'); print(pypi_source.fetch(d), d.import_names, d.requires)"`
prints a path ending in `pyyaml-5.3`, `['yaml']` (plus `_yaml`), and `[]`; for `requests==2.31.0`
`requires` contains `urllib3`, `certifi`, `charset-normalizer`, `idna` and not `pysocks`.

## Task 3 (1:15–1:45): OpenVEX and SARIF (`report.py`)

- `to_openvex(result)`: OpenVEX document (`@context` `https://openvex.dev/ns/v0.2.0`, `@id`,
  `author: "TraceLock"`, `timestamp`, `version: 1`, `statements: [...]`). One statement per finding:
  `vulnerability: {"name": advisory.id}` (plus `aliases`), `products: [{"@id": "pkg:pypi/<name>@<version>"}]`,
  `status`: `affected` for REACHABLE, `not_affected` with
  `justification: "vulnerable_code_not_in_execute_path"` and `impact_statement` = a one-line
  checklist summary for NOT_REACHABLE, `under_investigation` with `action_statement` = the first
  reason's `check` text for UNCERTAIN. Validate the JSON shape against https://github.com/openvex/spec.
- `to_sarif(result)`: SARIF 2.1.0. `tool.driver.name = "TraceLock"`, one rule per advisory id
  (`shortDescription` = summary), one result per REACHABLE (level `error`) and UNCERTAIN
  (level `warning`) at the call-site location (`physicalLocation.artifactLocation.uri`,
  `region.startLine`), and the path as `codeFlows[0].threadFlows[0].locations[]`. NOT_REACHABLE
  findings are omitted from results.
- Optional, 15 minutes max: if `rich` imports, colour the verdict word in `render_terminal`
  (green/red/yellow) and keep the plain renderer as fallback. Do not add `rich` to requirements.

Acceptance: `python -m tracelock.cli scan ../benchmark/pyyaml_direct --offline --vex /tmp/v.json --sarif /tmp/s.sarif`
writes both files; `python -m json.tool` accepts them.

## Task 4 (1:45–2:30): wire the engine into the worker and API (`backend/app/`)

- After `repository_fetched`, the worker calls `tracelock.scan(Path(scan.workspace_path), offline=settings)`
  in the same worker process (it is CPU-bound and already off the API process). Store
  `report.to_dict(result)` in a new JSON column `scans.result`, set `stage="analyzed"`,
  `status="done"`, `progress=100`. On exception: `status="failed"`, message
  `"Analysis failed: <short>"`, log the traceback.
- New endpoints: `GET /api/scans/{id}/result` (the JSON), `GET /api/scans/{id}/result.vex.json`,
  `GET /api/scans/{id}/result.sarif`. Keep the `{"error": ...}` format on failures.
- Progress: set `stage="analysis"`, `progress=60` when the scan starts so the UI can show it.
- Tests: one worker test with a fixture folder copied into the workspace (no network:
  `offline=True`) asserting `status="done"` and a REACHABLE finding for pyyaml.

## Task 5 (2:30–3:15): the evidence view (`frontend/src/`)

Make the form submit to `POST /api/scans` (or your new `/api/analyze` that creates a scan), poll
`GET /api/scans/{id}` until `done`, then fetch `/result` and render:

- A summary bar: N reachable / N not reachable / N uncertain, and the scan time.
- One card per finding, sorted REACHABLE → UNCERTAIN → NOT_REACHABLE. Verdict pill (red / amber /
  green), advisory id + aliases, package and version → fixed version, the `functions` line with its
  tier badge (`curated`, `fix_commit`, `llm_verified`, `none`).
- REACHABLE: the `path` as a vertical stepper: `file:line qualname` and the code line under each
  step, ending at the target symbol; `entry` kind label; a "fix commit" link when present.
- NOT_REACHABLE: the `checklist` as a tick list (true → check, false → cross).
- UNCERTAIN: the `reasons` list: kind badge, `file:line`, detail, and the `check` line in italics.
- Buttons: download JSON, OpenVEX, SARIF (the endpoints from task 4).

No analysis logic in the frontend. If the backend is not ready, build against `/tmp/r.json`
served statically. Keep it to one page; polish beats features here.

## Task 6 (3:15–3:45): README, pitch, backup demo

- Rewrite the root `README.md` from the existing draft so every claim is true today: the pipeline,
  the three verdicts and their exact rules (copy from `verdict.py` docstring), the checklist, the
  tiers, the benchmark table from `benchmark/RESULTS.md` (Vaibhav), how to run the CLI and the web
  UI, limitations (no taint analysis; dynamic dispatch and C extensions produce UNCERTAIN).
- Five slides: title + one-liner ("govulncheck for Python: evidence-backed, never bluffs safe");
  the problem (pip-audit screenshot); how it works (the architecture drawing from the plan doc);
  verdict rules + checklist; benchmark table + OpenVEX. Everything else is the live terminal.
- Record a 90-second screen capture of the three terminal runs (reachable / not reachable /
  uncertain) and one web UI result page, as the backup if the venue network or laptop fails.

## Rules

- `python benchmark/run.py` and `pytest` before every commit.
- Never execute downloaded dependency code: download, unzip, parse only.
- Commit messages `platform: ...` / `ui: ...` / `report: ...`; branch `feat/mukul`; merge to
  `main` at 1:30, 2:15, 3:15. If the UI is not demo-ready at 3:15, stop and polish the terminal
  output instead; the UI is a bonus, the CLI is the product.
