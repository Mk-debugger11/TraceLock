# BRIEF — Vaibhav — data, knowledge base, benchmark

## Context (read once)

TraceLock is a hackathon entry: a Python vulnerability **reachability** analyzer. Input: a Python
project folder pinned to vulnerable dependency versions. Output: for each advisory, a verdict
REACHABLE / NOT_REACHABLE / UNCERTAIN with evidence. Judges run it on small apps where some call
the vulnerable function and some do not. A wrong "NOT_REACHABLE" is the worst outcome.

The hard problem the judges explicitly test: PyPI advisories almost never name the vulnerable
function (about 5% do). Your job is to make the tool know *which functions* are dangerous for
every advisory, with provenance, and to build the benchmark that proves the whole tool works.

You own: `backend/tracelock/deps.py`, `osv.py`, `kb/` (`__init__.py`, `curated.json`,
`fixdiff.py`, `llm.py`), `backend/tracelock/data/**`, and `benchmark/**`. Kartik owns the
engine (`app_graph.py`, `lib_graph.py`, `verdict.py`), Mukul owns platform (`pypi_source.py`,
`report.py`, `cli.py`, FastAPI, React). Do not edit their files. `models.py` is the frozen
contract; read it first.

Start by running:

```
cd backend && python -m tracelock.cli scan ../benchmark/pyyaml_direct --offline
cd .. && python benchmark/run.py
```

Then read `models.py`, `kb/__init__.py`, `kb/curated.json`, `osv.py`, `deps.py`, `benchmark/run.py`.

## Task 1 (0:15–0:45): fixtures 7–15 in `benchmark/`

Each fixture = folder with `requirements.txt` (pinned `name==version`), 1–3 `.py` files, and
`expected.json` mapping advisory ids (use the CVE alias) to verdicts. Keep apps tiny and realistic.
Add these (6 already exist: pyyaml_direct, pyyaml_safe_load, pyyaml_safeloader_kwarg,
not_imported, three_hop_chain, getattr_dynamic):

| Folder | App | expected |
| --- | --- | --- |
| `alias_import` | `import yaml as y; y.full_load(fh)` in one function, `from yaml import load as ld; ld(fh)` in another | REACHABLE |
| `getattr_literal` | `getattr(yaml, "load")(fh)` | REACHABLE |
| `pyyaml_loader_variable` | `yaml.load(fh, Loader=cfg.loader)` | REACHABLE (reason safe_arg_variable) |
| `method_on_object` | `requests==2.30.0`; `s = requests.Session(); s.get(url)` | REACHABLE for CVE-2023-32681 (after you curate it) |
| `dead_code` | pyyaml; `yaml.load` inside `unused_helper()` nobody calls | REACHABLE |
| `star_import` | `from yaml import *; load(fh)` | UNCERTAIN (REACHABLE once star expansion lands) |
| `jinja_xmlattr_template` | `jinja2==3.1.2`; Flask-free: `Environment(loader=FileSystemLoader("templates")).get_template("page.html").render(attrs=...)`, template contains `{{ attrs \| xmlattr }}` | UNCERTAIN (string_ref) — agree with Kartik whether to make it REACHABLE |
| `pillow_imagemath` | `pillow==10.1.0`; `from PIL import ImageMath; ImageMath.eval(expr, a=img)` | REACHABLE for CVE-2023-50447 |
| `pillow_safe` | `pillow==10.1.0`; only `Image.open(...).resize(...)` | NOT_REACHABLE |
| `transitive_urllib3` | `urllib3==2.0.6`, `requests==2.31.0`; app calls `requests.get(url)` only | UNCERTAIN for CVE-2023-45803 (transitive) |

Acceptance: `python benchmark/run.py` lists every fixture; failures are allowed at this stage
only for fixtures whose feature is not built yet, and you post the list of failing rows in chat.

## Task 2 (0:45–1:30): `osv.py` snapshot and `deps.py` formats

1. For every package in the seed list below, fetch the real OSV records once (online) and save
   them into `backend/tracelock/data/osv_snapshot.json` under the normalised package name (same
   shape as `api.osv.dev/v1/vulns/<id>`; the loader already filters by version range). Use
   `python - <<EOF` with `urllib.request` against `https://api.osv.dev/v1/query` with
   `{"package": {"name": ..., "ecosystem": "PyPI"}}` (no version → all advisories for the package).
   Keep only PyPI-affected records; drop `withdrawn` ones.
2. `deps.py`: add `poetry.lock`, `uv.lock`, `Pipfile.lock` (all list exact versions; parse with
   `tomllib`/`json`), and a venv inside the project (`.venv/lib/python*/site-packages/*.dist-info/METADATA`
   → Name/Version). Precedence: lock file > venv > requirements > pyproject. Unpinned specs
   (`requests>=2`) go into `ScanResult.warnings` via a module-level `WARNINGS` list that
   `scan()` can read (coordinate the one-line hook with Kartik) and are skipped.
3. `osv.lookup`: add retry with backoff (3 tries), and when the live call fails, write a warning
   string into the returned data? No — keep the signature; instead print to stderr and fall back.

## Task 3 (1:00–1:45, overlaps): curate the knowledge base (`kb/curated.json`)

One entry per advisory id (the CVE alias as key; the resolver also matches GHSA/PYSEC aliases).
Fields: `package`, `vulnerable_funcs` (internal, dotted by *import* name), `entry_api` (public
symbols app code would call), `safe_usage` (kwarg rules), `fix_commit`, `confidence`, `notes`.
Verify each one by opening the fix commit on GitHub and reading the diff; do not trust memory.

Seed list (vulnerable pin → advisory → what to look for):

- pyyaml 5.3 → CVE-2020-14343, CVE-2020-1747 — done; verify the fix commit sha.
- jinja2 3.1.2 → CVE-2024-22195 (GHSA-h5c8-rqwp-cp95) — `jinja2.filters.do_xmlattr`; fix
  commit 716795349a41d4983a9a4771f7d883c96ea17be7. Also jinja2 3.1.3 → CVE-2024-34064.
- requests 2.30.0 → CVE-2023-32681 — Proxy-Authorization leaked on redirect; functions in
  `requests/sessions.py` (`Session.rebuild_proxies`, reached from `Session.request`/`send`,
  `requests.get/post/...`).
- requests 2.31.0 → CVE-2024-35195 — `verify=False` sticks on the Session; `Session.send`.
- urllib3 2.0.6 → CVE-2023-45803 — body not stripped on 303; `urllib3.PoolManager.request`,
  `HTTPConnectionPool.urlopen`, `urllib3.request`.
- urllib3 1.26.17 → CVE-2023-43804 — Cookie header on redirect.
- pillow 10.1.0 → CVE-2023-50447 — `PIL.ImageMath.eval` (environment keys). pillow 9.3.0 →
  CVE-2022-22817 — same function.
- werkzeug 2.2.2 → CVE-2023-25577 — multipart parts unlimited; `werkzeug.formparser`.
- werkzeug 3.0.2 → CVE-2024-34069 — debugger; `werkzeug.debug.DebuggedApplication`,
  safe_usage: `debug=False`.
- flask 2.2.5 → CVE-2023-30861 — `flask.sessions.SecureCookieSessionInterface.save_session`.
- setuptools 69.0.3 → CVE-2024-6345 — `setuptools.package_index.PackageIndex` download methods.
- pyjwt 2.3.0 → CVE-2022-29217 — `jwt.decode` / `jwt.api_jws.PyJWS.decode` algorithm confusion.
- python-multipart 0.0.6 → CVE-2024-24762 — `multipart.multipart.parse_options_header` ReDoS.
- aiohttp 3.9.1 → CVE-2024-23334 — `aiohttp.web.Application.router.add_static` with
  `follow_symlinks=True`; safe_usage: kwarg absent/False → safe.
- black 23.12.1 → CVE-2024-21503 — `black.format_str`/`format_file_contents` ReDoS.
- cryptography 41.0.5 → CVE-2023-49083 — `cryptography.hazmat.primitives.serialization.pkcs7.load_pem_pkcs7_certificates` and `load_der_pkcs7_certificates`.
- certifi, tqdm (any pinned vulnerable version) — decoys for "not imported" fixtures.

Acceptance: every seed advisory resolves to tier `curated` with non-empty `entry_api`;
`python benchmark/run.py` passes for pyyaml, jinja2, pillow, requests fixtures.

## Task 4 (1:45–2:30): fix-commit tier (`kb/fixdiff.py`) — the "advisories don't name functions" answer

The docstring in `fixdiff.py` has the 8-step design. Summary: from `Advisory.fix_urls` pick
GitHub commit URLs (and PR URLs → `.patch` to get the sha), download `<commit>.diff`, parse hunks
for `.py` files, fetch the pre-fix file via the GitHub contents API with `ref=<sha>^`, `ast.parse`
it, and map each hunk's old line range to the innermost enclosing `def`/`class` by line span.
Never trust the `@@ ... def foo` hunk header. Return `(qualnames, hunk_texts, commit_url)`.
Cache to `.tracelock/cache/fixes/<sha>.json` and copy the seed results into
`backend/tracelock/data/fixes/` so `--offline` works.

Test it on jinja2 CVE-2024-22195: it must return `jinja2.filters.do_xmlattr`. Test it on a
PyYAML fix commit: it should return the `FullConstructor` methods. Then temporarily delete the
jinja2 curated entry and confirm `kb.resolve` produces tier `fix_commit` with those functions.

## Task 5 (2:30–3:00): LLM tier, proposed-then-verified (`kb/llm.py`)

Docstring has the design. Use the API key available (`ANTHROPIC_API_KEY` or `OPENAI_API_KEY`) via
plain `urllib.request` (no SDK dependency). Prompt inputs: advisory summary + details, the
hunks from task 4, and the package's public symbol list (reuse `_symbols_in(lib_src)`; cap at 400
names). Ask for JSON `{"entry_api": [...], "vulnerable_funcs": [...], "reasoning": "..."}`.
`kb.resolve` already filters proposals through `symbol_exists`; make sure a hallucinated name is
dropped (write a unit test with a fake name). Cache responses to
`backend/tracelock/data/llm_cache/<advisory_id>.json` and read the cache first; commit the cache
for the seed advisories so the demo never waits on the network.

The pitch line this enables: "LLM proposes, AST verifies, so it cannot hallucinate a function."

## Task 6 (3:00–3:45): numbers for the pitch

1. Make `benchmark/run.py` also print precision/recall for REACHABLE and for NOT_REACHABLE and
   write `benchmark/RESULTS.md` (a markdown table) — Mukul pastes it into the README.
2. Add `benchmark/real_flask_app/`: a ~200-line Flask app with 10 pinned packages from the seed
   list where only 2 are actually reachable. Record `pip-audit`-style count (10 advisories) vs
   our verdicts (2 reachable, 6 not reachable, 2 uncertain) for the "noise reduction" slide.
3. Screenshots of one REACHABLE, one NOT_REACHABLE, one UNCERTAIN terminal block for the slides.

## Rules

- `python benchmark/run.py` before every commit; FALSE SAFE must be 0.
- Everything you fetch from the network gets saved under `backend/tracelock/data/` so the demo
  works offline. Commit those files.
- Verify every curated function against the real diff; a wrong curated entry is a false safe.
- Commit messages `kb: ...` / `bench: ...` / `deps: ...`; branch `feat/vaibhav`; merge to `main`
  at 1:30, 2:15, 3:15.
