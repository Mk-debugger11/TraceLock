# Using TraceLock in a real project

## Install

```
pip install ./backend            # from a checkout; `pip install tracelock` once published
tracelock --version
tracelock scan .                 # static, never executes your code
tracelock scan . --explain       # adds a plain-language "why" under every finding
tracelock scan . --json out.json --vex out.vex.json --sarif out.sarif
tracelock trace . -- python app.py       # runtime confirmation; this one executes your app
```

Exit codes: `0` nothing reachable, `1` at least one REACHABLE (or UNCERTAIN with `--fail-on uncertain`),
`2` the tool itself failed. Accepted findings (below) never affect the exit code.

## Project config: `.tracelock.yml`

Put it at the project root. Everything is optional.

```yaml
accept:
  - id: CVE-2023-32681                 # advisory id or any alias (GHSA-…, PYSEC-…)
    reason: "no Proxy-Authorization header is ever set; proxies are not used"
    by: kartik
    until: 2026-12-31                  # expiry; after this date the finding counts again
    justification: vulnerable_code_cannot_be_controlled_by_adversary   # OpenVEX justification (optional)
ignore_paths: ["tests/", "examples/"]  # application files left out of the analysis
fail_on: reachable                     # or uncertain
offline: false
```

An accepted finding keeps its real verdict in the report, is marked `[ACCEPTED]`, is excluded from the
exit code, and appears in the OpenVEX document as `not_affected` with your justification and reason as
the `impact_statement`. That is the audit trail: who accepted what, why, and until when.

## CI: GitHub Actions

`.github/workflows/tracelock.yml` in this repo runs the test suite and the benchmark on every push, scans
the demo app, and uploads the SARIF to GitHub code scanning, so REACHABLE findings appear in the
repository's **Security → Code scanning** tab with the call path as a code flow. For your own project the
job is three steps:

```yaml
- run: pip install tracelock
- run: tracelock scan . --sarif tracelock.sarif --vex tracelock.vex.json
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: tracelock.sarif }
```

## pre-commit

```yaml
repos:
  - repo: https://github.com/Mk-debugger11/TraceLock
    rev: v0.2.0
    hooks:
      - id: tracelock
```

The hook runs on changes to manifests (`requirements*.txt`, `pyproject.toml`, lock files) and `.py` files.

## Docker

```
docker build -t tracelock --target cli .
docker run --rm -v "$PWD:/src" tracelock scan /src --offline

docker compose up            # API on :5001, UI on :3000; drop projects into ./projects and scan /projects/<name>
```

## Feeding other tools

- **OpenVEX** (`--vex`): `affected` / `not_affected` (justification `vulnerable_code_not_in_execute_path`,
  or yours for accepted findings) / `under_investigation`. Consumed by Docker Scout, Trivy, Grype and
  most SBOM platforms, so TraceLock's verdicts suppress or prioritise alerts in the scanner you already run.
- **SARIF** (`--sarif`): one result per REACHABLE (error) and UNCERTAIN (warning) with the call chain as a
  code flow; NOT_REACHABLE findings are omitted. Works with GitHub code scanning, VS Code's SARIF viewer, SonarQube.
- **JSON** (`--json`): the full result, including the checklist and reasons, for your own dashboards.

## Environment variables (server)

| variable | effect |
| --- | --- |
| `TRACELOCK_OFFLINE=1` | never call OSV or PyPI; use the bundled snapshot and wheels |
| `TRACELOCK_ALLOW_LOCAL_PATHS=1` | let the web UI scan folders on the server (off by default) |
| `TRACELOCK_DATABASE_URL` | SQLAlchemy URL for scan history (default SQLite in `backend/`) |
| `TRACELOCK_WORKSPACE_ROOT` | where fetched repositories are unpacked |
| `TRACELOCK_LLM_ENABLED` / `TRACELOCK_LLM_PROVIDER` | local LLM help (default off; provider `ollama`). An API key alone never enables a cloud model. See [LOCAL_LLM.md](LOCAL_LLM.md) |
| `OLLAMA_BASE_URL` / `OLLAMA_MODEL` | `http://127.0.0.1:11434` from the host, `http://ollama:11434` inside Compose; `qwen2.5-coder:3b` |
