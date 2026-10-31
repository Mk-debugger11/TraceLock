# TraceLock

**Reachability-aware vulnerability scanner for Python projects.**

TraceLock goes beyond traditional dependency scanners. Instead of just telling you *"this package has a known CVE,"* it answers the question that actually matters: **can your application reach the vulnerable code?**

Most vulnerability scanners flood developers with alerts for dependencies that are installed but never actually called. TraceLock uses static analysis — AST parsing, call graph construction, and reachability search — to separate real, exploitable risk from noise.

---

## Why TraceLock

```
pip-audit / safety / snyk          TraceLock
─────────────────────────          ─────────────────────────
"PyYAML 5.3 has CVE-2020-14343"    "PyYAML 5.3 has CVE-2020-14343,
                                     AND your app reaches it via:
❌ No idea if you use it            app.upload() → services.process()
❌ No idea if it's exploitable       → yaml.full_load()
❌ Just a list of CVE IDs           ✅ Confirmed reachable, with proof"
```

---

## How it works

TraceLock runs a repository through a pipeline of focused stages, each narrowing down from *"everything installed"* to *"what's actually exploitable."*

```
1.  Ingest              → safely clone/extract the repo
2.  Dependency Scanner   → parse requirements.txt into package + version
3.  OSV Lookup           → query the OSV database for known CVEs
4.  Knowledge Mapping    → map each CVE to its exact vulnerable function(s)
5.  Import Check         → is the vulnerable package even imported?
6.  AST Analyzer         → parse the app's source into functions/calls
7.  Call Graph Builder   → build a directed graph of function calls
8.  Entry Point Detection→ find routes, CLI entry points, __main__
9.  Reachability Engine  → BFS/DFS from entry points to vulnerable functions
10. Argument Check       → confirm the call site is actually unsafe
11. Evidence Generator   → produce a classified, evidence-backed result
12. LLM Report Writer    → turn evidence into a human-readable explanation
```

The LLM is used **only** to narrate results that have already been computed deterministically — it never decides whether something is vulnerable.

---

## Example output

**Input:** `PyYAML==5.3` detected in `requirements.txt`

**OSV lookup:** `CVE-2020-14343` — unsafe YAML loading

**Reachability result:**

```json
{
  "vulnerability": "CVE-2020-14343",
  "package": "PyYAML",
  "installed_version": "5.3",
  "status": "reachable",
  "evidence": {
    "entry_point": "app.upload",
    "call_path": [
      "app.upload",
      "services.process",
      "yaml.full_load"
    ],
    "source_files": ["app.py", "services.py"]
  },
  "limitations": []
}
```

### Classification statuses

| Status | Meaning |
|---|---|
| `Reachable` | A confirmed call path exists from an entry point to the vulnerable function |
| `Not imported` | The package is installed but never imported — no exposure |
| `No path found` | Searched, no path found within the analyzed scope (not a safety guarantee) |
| `Unknown` | CVE found via OSV but not yet mapped to a specific function |

---

## Architecture

### Frontend
- **Stack:** React + Vite + Tailwind CSS + shadcn/ui + Lucide icons
- Submits scan requests and visualizes results
- Renders the **call-path evidence view** — the core feature: a visual trace from entry point to vulnerable function
- Performs no analysis itself; purely a client for the backend API

### Backend
- **Stack:** Python + FastAPI
- Hosts the analysis pipeline and exposes a REST API
- Scans run as background tasks (process pool, to avoid blocking the API on CPU-heavy AST work)

### API Endpoints

| Endpoint | Responsibility |
|---|---|
| `POST /api/scans` | Start a repository scan |
| `GET /api/scans/{id}` | Get scan status |
| `GET /api/scans/{id}/dependencies` | Get detected packages |
| `GET /api/scans/{id}/vulnerabilities` | Get vulnerability findings |
| `GET /api/scans/{id}/graph` | Get call graph |
| `GET /api/scans/{id}/report` | Get final report |

---

## Current scope (MVP)

To keep the first version focused and demoable:

- ✅ GitHub URL as repository source
- ✅ `requirements.txt` with pinned versions only
- ✅ Single-repo call graph (no transitive dependency source analysis)
- ✅ Flask/FastAPI entry point detection
- ✅ A curated knowledge base of 5–8 well-understood CVEs
- ✅ Constant-string `getattr()` resolution

**Not yet implemented** (explicitly out of scope for MVP, noted as limitations rather than hidden):
- Transitive dependency resolution
- Alternate manifest formats (`pyproject.toml`, `poetry.lock`, `uv.lock`, `Pipfile.lock`)
- ZIP upload as a repository source
- Taint analysis
- Full dynamic call resolution (reflection, complex `getattr` patterns)
- Automated LLM-assisted vulnerability mapping (current mapping is manually curated)

---

## Design principles

1. **Deterministic analysis decides the verdict.** The LLM explains results; it never classifies them.
2. **Uncertainty is reported, not hidden.** A finding with no confirmed path is `No path found`, never silently marked safe.
3. **Read-only by default.** Repository code is parsed, never executed. No `pip install`, no running uploaded scripts.
4. **Evidence over opinion.** Every "Reachable" verdict ships with the exact call path and source files that prove it.

---

## Getting started

### Prerequisites
- Python 3.11+
- Node.js 18+

### Backend

```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

The app will be available at `http://localhost:3000`, calling the API at `http://localhost:8000` by default.

---

## Validation approach

Rather than claiming accuracy abstractly, TraceLock is validated against a set of small fixture repositories with known, hand-verified outcomes: confirmed-reachable cases, safe-usage cases (e.g. `Loader=SafeLoader`), imported-but-unused cases, and dead code. Results are compared against standard tools like `pip-audit` to demonstrate concrete noise reduction.

---

## Security notes

- Uploaded/cloned repositories are treated as untrusted input: extraction is sandboxed, paths and archive sizes are validated, and no code from the target repository is ever executed.
- OSV queries are batched and cached per `(package, version)` to minimize external calls.

---

## Roadmap

- [ ] Transitive dependency resolution via lockfiles
- [ ] Taint analysis for severity scoring
- [ ] Expand curated CVE knowledge base; explore LLM-assisted candidate mapping with mandatory source verification
- [ ] Support additional frameworks for entry-point detection (Django, Celery tasks)
- [ ] ZIP upload support

---

## License

_Add your license here._
