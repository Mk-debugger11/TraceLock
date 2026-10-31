# TraceLock briefs — one per person, one per Claude

Paste the matching brief into your Claude Code session as the first message, verbatim, with
this line in front of it:

> You are working in the TraceLock repo (cd to the repo root first). Read this brief fully, then
> read the files it names, then start with task 1. Run `python benchmark/run.py` before every
> commit; never let the "FALSE SAFE" count go above 0.

| Person  | Brief              | Owns                                                                 |
| ------- | ------------------ | -------------------------------------------------------------------- |
| Kartik  | BRIEF_KARTIK.md    | `backend/tracelock/app_graph.py`, `lib_graph.py`, `verdict.py`, `__init__.py`, `tracer.py` |
| Mukul   | BRIEF_MUKUL.md     | `backend/tracelock/pypi_source.py`, `report.py`, `cli.py`, `backend/app/**` (FastAPI), `frontend/**` |
| Vaibhav | BRIEF_VAIBHAV.md   | `backend/tracelock/deps.py`, `osv.py`, `kb/**`, `data/**`, `benchmark/**` |

Shared and frozen: `backend/tracelock/models.py` (the contract). Change it only after all three agree
in the group chat, and the person who changes it runs the benchmark and fixes every caller.

## What already works (scaffold, committed)

```
cd backend
python -m tracelock.cli scan ../benchmark/three_hop_chain --offline   # REACHABLE with a 3-step chain
python -m tracelock.cli scan ../benchmark/pyyaml_safe_load --offline  # NOT_REACHABLE with checklist
python -m tracelock.cli scan ../benchmark/getattr_dynamic --offline   # UNCERTAIN with a reason
cd .. && python benchmark/run.py                                        # 12/12, 0 FALSE SAFE
```

Pipeline: `deps.scan_dependencies` -> `osv.lookup` (live querybatch, cache, offline snapshot) ->
`kb.resolve` (curated.json for PyYAML; fix-commit and LLM tiers are stubs) -> `app_graph.build`
(real: imports, aliases, attribute chains, constructor-typed locals, self., getattr literal,
dynamic markers, string refs, entry tagging, caller->callee edges) -> `lib_graph.exposure_set`
(stub) -> `verdict.decide` (real rules + checklist) -> `report.render_terminal` / `to_json`
(real), `to_openvex` / `to_sarif` (stubs). `pypi_source.fetch` and `tracer.run_trace` are stubs.

## Checkpoints (elapsed time from kickoff)

| When | Everyone does |
| ---- | ------------- |
| 0:15 | `git pull`, read your brief, confirm the scaffold runs on your machine |
| 1:30 | merge your branch to `main`, run `python benchmark/run.py`, post the score |
| 2:15 | merge again; Kartik runs the full benchmark; wrong verdicts are fixed before anything new |
| 3:15 | feature freeze; only bug fixes, README, demo rehearsal |
| 3:45 | tag `v0.1`, record a backup demo, submit |

Git: branch `feat/<yourname>`, commit every 20 minutes, `git pull --rebase origin main` before
merging. Conflicts outside your own files mean you edited the wrong file.
