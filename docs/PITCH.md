---
marp: true
theme: default
paginate: true
style: |
  section { font-size: 26px; }
  pre, code { font-size: 0.8em; }
  table { font-size: 0.75em; }
---

# TraceLock

## govulncheck for Python: evidence-backed, never bluffs safe

For every known vulnerability in your dependencies:
**REACHABLE** with the call chain, **NOT_REACHABLE** with a checklist, or **UNCERTAIN** with the line to check.

Team T032 · Mukul Kumar · Kartik Madaan · Vaibhav Vats

<!-- One sentence: dependency scanners tell you what is installed; TraceLock tells you what your code can actually reach, and proves it. -->

---

# The problem: N CVEs, no context

Five different apps, all pinning `pyyaml==5.3`. `pip-audit` says the same thing about every one:

```
$ pip-audit -r requirements.txt --no-deps --disable-pip
Found 4 known vulnerabilities in 1 package
Name   Version ID             Fix Versions
------ ------- -------------- ------------
pyyaml 5.3     PYSEC-2020-96  5.3.1
pyyaml 5.3     PYSEC-2021-142 5.4
...
```

One calls `yaml.full_load` three functions deep. One only uses `yaml.safe_load`.
One never imports `yaml`. One picks the loader with `getattr(yaml, name)`.
**Which ones do you fix tonight?**

<!-- Real output, captured on benchmark/three_hop_chain; identical for the other four. -->

---

# How it works

```
requirements / pyproject ──► OSV advisories (live, cached, offline snapshot)
                                   │
                                   ▼
                     knowledge base: which functions are dangerous
                     curated · ecosystem imports · fix-commit diff · LLM (verified)
                                   │
  app source ──AST──► calls, entry points,      library source ──AST──► exposure set
                     dynamic markers, strings   (downloaded, never      (public APIs that
                                   │             installed)              reach the bug)
                                   ▼                                         │
                            verdict engine ◄─────────────────────────────────┘
                                   │         optional: runtime trace confirms with the live stack
                                   ▼
               terminal · JSON · OpenVEX · SARIF · web evidence view
```

The LLM can only propose function names, each checked against the real library source. It never decides a verdict.

---

# Verdict rules

**REACHABLE**: a call chain from app code to a vulnerable symbol, `file:line` at every step.
**UNCERTAIN**: anything we cannot rule out, with the reason, the line, and what to check.
**NOT_REACHABLE**: only when every check holds:

| check | meaning |
| --- | --- |
| `no_call_to_vulnerable_api` | no resolved call hits the vulnerable symbols or the exposure set |
| `all_call_sites_safe` | any hit uses a safe argument (`Loader=yaml.SafeLoader`) |
| `no_unresolved_call_with_same_name` | no `obj.load()` on a receiver we could not type |
| `no_dynamic_markers` | no `getattr(x, var)`, `importlib`, `eval`, `exec`, pickle loads |
| `no_string_reference` | no string naming the symbol in code, templates or config |
| `no_star_import` | no `from pkg import *` |
| `function_data_available` | we know which functions are affected |
| `not_transitively_required` | not pulled in by a package the app imports |

Doubt always resolves to UNCERTAIN. A wrong "safe" is the one failure we are built to avoid.

---

# Benchmark and output

| fixture | pip-audit | TraceLock |
| --- | --- | --- |
| `three_hop_chain` | 4 vulns | REACHABLE, 3-step chain |
| `pyyaml_direct` | 10 vulns (pyyaml + requests) | pyyaml REACHABLE |
| `pyyaml_safe_load` | 4 vulns | NOT_REACHABLE, 9/9 checks |
| `pyyaml_safeloader_kwarg` | 4 vulns | NOT_REACHABLE |
| `not_imported` | 4 vulns | NOT_REACHABLE |
| `getattr_dynamic` | 4 vulns | UNCERTAIN, `app.py:6` |

**65/65 correct across 38 fixture apps, 0 FALSE SAFE; precision and recall 1.00** for both REACHABLE
and NOT_REACHABLE (`python benchmark/run.py`). Full table: `benchmark/RESULTS.md`.

```json
{ "vulnerability": { "name": "GHSA-8q59-q68h-6hv4", "aliases": ["CVE-2020-14343", "PYSEC-2021-142"] },
  "products": [{ "@id": "pkg:pypi/pyyaml@5.3" }],
  "status": "not_affected",
  "justification": "vulnerable_code_not_in_execute_path",
  "impact_statement": "TraceLock found no call path from application code to yaml.load, ...; 9/9 checks passed: ..." }
```

<!-- Then switch to the live terminal: scan three_hop_chain, pyyaml_safe_load, getattr_dynamic, then trace pyyaml_direct. -->

---

# A real app: 108 advisories → 6 to fix

`benchmark/real_flask_app`: a Flask notes app, 10 pinned packages. A dependency scanner lists **108 advisories**.

| TraceLock | count | what you get |
| --- | --- | --- |
| **REACHABLE** | **6** | call path from a route to the bug, e.g. `views.index → weather.fetch_forecast → requests.Session.get → … → get_netrc_auth` |
| **NOT_REACHABLE** | **7** | the checklist that proves it (pyyaml only via `yaml.safe_load`, pyjwt never imported, …) |
| **UNCERTAIN** | **95** | the reason: 74 have no function data offline, 21 come in transitively, never a guess |

Fix tonight: flask, werkzeug, requests ×3, urllib3. Prove the rest with a document, not a meeting.

<!-- Fresh offline scan: tracelock scan benchmark/real_flask_app --offline. pillow alone is 50 of the 95 UNCERTAIN. -->

---

# Triage with an audit trail

Decided a REACHABLE finding is not exploitable here? Record it, don't hide it: `.tracelock.yml`

```yaml
accept:
  - id: CVE-2023-32681
    reason: "no proxies are configured; Proxy-Authorization is never set"
    by: mukul
    until: 2026-12-31          # expires: after this date it counts again, with a warning
    justification: vulnerable_code_cannot_be_controlled_by_adversary
```

- The report still says **REACHABLE `[ACCEPTED]`**: who, why, until when. The exit code ignores it.
- OpenVEX says `not_affected` + your justification, so Trivy, Grype and Docker Scout stop alerting.
- SARIF goes to GitHub **Security → Code scanning** from CI, call path as a code flow.

```json
{ "status": "not_affected", "justification": "vulnerable_code_cannot_be_controlled_by_adversary",
  "impact_statement": "Accepted in .tracelock.yml (by mukul), until 2026-12-31: no proxies are configured; ... TraceLock verdict was REACHABLE." }
```
