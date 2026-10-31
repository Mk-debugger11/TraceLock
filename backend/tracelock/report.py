"""Output formats: terminal text, JSON, OpenVEX, SARIF. OWNER: Mukul.

Scaffold status: terminal (plain text, stdlib only) and JSON are REAL; OpenVEX and SARIF
are STUBS that raise NotImplementedError. Build (BRIEF_MUKUL.md, task 4):
 - to_openvex(): https://github.com/openvex/spec ; one statement per finding,
   status affected | not_affected (justification vulnerable_code_not_in_execute_path,
   impact_statement = checklist summary) | under_investigation (action_statement = reasons[0].check),
   products = [{"@id": "pkg:pypi/<name>@<version>"}], vulnerability = {"name": advisory.id}.
 - to_sarif(): SARIF 2.1.0 with one rule per advisory and one result per REACHABLE/UNCERTAIN
   finding at the call-site location; the path as codeFlows.threadFlows.locations.
 - Optional: a `rich` renderer with colours when `rich` is importable; keep the plain one as fallback.
"""
from __future__ import annotations

import json

from .models import NOT_REACHABLE, REACHABLE, UNCERTAIN, Finding, ScanResult, to_dict

ORDER = {REACHABLE: 0, UNCERTAIN: 1, NOT_REACHABLE: 2}


def _finding_text(f: Finding) -> str:
    adv, dep, spec = f.advisory, f.dependency, f.spec
    fixed = f" -> fixed {adv.fixed_in}" if adv.fixed_in else ""
    lines = [f"{f.verdict:<14}{adv.id}  {dep.name} {dep.version}{fixed}    confidence {f.confidence:.2f}"]
    aliases = ", ".join(a for a in adv.aliases if a != adv.id)
    if aliases:
        lines.append(f"  aliases:   {aliases}")
    if adv.summary:
        lines.append(f"  summary:   {adv.summary[:110]}")
    funcs = spec.entry_api or spec.vulnerable_funcs
    src = spec.tier + (f", fix commit {spec.fix_commit.rsplit('/', 1)[-1][:10]}" if spec.fix_commit else "")
    lines.append(f"  functions: {', '.join(funcs[:6])}{' ...' if len(funcs) > 6 else ''}  ({src})")
    if f.verdict == REACHABLE and f.path:
        chain = "  ->  ".join(f"{s.file}:{s.line} {s.qualname}" if s.file else s.qualname for s in f.path)
        lines.append(f"  path:      {chain}")
        site = next((s for s in reversed(f.path) if s.file), None)
        if site:
            lines.append(f"             {site.file}:{site.line} | {site.code}")
        lines.append(f"  entry:     {f.entry_kind}")
        if f.runtime:
            lines.append("  runtime:   CONFIRMED, the vulnerable function executed during the trace")
    if f.verdict == NOT_REACHABLE:
        ticks = "  ".join(f"{k} {'ok' if v else 'NO'}" for k, v in f.checklist.items() if isinstance(v, bool))
        lines.append(f"  checklist: {ticks}")
    for r in f.reasons:
        where = f"{r.file}:{r.line} " if r.file else ""
        lines.append(f"  reason:    [{r.kind}] {where}{r.detail}")
        if r.check:
            lines.append(f"  check:     {r.check}")
    if adv.fixed_in:
        lines.append(f"  fix:       upgrade {dep.name}>={adv.fixed_in}")
    return "\n".join(lines)


def render_terminal(result: ScanResult) -> str:
    out = [f"TraceLock scan of {result.root}", f"dependencies: {len(result.dependencies)}  findings: {len(result.findings)}", ""]
    for f in sorted(result.findings, key=lambda x: (ORDER.get(x.verdict, 9), x.dependency.name)):
        out.append(_finding_text(f))
        out.append("")
    counts = {v: sum(1 for f in result.findings if f.verdict == v) for v in ORDER}
    out.append(f"summary: {counts[REACHABLE]} reachable, {counts[NOT_REACHABLE]} not reachable, {counts[UNCERTAIN]} uncertain")
    for w in result.warnings:
        out.append(f"warning: {w}")
    return "\n".join(out)


def to_json(result: ScanResult, indent: int = 2) -> str:
    return json.dumps(to_dict(result), indent=indent)


def to_openvex(result: ScanResult) -> str:
    raise NotImplementedError("Mukul: see report.py docstring")


def to_sarif(result: ScanResult) -> str:
    raise NotImplementedError("Mukul: see report.py docstring")
