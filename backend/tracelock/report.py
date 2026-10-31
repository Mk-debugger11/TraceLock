"""Output formats: terminal text, JSON, OpenVEX, SARIF. OWNER: Mukul.

 - render_terminal(): plain text, stdlib only. print_terminal() colours the verdict word with
   `rich` when it is importable (not a requirement) and falls back to the plain text.
 - to_json(): models.to_dict(ScanResult).
 - to_openvex(): OpenVEX v0.2.0 (https://github.com/openvex/spec), one statement per finding:
   affected (action_statement = upgrade advice) | not_affected (justification
   vulnerable_code_not_in_execute_path, impact_statement = checklist summary) |
   under_investigation (action_statement = reasons[0].check). products = pkg:pypi purls.
 - to_sarif(): SARIF 2.1.0, one rule per advisory, one result per REACHABLE (error) or
   UNCERTAIN (warning) finding at the call site; the path as codeFlows[0].threadFlows[0].
"""
from __future__ import annotations

import json
import sys
import uuid
from dataclasses import fields
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, TextIO
from urllib.parse import quote

from .models import (
    NOT_REACHABLE,
    REACHABLE,
    UNCERTAIN,
    Advisory,
    CallStep,
    Dependency,
    Finding,
    Reason,
    ScanResult,
    VulnSpec,
    to_dict,
)

ORDER = {REACHABLE: 0, UNCERTAIN: 1, NOT_REACHABLE: 2}
VERDICT_STYLE = {NOT_REACHABLE: "bold green", REACHABLE: "bold red", UNCERTAIN: "bold yellow"}
OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def _finding_text(f: Finding) -> str:
    adv, dep, spec = f.advisory, f.dependency, f.spec
    fixed = f" -> fixed {adv.fixed_in}" if adv.fixed_in else ""
    version = dep.version or "(unpinned)"
    header = f"{f.verdict:<14}{adv.id}  {dep.name} {version}{fixed}    confidence {f.confidence:.2f}"
    if f.accepted:
        header += "    [ACCEPTED]"
    lines = [header]
    if f.accepted:
        who = f" by {f.accepted['by']}" if f.accepted.get("by") else ""
        until = f", until {f.accepted['until']}" if f.accepted.get("until") else ""
        lines.append(f"  accepted:  {f.accepted['reason']}{who}{until} (not counted in the exit code)")
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
        site = _call_site(f.path)
        if site:
            lines.append(f"             {site.file}:{site.line} | {site.code}")
        lines.append(f"  entry:     {f.entry_kind}")
    if f.entry_kind == "runtime" or (f.runtime and f.runtime.get("executed")):
        fn = (f.runtime or {}).get("function")
        cmd = (f.runtime or {}).get("command")
        lines.append(f"  runtime:   CONFIRMED, {fn or 'the vulnerable function'} executed" + (f" under `{cmd}`" if cmd else ""))
    if f.verdict == NOT_REACHABLE:
        ticks = "  ".join(f"{k} {'ok' if v else 'NO'}" for k, v in f.checklist.items() if isinstance(v, bool))
        lines.append(f"  checklist: {ticks}")
    for r in f.reasons:
        where = f"{r.file}:{r.line} " if r.file else ""
        lines.append(f"  reason:    [{r.kind}] {where}{r.detail}")
        if r.check:
            lines.append(f"  check:     {r.check}")
    if f.confidence_factors:
        lines.append("  confidence: " + " · ".join(f"{c['factor']} ({c['effect']})" for c in f.confidence_factors))
    if adv.fixed_in:
        lines.append(f"  fix:       upgrade {dep.name}>={adv.fixed_in}")
    return "\n".join(lines)


TIER_WORDS = {
    "curated": "a hand-verified entry in TraceLock's knowledge base (checked against the fix commit)",
    "ecosystem_specific": "the advisory's own machine-readable list of affected imports",
    "fix_commit": "the functions changed by the advisory's fix commit, mapped with the AST of the pre-fix file",
    "llm_verified": "functions proposed by an LLM from the advisory and fix diff, each verified to exist in the library source",
    "none": "no source at all: the advisory names no function and has no usable fix commit",
}


def explain(f: Finding) -> str:
    """One paragraph of plain-language reasoning for a finding, for `--explain` and the UI's Why? button."""
    adv, dep, spec = f.advisory, f.dependency, f.spec
    parts = [f"{adv.id} affects {dep.name} {dep.version or '(version unpinned)'}"
             + (f" and is fixed in {adv.fixed_in}." if adv.fixed_in else ".")]
    parts.append(f"The vulnerable functions came from {TIER_WORDS.get(spec.tier, spec.tier)}"
                 + (f": {', '.join((spec.entry_api or spec.vulnerable_funcs)[:4])}." if (spec.entry_api or spec.vulnerable_funcs) else "."))
    if f.verdict == REACHABLE:
        if f.entry_kind == "runtime":
            parts.append("The verdict is REACHABLE because the function actually executed while the app ran under TraceLock's profiler; the stack above is the real call stack.")
        else:
            app_steps = [s for s in f.path if s.file]
            lib_steps = [s for s in f.path if not s.file]
            start = app_steps[0] if app_steps else None
            where = f"starting at {start.qualname} ({start.file}:{start.line})" if start else "starting in application code"
            entry = {"main": "a recognised entry point (main / __main__)", "route": "a web route handler", "module": "module-level code",
                     "test": "a test", "class definition": "a class definition", "orphan": "a function nothing else calls statically; still reachable because Python can invoke it by name"}.get(f.entry_kind or "", f.entry_kind or "")
            parts.append(f"The verdict is REACHABLE because a resolved call chain exists {where}, which is {entry}, "
                         f"through {len(app_steps)} application step(s)" + (f" and {len(lib_steps)} step(s) inside the library" if len(lib_steps) > 1 else "") + " to the vulnerable symbol.")
        for r in f.reasons:
            if r.kind in ("safe_arg_variable", "transitive", "value_ref", "subclass", "reference", "version_unpinned"):
                parts.append(r.detail if r.detail.endswith(".") else r.detail + ".")
    elif f.verdict == NOT_REACHABLE:
        checks = [k for k, v in f.checklist.items() if isinstance(v, bool) and v]
        detail = next((r.detail for r in f.reasons if r.kind in ("no_path", "not_imported")), "")
        parts.append(f"The verdict is NOT_REACHABLE because all {len(checks)} soundness checks passed ({', '.join(checks)}). {detail}."
                     " TraceLock only says this when it can prove the absence of a path; any dynamic call, string reference or unresolved receiver would have made it UNCERTAIN.")
    else:
        top = f.reasons[0] if f.reasons else None
        if top:
            where = f" at {top.file}:{top.line}" if top.file else ""
            parts.append(f"The verdict is UNCERTAIN because of a '{top.kind}' signal{where}: {top.detail}. What to check: {top.check}")
        parts.append("TraceLock prefers UNCERTAIN over a wrong 'safe'.")
    if f.accepted:
        parts.append(f"This finding is accepted in .tracelock.yml ({f.accepted['reason']}) and does not affect the exit code; the OpenVEX output records it as not_affected.")
    if f.confidence_factors:
        parts.append(f"Confidence {f.confidence:.2f} = " + "; ".join(f"{c['factor']} ({c['effect']}: {c['note']})" for c in f.confidence_factors)
                     + ". Confidence orders findings and never changes a verdict.")
    else:
        parts.append(f"Confidence {f.confidence:.2f} reflects how the functions were identified and how much of the call resolution was exact; it orders findings and never changes a verdict.")
    return " ".join(parts)


def render_terminal(result: ScanResult, explain_findings: bool = False) -> str:
    out = [f"TraceLock scan of {result.root}", f"dependencies: {len(result.dependencies)}  findings: {len(result.findings)}", ""]
    for f in sorted(result.findings, key=lambda x: (ORDER.get(x.verdict, 9), x.dependency.name)):
        out.append(_finding_text(f))
        if explain_findings:
            out.append("  why:       " + explain(f))
        out.append("")
    counts = {v: sum(1 for f in result.findings if f.verdict == v) for v in ORDER}
    accepted = sum(1 for f in result.findings if f.accepted)
    out.append(f"summary: {counts[REACHABLE]} reachable, {counts[NOT_REACHABLE]} not reachable, {counts[UNCERTAIN]} uncertain"
               + (f", {accepted} accepted" if accepted else ""))
    for w in result.warnings:
        out.append(f"warning: {w}")
    return "\n".join(out)


def print_terminal(result: ScanResult, file: Optional[TextIO] = None, explain_findings: bool = False) -> None:
    """Print render_terminal(), with the verdict word coloured when `rich` is installed."""
    text = render_terminal(result, explain_findings=explain_findings)
    try:
        from rich.console import Console
        from rich.text import Text
    except ImportError:
        print(text, file=file or sys.stdout)
        return
    console = Console(file=file, highlight=False)  # rich drops colour itself when not writing to a terminal
    for line in text.splitlines():
        styled = Text(line)
        verdict = next((v for v in VERDICT_STYLE if line.startswith(v)), None)
        if verdict:
            styled.stylize(VERDICT_STYLE[verdict], 0, len(verdict))
        console.print(styled, soft_wrap=True)


def to_json(result: ScanResult, indent: int = 2) -> str:
    return json.dumps(to_dict(result), indent=indent)


def _build(cls, data: dict):
    """Instantiate a models dataclass from a dict, ignoring keys it does not know."""
    names = {f.name for f in fields(cls)}
    return cls(**{k: v for k, v in data.items() if k in names})


def from_dict(data: dict) -> ScanResult:
    """Inverse of models.to_dict: rebuild a ScanResult from stored JSON (the advisory's raw record stays empty)."""
    findings = []
    for f in data.get("findings", []):
        findings.append(_build(Finding, {
            **f,
            "advisory": _build(Advisory, f["advisory"]),
            "dependency": _build(Dependency, f["dependency"]),
            "spec": _build(VulnSpec, f["spec"]),
            "path": [_build(CallStep, s) for s in f.get("path", [])],
            "reasons": [_build(Reason, r) for r in f.get("reasons", [])],
        }))
    return _build(ScanResult, {
        **data,
        "dependencies": [_build(Dependency, d) for d in data.get("dependencies", [])],
        "findings": findings,
    })


def _purl(f: Finding) -> str:
    if not f.dependency.version:
        return f"pkg:pypi/{f.dependency.name}"
    return f"pkg:pypi/{f.dependency.name}@{quote(f.dependency.version, safe='')}"


def _functions(f: Finding) -> str:
    funcs = f.spec.entry_api or f.spec.vulnerable_funcs
    return ", ".join(funcs[:6]) + (" ..." if len(funcs) > 6 else "") if funcs else "the vulnerable code"


def _upgrade(f: Finding) -> str:
    if f.advisory.fixed_in:
        return f"Upgrade {f.dependency.name} to {f.advisory.fixed_in} or later."
    return f"No fixed release of {f.dependency.name} is known; remove or guard the call."


def _checklist_summary(f: Finding) -> str:
    checks = [(k, v) for k, v in f.checklist.items() if isinstance(v, bool)]
    passed = sum(v for _, v in checks)
    detail = ", ".join(f"{k} {'ok' if v else 'NO'}" for k, v in checks)
    return f"TraceLock found no call path from application code to {_functions(f)}; {passed}/{len(checks)} checks passed: {detail}."


def _statement(f: Finding) -> dict:
    adv = f.advisory
    vulnerability = {"name": adv.id}
    aliases = [a for a in adv.aliases if a != adv.id]
    if aliases:
        vulnerability["aliases"] = aliases
    statement = {"vulnerability": vulnerability, "products": [{"@id": _purl(f)}]}
    if f.accepted:
        who = f" (by {f.accepted['by']})" if f.accepted.get("by") else ""
        until = f", until {f.accepted['until']}" if f.accepted.get("until") else ""
        statement.update(status="not_affected", justification=f.accepted["justification"],
                         impact_statement=f"Accepted in .tracelock.yml{who}{until}: {f.accepted['reason']} TraceLock verdict was {f.verdict}.")
        return statement
    if f.verdict == REACHABLE:
        site = _call_site(f.path)
        target = f.path[-1].qualname if f.path and not f.path[-1].file else _functions(f)
        where = f" from {site.file}:{site.line}" if site else ""
        statement.update(status="affected", action_statement=f"{target} is called{where}. {_upgrade(f)}")
    elif f.verdict == NOT_REACHABLE:
        statement.update(
            status="not_affected",
            justification="vulnerable_code_not_in_execute_path",
            impact_statement=_checklist_summary(f),
        )
    else:
        check = next((r.check for r in f.reasons if r.check), "")
        statement.update(status="under_investigation", action_statement=check or f"Review how the app uses {f.dependency.name}.")
    return statement


def to_openvex(result: ScanResult) -> str:
    from . import __version__

    findings = sorted(result.findings, key=lambda x: (ORDER.get(x.verdict, 9), x.dependency.name, x.advisory.id))
    document = {
        "@context": OPENVEX_CONTEXT,
        "@id": f"urn:uuid:{uuid.uuid4()}",
        "author": "TraceLock",
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "version": 1,
        "tooling": f"TraceLock {__version__}",
        "statements": [_statement(f) for f in findings],
    }
    return json.dumps(document, indent=2)


def _in_project(step: CallStep) -> bool:
    """Static steps are relative to the scanned root; runtime traces also contain absolute library frames."""
    return bool(step.file) and not Path(step.file).is_absolute() and not step.file.startswith("site-packages/")


def _call_site(path: list[CallStep]) -> Optional[CallStep]:
    """The last step inside the app: the line that calls the vulnerable symbol."""
    return next((s for s in reversed(path) if _in_project(s) and s.line > 0), None)


def _physical(file: str, line: int) -> dict:
    if Path(file).is_absolute():
        location = {"artifactLocation": {"uri": Path(file).as_uri()}}
    else:
        location = {"artifactLocation": {"uri": file.replace("\\", "/"), "uriBaseId": "%SRCROOT%"}}
    if line > 0:
        location["region"] = {"startLine": line}
    return {"physicalLocation": location}


def _sarif_result(f: Finding, rule_index: int) -> dict:
    adv, dep = f.advisory, f.dependency
    fix = f" Fixed in {adv.fixed_in}." if adv.fixed_in else ""
    result = {"ruleId": adv.id, "ruleIndex": rule_index}
    if f.verdict == REACHABLE:
        site = _call_site(f.path)
        chain = " -> ".join(s.qualname for s in f.path)
        result.update(level="error", message={"text": f"{dep.name} {dep.version}: {adv.id} is reachable via {chain}.{fix}"})
        if site:
            result["locations"] = [_physical(site.file, site.line)]
        steps = []
        for step in f.path:
            location = _physical(step.file, step.line) if step.file else {}
            location["message"] = {"text": step.qualname if step.file else f"{step.qualname} (vulnerable)"}
            steps.append({"location": location})
        if steps:
            result["codeFlows"] = [{"threadFlows": [{"locations": steps}]}]
    else:
        reason = next((r for r in f.reasons if r.file), f.reasons[0] if f.reasons else None)
        detail = ""
        if reason:
            detail = f" Saw: {reason.detail.rstrip('.')}." + (f" Check: {reason.check.rstrip('.')}." if reason.check else "")
        result.update(level="warning", message={"text": f"{dep.name} {dep.version}: {adv.id} may be reachable.{detail}{fix}"})
        if reason and reason.file:
            result["locations"] = [_physical(reason.file, reason.line or 0)]
    return result


def to_sarif(result: ScanResult) -> str:
    from . import __version__

    rules, index = [], {}
    for f in result.findings:
        adv = f.advisory
        if adv.id in index:
            continue
        index[adv.id] = len(rules)
        rule = {
            "id": adv.id,
            "shortDescription": {"text": adv.summary or adv.id},
            "properties": {"tags": ["security", "vulnerability", f.dependency.name]},
        }
        if adv.details:
            rule["fullDescription"] = {"text": adv.details[:2000]}
        if adv.fix_urls:
            rule["helpUri"] = adv.fix_urls[0]
        rules.append(rule)

    findings = sorted(result.findings, key=lambda x: (ORDER.get(x.verdict, 9), x.dependency.name, x.advisory.id))
    log = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "TraceLock",
                "version": __version__,
                "informationUri": "https://github.com/Mk-debugger11/TraceLock",
                "rules": rules,
            }},
            "originalUriBaseIds": {"%SRCROOT%": {"uri": f"{_file_uri(result.root)}/"}},
            "results": [_sarif_result(f, index[f.advisory.id]) for f in findings if f.verdict in (REACHABLE, UNCERTAIN)],
        }],
    }
    return json.dumps(log, indent=2)


def _file_uri(root: str) -> str:
    try:
        return Path(root).resolve().as_uri().rstrip("/")
    except ValueError:
        return "file:///" + quote(root.strip("/"))
