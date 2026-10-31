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
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, TextIO
from urllib.parse import quote

from .models import NOT_REACHABLE, REACHABLE, UNCERTAIN, CallStep, Finding, ScanResult, to_dict

ORDER = {REACHABLE: 0, UNCERTAIN: 1, NOT_REACHABLE: 2}
VERDICT_STYLE = {NOT_REACHABLE: "bold green", REACHABLE: "bold red", UNCERTAIN: "bold yellow"}
OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


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


def print_terminal(result: ScanResult, file: Optional[TextIO] = None) -> None:
    """Print render_terminal(), with the verdict word coloured when `rich` is installed."""
    text = render_terminal(result)
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


def _purl(f: Finding) -> str:
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


def _call_site(path: list[CallStep]) -> Optional[CallStep]:
    """The last step inside the app: the line that calls the vulnerable symbol."""
    return next((s for s in reversed(path) if s.file and s.line > 0), None)


def _physical(file: str, line: int) -> dict:
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
