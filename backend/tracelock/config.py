"""Project configuration: `.tracelock.yml` (or `.tracelock.json`) at the scanned root. OWNER: Kartik.

    accept:
      - id: CVE-2023-32681          # advisory id or alias
        reason: "proxy auth is never used; no Proxy-Authorization header is ever set"
        by: "kartik"
        until: 2026-12-31           # optional expiry; an expired acceptance is ignored and reported
        justification: vulnerable_code_cannot_be_controlled_by_adversary   # optional OpenVEX justification
    ignore_paths: ["tests/", "examples/"]   # app files left out of the analysis
    fail_on: reachable                       # or uncertain
    offline: false

An accepted finding keeps its real verdict in the report (nothing is hidden) but is marked
`accepted`, excluded from the exit code, and emitted in OpenVEX as `not_affected` with the given
justification (default `inline_mitigations_already_exist`) and the reason as impact_statement.
A minimal YAML subset is parsed without a dependency; JSON works too.
"""
from __future__ import annotations

import datetime as _dt
import json
import re
from pathlib import Path
from typing import Optional

CONFIG_NAMES = (".tracelock.yml", ".tracelock.yaml", ".tracelock.json")
VEX_JUSTIFICATIONS = {"component_not_present", "vulnerable_code_not_present", "vulnerable_code_not_in_execute_path",
                      "vulnerable_code_cannot_be_controlled_by_adversary", "inline_mitigations_already_exist"}


def _parse_mini_yaml(text: str) -> dict:
    """Enough YAML for this file: top-level keys, scalar values, lists of scalars, lists of flat mappings."""
    try:
        import yaml  # type: ignore
        data = yaml.safe_load(text)
        return data if isinstance(data, dict) else {}
    except Exception:
        pass
    out: dict = {}
    key: Optional[str] = None
    item: Optional[dict] = None
    for raw in text.splitlines():
        line = raw.split(" #", 1)[0].rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        stripped = line.strip()
        if indent == 0 and ":" in stripped:
            k, _, v = stripped.partition(":")
            key, item = k.strip(), None
            v = v.strip()
            if v.startswith("[") and v.endswith("]"):
                out[key] = [x.strip().strip("'\"") for x in v[1:-1].split(",") if x.strip()]
            elif v:
                out[key] = _scalar(v)
            else:
                out[key] = []
        elif stripped.startswith("- ") and key is not None:
            body = stripped[2:].strip()
            if ":" in body and not body.startswith(("'", '"')):
                k, _, v = body.partition(":")
                item = {k.strip(): _scalar(v.strip())}
                out[key].append(item)
            else:
                item = None
                out[key].append(_scalar(body))
        elif item is not None and ":" in stripped:
            k, _, v = stripped.partition(":")
            item[k.strip()] = _scalar(v.strip())
    return out


def _scalar(v: str):
    v = v.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
        return v[1:-1]
    if v.lower() in ("true", "yes"):
        return True
    if v.lower() in ("false", "no"):
        return False
    if re.fullmatch(r"-?\d+", v):
        return int(v)
    return v


def load_config(root: Path) -> dict:
    """The project's config dict, or {} when there is none / it is unreadable (a warning goes in `_warnings`)."""
    for name in CONFIG_NAMES:
        path = Path(root) / name
        if path.exists():
            try:
                text = path.read_text(encoding="utf-8")
                data = json.loads(text) if name.endswith(".json") else _parse_mini_yaml(text)
                data = data if isinstance(data, dict) else {}
                data["_file"] = name
                return data
            except Exception as exc:
                return {"_file": name, "_warnings": [f"{name}: could not be read ({exc}); ignored"]}
    return {}


def acceptance_for(config: dict, advisory_ids: list[str], today: Optional[_dt.date] = None) -> tuple[Optional[dict], Optional[str]]:
    """(acceptance entry, warning). Matches by id or alias; an expired `until` returns (None, warning)."""
    today = today or _dt.date.today()
    wanted = {a.upper() for a in advisory_ids}
    for entry in config.get("accept", []) or []:
        if not isinstance(entry, dict):
            continue
        if str(entry.get("id", "")).upper() not in wanted:
            continue
        until = entry.get("until")
        if until:
            try:
                expiry = _dt.date.fromisoformat(str(until))
            except ValueError:
                return None, f"{config.get('_file')}: acceptance for {entry.get('id')} has an invalid until date {until!r}; ignored"
            if expiry < today:
                return None, f"{config.get('_file')}: acceptance for {entry.get('id')} expired on {expiry}; finding counts again"
        justification = entry.get("justification") or "inline_mitigations_already_exist"
        if justification not in VEX_JUSTIFICATIONS:
            return None, f"{config.get('_file')}: acceptance for {entry.get('id')} has unknown justification {justification!r}; ignored"
        return {"reason": str(entry.get("reason", "")).strip() or "accepted in .tracelock.yml",
                "by": str(entry.get("by", "")), "until": str(until) if until else None,
                "justification": justification}, None
    return None, None
