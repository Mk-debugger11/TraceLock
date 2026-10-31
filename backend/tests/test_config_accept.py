"""`.tracelock.yml`: acceptances with an audit trail, ignore_paths, exit code and OpenVEX integration."""
import json
import shutil
from pathlib import Path

import pytest

import tracelock
from tracelock import cli, config, report

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "benchmark" / "alias_import"


@pytest.fixture
def project(tmp_path):
    shutil.copytree(FIXTURE, tmp_path / "app")
    (tmp_path / "app" / "tests").mkdir()
    (tmp_path / "app" / "tests" / "test_x.py").write_text("import yaml\ndef test_x():\n    yaml.unsafe_load('a')\n")
    return tmp_path / "app"


def test_mini_yaml_parser():
    data = config._parse_mini_yaml(
        'accept:\n  - id: CVE-1\n    reason: "x"\n    until: 2030-01-01\nignore_paths: ["tests/", "ex/"]\nfail_on: uncertain\noffline: true\n')
    assert data["accept"][0]["id"] == "CVE-1" and data["accept"][0]["reason"] == "x"
    assert data["ignore_paths"] == ["tests/", "ex/"] and data["offline"] is True


def test_accepted_finding_is_marked_and_excluded_from_exit_code(project):
    (project / ".tracelock.yml").write_text(
        "accept:\n  - id: CVE-2020-1747\n    reason: internal bundle only\n    by: kartik\n    until: 2999-01-01\n"
        "  - id: CVE-2020-14343\n    reason: expired\n    until: 2000-01-01\nignore_paths: [\"tests/\"]\n")
    result = tracelock.scan(project, offline=True)
    by_alias = {a: f for f in result.findings for a in [f.advisory.id, *f.advisory.aliases]}
    accepted, expired = by_alias["CVE-2020-1747"], by_alias["CVE-2020-14343"]
    assert accepted.verdict == "REACHABLE" and accepted.accepted["by"] == "kartik"
    assert expired.accepted is None and any("expired" in w for w in result.warnings)
    assert not any(r.file.startswith("tests/") for f in result.findings for r in f.reasons if r.file)
    statements = {s["vulnerability"]["name"]: s for s in json.loads(report.to_openvex(result))["statements"]}
    assert statements[accepted.advisory.id]["status"] == "not_affected"
    assert statements[accepted.advisory.id]["justification"] == "inline_mitigations_already_exist"
    assert statements[expired.advisory.id]["status"] == "affected"
    assert cli.main(["scan", str(project), "--offline", "--quiet"]) == 1   # the expired one still counts
    (project / ".tracelock.yml").write_text("accept:\n  - id: CVE-2020-1747\n    reason: a\n  - id: CVE-2020-14343\n    reason: b\n")
    assert cli.main(["scan", str(project), "--offline", "--quiet"]) == 0


def test_explain_mentions_verdict_and_tier(project):
    result = tracelock.scan(project, offline=True)
    text = report.explain(result.findings[0])
    assert "REACHABLE" in text and "knowledge base" in text
