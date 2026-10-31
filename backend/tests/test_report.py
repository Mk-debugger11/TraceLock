import io
import json
import sys
from pathlib import Path

import pytest

from tracelock import cli, report, scan

BENCHMARK = Path(__file__).resolve().parents[2] / "benchmark"


@pytest.fixture(scope="module")
def results():
    names = ("three_hop_chain", "pyyaml_safe_load", "getattr_dynamic")
    return {name: scan(BENCHMARK / name, offline=True, fetch_sources=False) for name in names}


def test_openvex_document_and_statuses(results):
    doc = json.loads(report.to_openvex(results["three_hop_chain"]))
    assert doc["@context"] == "https://openvex.dev/ns/v0.2.0"
    assert doc["@id"].startswith("urn:uuid:") and doc["author"] == "TraceLock" and doc["version"] == 1
    assert doc["timestamp"].endswith("Z")
    reachable = doc["statements"][0]
    assert reachable["status"] == "affected"
    assert reachable["products"] == [{"@id": "pkg:pypi/pyyaml@5.3"}]
    assert reachable["vulnerability"]["name"].startswith("GHSA-")
    assert any(a.startswith("CVE-") for a in reachable["vulnerability"]["aliases"])
    assert "yaml.full_load is called from app/settings.py:5" in reachable["action_statement"]

    safe = json.loads(report.to_openvex(results["pyyaml_safe_load"]))["statements"][0]
    assert safe["status"] == "not_affected"
    assert safe["justification"] == "vulnerable_code_not_in_execute_path"
    assert "9/9 checks passed" in safe["impact_statement"]

    uncertain = json.loads(report.to_openvex(results["getattr_dynamic"]))["statements"][0]
    assert uncertain["status"] == "under_investigation"
    assert uncertain["action_statement"] == results["getattr_dynamic"].findings[0].reasons[0].check


def test_sarif_results_and_code_flow(results):
    log = json.loads(report.to_sarif(results["three_hop_chain"]))
    assert log["version"] == "2.1.0"
    run = log["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    assert run["tool"]["driver"]["name"] == "TraceLock"
    assert len(rules) == len({f.advisory.id for f in results["three_hop_chain"].findings})
    first = run["results"][0]
    assert first["level"] == "error" and rules[first["ruleIndex"]]["id"] == first["ruleId"]
    site = first["locations"][0]["physicalLocation"]
    assert site["artifactLocation"]["uri"] == "app/settings.py" and site["region"]["startLine"] == 5
    steps = first["codeFlows"][0]["threadFlows"][0]["locations"]
    assert [s["location"]["message"]["text"] for s in steps] == [
        "app.main.main", "app.settings.load_settings", "app.settings._read", "yaml.full_load (vulnerable)"
    ]
    assert "physicalLocation" not in steps[-1]["location"]


def test_sarif_omits_not_reachable_and_warns_on_uncertain(results):
    assert json.loads(report.to_sarif(results["pyyaml_safe_load"]))["runs"][0]["results"] == []
    uncertain = json.loads(report.to_sarif(results["getattr_dynamic"]))["runs"][0]["results"][0]
    assert uncertain["level"] == "warning"
    assert uncertain["locations"][0]["physicalLocation"]["region"]["startLine"] == 6


def test_print_terminal_falls_back_to_plain_text(results, monkeypatch):
    monkeypatch.setitem(sys.modules, "rich", None)  # makes `import rich.console` raise ImportError
    monkeypatch.setitem(sys.modules, "rich.console", None)
    out = io.StringIO()
    report.print_terminal(results["three_hop_chain"], file=out)
    assert out.getvalue() == report.render_terminal(results["three_hop_chain"]) + "\n"


def test_cli_writes_vex_and_sarif(tmp_path, capsys):
    vex, sarif = tmp_path / "v.json", tmp_path / "s.sarif"
    code = cli.main(["scan", str(BENCHMARK / "pyyaml_direct"), "--offline", "--no-sources", "--quiet",
                     "--vex", str(vex), "--sarif", str(sarif)])
    assert code == 1  # a REACHABLE finding fails the build by default
    assert json.loads(vex.read_text())["statements"]
    assert json.loads(sarif.read_text())["runs"][0]["results"]
