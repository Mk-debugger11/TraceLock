"""Every finding explains its own confidence: the factors are serialised, survive a JSON round trip, and the
`explanation` field in to_dict() matches report.explain()."""
from pathlib import Path

import tracelock
from tracelock import models, report

BENCH = Path(__file__).resolve().parents[2] / "benchmark"


def _scan(name):
    return tracelock.scan(BENCH / name, offline=True)


def test_every_finding_has_factors_and_explanation():
    for fixture in ("engine_template_ref", "engine_safe_clean", "engine_unpinned_used", "pyyaml_safe_load"):
        root = BENCH / fixture
        if not root.exists():
            continue
        result = _scan(fixture)
        data = models.to_dict(result)
        assert result.findings, fixture
        for f, d in zip(result.findings, data["findings"]):
            assert f.confidence_factors, (fixture, f.advisory.id)
            assert {"factor", "effect", "note"} <= set(f.confidence_factors[0])
            assert d["explanation"] == report.explain(f)
            assert f"Confidence {f.confidence:.2f}" in d["explanation"]


def test_factors_round_trip_and_render():
    result = _scan("engine_template_ref")
    data = models.to_dict(result)
    again = report.from_dict(data)
    assert [f.confidence_factors for f in again.findings] == [f.confidence_factors for f in result.findings]
    text = report.render_terminal(again)
    assert "confidence: function data: curated (base" in text
    assert "reference, not a call (x0.90)" in text


def test_reachable_factors_name_the_entry_point():
    result = _scan("engine_template_ref")
    f = result.findings[0]
    assert f.verdict == models.REACHABLE
    names = [c["factor"] for c in f.confidence_factors]
    assert names[0].startswith("function data:")
    assert any(n.startswith("entry point:") for n in names)
