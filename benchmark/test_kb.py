"""Knowledge-base regression tests (no network). OWNER: Vaibhav.

    python benchmark/test_kb.py        # or: python -m pytest benchmark/test_kb.py
"""
from __future__ import annotations

import json
import sys
import textwrap
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "backend"))

from tracelock import deps, kb, osv  # noqa: E402
from tracelock.kb import fixdiff  # noqa: E402
from tracelock.models import TIER_CURATED, TIER_NONE, Dependency  # noqa: E402

PRE = textwrap.dedent('''\
    import re

    LIMIT = 10
    _private = 1


    def helper(x):
        return x


    def target(d):
        out = []
        for k in d:
            out.append(k)
        return out


    class Retry:
        DEFAULT_REMOVE = frozenset(["Authorization"])

        def increment(self):
            return 1


    if True:
        class Guarded:
            def prepare_key(self, key):
                return key


    class Constructor:
        def construct_new(self, node):
            return node


    Constructor.add_multi_constructor("tag:new", Constructor.construct_new)

    FILTERS = {"tgt": target, "help": helper}
    ''')


def _analyze(diff: str) -> list[str]:
    original = fixdiff._prefix_source
    fixdiff._prefix_source = lambda owner, repo, sha, path: (PRE, "test")
    try:
        return fixdiff.analyze_commit("o", "r", "0" * 40, diff)["qualnames"]
    finally:
        fixdiff._prefix_source = original


def _diff(body: str) -> str:
    return "diff --git a/src/pkg/mod.py b/src/pkg/mod.py\n--- a/src/pkg/mod.py\n+++ b/src/pkg/mod.py\n" + textwrap.dedent(body)


def test_header_text_is_ignored():
    # header names `helper`, the changed line is inside `target`
    assert _analyze(_diff("""\
        @@ -13,3 +13,3 @@ def helper(x):
             for k in d:
        -        out.append(k)
        +        out.append(k.strip())
             return out
        """)) == ["pkg.mod.FILTERS.tgt", "pkg.mod.target"]


def test_appended_statement_belongs_to_function_but_new_sibling_def_does_not():
    assert _analyze(_diff("""\
        @@ -14,2 +14,6 @@ def target(d):
                 out.append(k)
             return out
        +    # unreachable but inside target
        +
        +def brand_new():
        +    return 2
        """)) == ["pkg.mod.FILTERS.tgt", "pkg.mod.target"]


def test_module_level_insert_after_last_def_is_not_attributed():
    assert _analyze(_diff("""\
        @@ -7,2 +7,6 @@
         def helper(x):
             return x
        +
        +_PEMS = {
        +    b"CERTIFICATE",
        +}
        """)) == []


def test_class_attribute_and_guarded_class_and_registration():
    quals = _analyze(_diff("""\
        @@ -19,1 +19,1 @@ class Retry:
        -    DEFAULT_REMOVE = frozenset(["Authorization"])
        +    DEFAULT_REMOVE = frozenset(["Cookie", "Authorization"])
        @@ -27,2 +27,2 @@ if True:
                 def prepare_key(self, key):
        -            return key
        +            return bytes(key)
        @@ -36,1 +36,0 @@ class Constructor:
        -Constructor.add_multi_constructor("tag:new", Constructor.construct_new)
        """))
    assert quals == ["pkg.mod.Constructor.construct_new", "pkg.mod.Guarded.prepare_key", "pkg.mod.Retry.DEFAULT_REMOVE"]


def test_seed_fix_results_match_hand_curated_entries():
    curated = json.loads((HERE.parent / "backend/tracelock/kb/curated.json").read_text())
    snap = osv._load_snapshot()
    expect = {
        "CVE-2024-22195": {"jinja2.filters.do_xmlattr"},
        "CVE-2020-14343": {"yaml.constructor.FullConstructor.construct_python_module",
                           "yaml.constructor.FullConstructor.construct_python_object",
                           "yaml.constructor.FullConstructor.construct_python_object_new"},
        "CVE-2022-29217": {"jwt.algorithms.HMACAlgorithm.prepare_key", "jwt.algorithms.OKPAlgorithm.prepare_key"},
    }
    for cve, entry in curated.items():
        if cve.startswith("_") or entry["package"] == "certifi":
            continue  # certifi fixes are data-only (cacert.pem)
        recs = [r for r in snap[entry["package"]] if cve in r.get("aliases", [])]
        adv = osv.merge_aliases(recs, entry["package"])[0]
        dep = Dependency(entry["package"], "0", import_names=deps.import_names_for(entry["package"]))
        funcs, hunks, commit = fixdiff.functions_from_fix(adv, dep, offline=True)
        assert funcs and hunks and commit, cve
        assert set(funcs) & set(entry["vulnerable_funcs"]), (cve, funcs)
        if cve in expect:
            assert expect[cve] <= set(funcs), (cve, funcs)


def test_fix_tier_without_entry_points_cannot_claim_safety():
    snap = osv._load_snapshot()
    adv = osv.merge_aliases([r for r in snap["pyyaml"] if "CVE-2020-14343" in r["aliases"]], "pyyaml")[0]
    dep = Dependency("pyyaml", "5.3", import_names=["yaml"])
    table = kb._curated()
    saved = table.pop("CVE-2020-14343")
    try:
        spec = kb.resolve(adv, dep, offline=True)
    finally:
        table["CVE-2020-14343"] = saved
    assert spec.tier == TIER_NONE and spec.vulnerable_funcs and not spec.entry_api
    assert kb.resolve(adv, dep, offline=True).tier == TIER_CURATED



def _fake_package(root: Path) -> Path:
    pkg = root / "fakepkg"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text("from .core import Client\n\ndef real_api(data):\n    return Client().fetch(data)\n")
    (pkg / "core.py").write_text("def _danger(x):\n    return eval(x)\n\nclass Client:\n    def fetch(self, data):\n        return _danger(data)\n")
    return root


def test_llm_hallucinated_name_is_dropped_and_cache_is_reused_offline():
    import tempfile
    from tracelock.kb import llm
    from tracelock.models import TIER_LLM, Advisory
    seen = {}

    def fake_llm(system, prompt):
        seen["prompt"] = prompt
        return "fake", "fake-model", '```json\n{"entry_api": ["fakepkg.real_api", "fakepkg.Client.fetch", ' \
                                     '"fakepkg.made_up_function", "fakepkg.core.totally_real"], "reasoning": "x"}\n```'

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        lib_src = _fake_package(tmp / "src")
        saved = (llm._transport_override, llm.LOCAL_CACHE, llm.DATA_CACHE, fixdiff.functions_from_fix)
        llm._transport_override = fake_llm
        llm.LOCAL_CACHE, llm.DATA_CACHE = tmp / "cache", tmp / "data"
        fixdiff.functions_from_fix = lambda adv, dep, offline=False: (
            ["fakepkg.core._danger"], ["@@ -1,2 +1,2 @@ def _danger(x):\n-    return eval(x)"], "https://github.com/x/fakepkg/commit/abc")
        try:
            adv = Advisory(id="GHSA-fake-0000-0001", summary="code execution in fetch",
                           fix_urls=["https://github.com/x/fakepkg/commit/abc"])
            dep = Dependency("fakepkg", "1.0", import_names=["fakepkg"])
            spec = kb.resolve(adv, dep, lib_src=lib_src, offline=False)
            assert spec.tier == TIER_LLM, spec.tier
            assert spec.entry_api == ["fakepkg.real_api", "fakepkg.Client.fetch"], spec.entry_api
            assert "fakepkg.made_up_function" not in spec.targets() and "fakepkg.core.totally_real" not in spec.targets()
            assert "fakepkg.real_api" in seen["prompt"] and "_danger" not in seen["prompt"].split("choose ONLY from this list):")[1]
            # offline, no source: only names verified earlier for this exact version come back
            llm._transport_override = lambda s, p: (_ for _ in ()).throw(AssertionError("network used offline"))
            again = kb.resolve(adv, dep, lib_src=None, offline=True)
            assert again.tier == TIER_LLM and again.entry_api == spec.entry_api, (again.tier, again.entry_api)
            other = kb.resolve(adv, Dependency("fakepkg", "2.0", import_names=["fakepkg"]), lib_src=None, offline=True)
            assert other.tier == TIER_NONE and not other.entry_api  # not verified for 2.0 -> safety net
        finally:
            llm._transport_override, llm.LOCAL_CACHE, llm.DATA_CACHE, fixdiff.functions_from_fix = saved


def test_llm_parse_response_is_defensive():
    from tracelock.kb import llm
    assert llm.parse_response("no json here")["entry_api"] == []
    assert llm.parse_response('{"entry_api": ["a.b", 3, null, " c.d "]}')["entry_api"] == ["a.b", "c.d"]
    assert llm.parse_response('{"entry_api": "a.b"}')["entry_api"] == []

if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"ok    {name}")
        except Exception as exc:  # any error is a failed test
            failed += 1
            print(f"FAIL  {name}: {exc}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
