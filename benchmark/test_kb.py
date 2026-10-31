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


if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"ok    {name}")
        except AssertionError as exc:
            failed += 1
            print(f"FAIL  {name}: {exc}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
