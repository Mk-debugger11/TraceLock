"""Native (C / PyO3) mapping, deterministic verification of LLM candidates, and verdict safety. No network."""
import json
import textwrap
from pathlib import Path

import pytest

from tracelock import app_graph, lib_graph, native, verdict
from tracelock.kb import discovery, verify
from tracelock.llm import load_settings
from tracelock.llm.schema import parse_discovery
from tracelock.models import NOT_REACHABLE, REACHABLE, TIER_NATIVE, UNCERTAIN, Advisory, Dependency, VulnSpec

C_EXT = """
#include <Python.h>
/* the vulnerable helper */
static int
blur_rows(int *buf, int n) {
    int total = 0;
    for (int i = 0; i <= n; i++) { total += buf[i]; }
    return total;
}

static PyObject *
_blur(PyObject *self, PyObject *args) {
    int buf[4] = {0};
    return PyLong_FromLong(blur_rows(buf, 4));
}

static PyObject *
_copy(PyObject *self, PyObject *args) {
    return PyLong_FromLong(blur_rows(NULL, 0));
}

static PyObject *
_safe(PyObject *self, PyObject *args) { Py_RETURN_NONE; }

static PyMethodDef methods[] = {
    {"blur", (PyCFunction)_blur, METH_VARARGS},
    {"copy", (PyCFunction)(void (*)(void))_copy, METH_VARARGS},
    {"safe", _safe, METH_NOARGS},
    {NULL, NULL, 0, NULL}
};

static PyModuleDef module_def = {PyModuleDef_HEAD_INIT, "_core", NULL, -1, methods};

PyMODINIT_FUNC
PyInit__core(void) { return PyModule_Create(&module_def); }
"""

RUST = """
use pyo3::prelude::*;

fn check_name(n: &str) -> bool { n.len() > 3 }

#[pyo3::prelude::pyclass(name = "Verifier", module = "fakepkg._rust")]
struct RustVerifier {}

#[pyo3::prelude::pymethods]
impl RustVerifier {
    #[new]
    fn new() -> Self { RustVerifier {} }
    fn verify_name(&self, n: &str) -> bool { check_name(n) }
}

#[pyo3::prelude::pyfunction]
fn parse_thing(s: &str) -> bool { check_name(s) }

#[pyo3::prelude::pymodule]
fn _rust(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(parse_thing, m)?)?;
    m.add_class::<RustVerifier>()?;
    Ok(())
}
"""

PY_INIT = "from .image import Image, open_image\nfrom .verify import Verifier\n"
PY_IMAGE = """
from . import _core as core


class Image:
    def __init__(self):
        self.im = core.new()

    def blur(self):
        return self.im.blur()

    def duplicate(self):
        return helper(self)

    def safe(self):
        return self.im.safe()


def helper(obj):
    return obj.thing.copy()


def open_image(path):
    return Image()
"""
PY_VERIFY = """
from ._rust import parse_thing
from . import _rust as rust

Verifier = rust.Verifier


def parse(s):
    return parse_thing(s)
"""

DIFF = """diff --git a/src/blur.c b/src/blur.c
--- a/src/blur.c
+++ b/src/blur.c
@@ -3,7 +3,7 @@ static int blur_rows(int *buf, int n) {
 blur_rows(int *buf, int n) {
     int total = 0;
-    for (int i = 0; i <= n; i++) { total += buf[i]; }
+    for (int i = 0; i < n; i++) { total += buf[i]; }
     return total;
 }
"""


@pytest.fixture()
def pkg(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)   # caches under tmp
    sdist = tmp_path / "sdist" / "fakepkg-1.0"
    (sdist / "src").mkdir(parents=True)
    (sdist / "src" / "blur.c").write_text(C_EXT)
    (sdist / "rust" / "src").mkdir(parents=True)
    (sdist / "rust" / "src" / "lib.rs").write_text(RUST)
    lib = tmp_path / "lib"
    (lib / "fakepkg").mkdir(parents=True)
    (lib / "fakepkg" / "__init__.py").write_text(PY_INIT)
    (lib / "fakepkg" / "image.py").write_text(textwrap.dedent(PY_IMAGE))
    (lib / "fakepkg" / "verify.py").write_text(textwrap.dedent(PY_VERIFY))
    return sdist, lib


def _changes(funcs):
    return {"files": [{"path": "src/blur.c", "lang": "c", "how": "test"}],
            "functions": {f: {"file": "src/blur.c", "lang": "c", "how": "test"} for f in funcs},
            "hunks": native.changed_functions(DIFF, lambda p: None)["hunks"]}


def test_c_index_and_registration(pkg):
    sdist, _lib = pkg
    idx = native.NativeIndex(sdist)
    regs = {(r.py_name, r.impl, r.kind, r.module) for r in idx.registrations if r.file.endswith(".c")}
    assert ("blur", "_blur", "module_function", "_core") in regs
    assert ("copy", "_copy", "module_function", "_core") in regs        # cast `(void (*)(void))` handled
    assert idx.callers["blur_rows"] == {"_blur", "_copy"}
    assert native.changed_functions(DIFF, lambda p: None)["functions"] == {"blur_rows": {"file": "src/blur.c", "lang": "c", "how": "hunk_header"}}


def test_pyo3_registration(pkg):
    sdist, _lib = pkg
    idx = native.NativeIndex(sdist)
    regs = {(r.py_name, r.impl, r.kind) for r in idx.registrations if r.file.endswith(".rs")}
    assert {("parse_thing", "parse_thing", "pyo3_function"), ("Verifier", "RustVerifier", "pyo3_class"),
            ("verify_name", "verify_name", "pyo3_method"), ("Verifier", "new", "pyo3_new")} <= regs
    assert "_rust" in idx.ext_modules
    m = native.map_to_python(idx, {"files": [1], "functions": {"check_name": {"file": "rust/src/lib.rs", "lang": "rust"}}, "hunks": []},
                             pkg[1], ["fakepkg"])
    assert "fakepkg.verify.parse" in m.wrappers                      # `from ._rust import parse_thing`
    assert "fakepkg.verify.Verifier" in m.entry_symbols              # `Verifier = rust.Verifier`
    assert "fakepkg.verify.Verifier.verify_name" in m.entry_symbols


def test_wrapper_mapping_and_gaps(pkg):
    sdist, lib = pkg
    m = native.map_to_python(native.NativeIndex(sdist), _changes(["blur_rows"]), lib, ["fakepkg"])
    assert set(m.wrappers) == {"fakepkg.image.Image.blur"}            # self.im.blur() on a native object
    assert "fakepkg.image.helper" in m.ambiguous                      # obj.thing.copy(): common name, unknown receiver
    assert not m.complete and any(g.kind == "ambiguous_name" for g in m.gaps)
    assert m.chains["fakepkg.image.Image.blur"] == ["src/blur.c::_blur", "native::blur_rows"]


def test_version_mismatch_rejected_and_equivalent_by_overlap(pkg):
    sdist, lib = pkg
    idx = native.NativeIndex(sdist)
    m = native.map_to_python(idx, {**_changes([]), "functions": {"made_up_fn": {"file": "src/other.c", "lang": "c"}}}, lib, ["fakepkg"])
    assert m.changed["made_up_fn"]["pinned"] is False and any(g.kind == "missing_in_pinned" for g in m.gaps)
    ch = _changes(["blur_rows_v2"])
    for h in ch["hunks"]:
        h["functions"] = ["blur_rows_v2"]
        h["pre_lines"] += ["int total = 0;", "return total;", "for (int i = 0; i <= n; i++) { total += buf[i]; }"]
    m = native.map_to_python(idx, ch, lib, ["fakepkg"])
    assert m.equivalents["blur_rows_v2"][0][0] == "blur_rows" and "fakepkg.image.Image.blur" in m.wrappers


def _cand(symbol, native_target="blur_rows", files=("fakepkg/image.py",), kind="python_public_api"):
    return parse_discovery({"candidate_functions": [{"symbol": symbol, "kind": kind, "native_target": native_target,
                                                     "evidence": [{"file": f, "symbol": symbol} for f in files]}],
                            "limitations": []}).candidates[0]


def test_llm_candidates_verified_deterministically(pkg):
    sdist, lib = pkg
    idx = native.NativeIndex(sdist)
    m = native.map_to_python(idx, _changes(["blur_rows"]), lib, ["fakepkg"])
    ok = verify.verify_native_entry(_cand("fakepkg.Image.duplicate"), lib, sdist, idx, m, ["fakepkg"])
    assert ok.accepted and ok.resolved == "fakepkg.image.Image.duplicate" and ok.via == ["fakepkg.image.helper"]
    cases = {
        "nonexistent": _cand("fakepkg.image.Image.sharpen"),
        "wrong_native": _cand("fakepkg.Image.duplicate", native_target="PyInit__core"),
        "unknown_native": _cand("fakepkg.Image.duplicate", native_target="ImagingBlur"),
        "invented_path": _cand("fakepkg.Image.duplicate", files=("fakepkg/not_there.py",)),
        "no_path": _cand("fakepkg.image.open_image"),
        "safe_method": _cand("fakepkg.image.Image.safe"),
        "lookalike": _cand("fakepkg.other.Image.blur"),
    }
    for name, cand in cases.items():
        chk = verify.verify_native_entry(cand, lib, sdist, idx, m, ["fakepkg"])
        assert not chk.accepted, (name, chk.checks)
    native_kind = verify.verify_native_entry(_cand("blur_rows", kind="native_function", files=("src/blur.c",)), lib, sdist, idx, m, ["fakepkg"])
    assert not native_kind.accepted   # a native name never becomes a Python target


class Fake:
    name, model = "ollama", "qwen2.5-coder:3b"

    def __init__(self, reply):
        self.reply, self.calls = reply, 0

    def check_available(self):
        pass

    def discover_vulnerable_functions(self, request):
        from tracelock.llm.base import ChatResult
        self.calls += 1
        self.request = request
        return parse_discovery(self.reply), ChatResult("{}", self.reply, "ollama", self.model, 50)


def _dep():
    return Dependency("fakepkg", "1.0", import_names=["fakepkg"])


def _discover(pkg, monkeypatch, reply, funcs=("blur_rows",)):
    sdist, lib = pkg
    monkeypatch.setattr(discovery, "native_changes", lambda adv, offline: {**_changes(list(funcs)), "commits": ["https://github.com/x/fakepkg/commit/abc"]})
    monkeypatch.setattr(discovery.pypi_source, "fetch_sdist", lambda dep, offline=False: sdist)
    fake = Fake(reply)
    session = discovery.LLMSession(load_settings({"TRACELOCK_LLM_ENABLED": "true"}), fake)
    out = discovery.native_discovery(Advisory("GHSA-fake"), _dep(), lib, False, session)
    return out, fake, session


def test_discovery_without_llm_need(pkg, monkeypatch):
    out, fake, _ = _discover(pkg, monkeypatch, {"candidate_functions": [], "limitations": []})
    assert fake.calls == 0 and out["metadata"]["llm"]["status"] == "not_needed"   # deterministic found a wrapper


def test_discovery_llm_fills_a_gap_and_rejects_hallucinations(pkg, monkeypatch):
    # a fix in _copy only: reached through the ambiguous `obj.thing.copy()`, so deterministic finds no wrapper
    reply = {"candidate_functions": [
        {"symbol": "fakepkg.Image.duplicate", "kind": "python_public_api", "native_target": "_copy",
         "evidence": [{"file": "fakepkg/image.py", "symbol": "Image.duplicate"}]},
        {"symbol": "fakepkg.image.Image.made_up", "kind": "python_public_api", "native_target": "_copy",
         "evidence": [{"file": "fakepkg/image.py", "symbol": "made_up"}]},
    ], "limitations": []}
    out, fake, session = _discover(pkg, monkeypatch, reply, funcs=("_copy",))
    llm = out["metadata"]["llm"]
    assert fake.calls == 1 and llm["status"] == "used"
    assert (llm["candidates_suggested"], llm["candidates_verified"], llm["candidates_rejected"]) == (2, 1, 1)
    assert "fakepkg.image.Image.duplicate" in out["mapping"].entry_symbols
    assert "fakepkg.image.Image.made_up" not in out["mapping"].entry_symbols
    assert "_core" in " ".join(s.text for s in fake.request.snippets) or fake.request.native_targets
    assert out["metadata"]["method"] == "deterministic+llm"
    assert session.status()["candidates_verified"] == 1


def _app(tmp_path, code):
    root = tmp_path / "app"
    root.mkdir(exist_ok=True)
    (root / "main.py").write_text(textwrap.dedent(code))
    return app_graph.build(root)


def _native_spec(complete):
    return VulnSpec("GHSA-fake", "fakepkg", vulnerable_funcs=["fakepkg.image.Image.blur"], tier=TIER_NATIVE, confidence=0.5,
                    discovery={"native": {"complete": complete, "gap_count": 0 if complete else 1,
                                          "gaps": [] if complete else [{"kind": "function_pointer", "detail": "x"}]}})


def test_incomplete_native_mapping_never_not_reachable(pkg, tmp_path):
    _sdist, lib = pkg
    dep = _dep()
    app = _app(tmp_path, "import fakepkg\n\ndef main():\n    fakepkg.open_image('x')\n")
    spec = _native_spec(False)
    f = verdict.decide(app, dep, Advisory("GHSA-fake"), spec, lib_graph.exposure_set(lib, spec), all_deps=[dep])
    assert f.verdict == UNCERTAIN and any(r.kind == "native_mapping_incomplete" for r in f.reasons)
    app = _app(tmp_path, "import fakepkg\n\ndef main():\n    fakepkg.Image().blur()\n")
    f = verdict.decide(app, dep, Advisory("GHSA-fake"), spec, lib_graph.exposure_set(lib, spec), all_deps=[dep])
    assert f.verdict == REACHABLE
    app = _app(tmp_path, "import fakepkg\n\ndef main():\n    fakepkg.open_image('x')\n")
    spec = _native_spec(True)
    f = verdict.decide(app, dep, Advisory("GHSA-fake"), spec, lib_graph.exposure_set(lib, spec), all_deps=[dep])
    assert f.verdict == NOT_REACHABLE and any(c["factor"] == "native mapping" for c in f.confidence_factors)


def test_llm_output_cannot_set_a_verdict(pkg, monkeypatch):
    reply = {"candidate_functions": [], "limitations": [], "verdict": "NOT_REACHABLE"}
    out, fake, session = _discover(pkg, monkeypatch, reply, funcs=("_copy",))
    assert out["metadata"]["llm"]["status"] in ("bad_response",) or out["metadata"]["llm"]["candidates_verified"] == 0
    assert session.status()["candidates_verified"] == 0


def test_kb_resolve_without_llm_is_deterministic(pkg, monkeypatch):
    from tracelock import kb
    sdist, lib = pkg
    monkeypatch.setattr(discovery, "native_changes", lambda adv, offline: {**_changes(["blur_rows"]), "commits": ["u"]})
    monkeypatch.setattr(discovery.pypi_source, "fetch_sdist", lambda dep, offline=False: sdist)
    adv = Advisory("GHSA-fake", fix_urls=["https://github.com/x/fakepkg/commit/abc"])
    spec = kb.resolve(adv, _dep(), lib_src=lib, offline=False, session=discovery.LLMSession(load_settings({})))
    assert spec.tier == TIER_NATIVE and spec.vulnerable_funcs == ["fakepkg.image.Image.blur"]
    assert spec.discovery["llm"]["status"] == "not_needed" and spec.discovery["native"]["complete"] is False
    json.dumps(spec.discovery)   # report-safe


def test_python_equivalent_for_renamed_function(tmp_path):
    lib = tmp_path / "lib"
    (lib / "jwtish").mkdir(parents=True)
    (lib / "jwtish" / "__init__.py").write_text("")
    (lib / "jwtish" / "api.py").write_text(textwrap.dedent("""
        class PyJWT:
            def decode_complete(self, jwt, key):
                payload = self._load(jwt)
                if not isinstance(payload, dict):
                    raise DecodeError("Invalid payload string: must be a json object")
                merged_options = {**self.options, **options}
                return payload
    """))
    hunk = textwrap.dedent("""\
        @@ -1,6 +1,6 @@
             def _decode_payload(self, decoded):
        -        payload = self._load(jwt)
                 if not isinstance(payload, dict):
        -            raise DecodeError("Invalid payload string: must be a json object")
                 merged_options = {**self.options, **options}
        """)
    eqs = verify.python_equivalents(lib, "jwtish.api.PyJWT._decode_payload", [hunk])
    assert eqs and eqs[0][0] == "jwtish.api.PyJWT.decode_complete"
    assert verify.resolve_python_symbol(lib, "jwtish.api.PyJWT._decode_payload") is None
    assert not verify.verify_python_equivalent("jwtish.api.PyJWT.encode", "x", lib, [hunk]).accepted
