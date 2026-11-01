"""Deterministic unused-package rule: a package with no function data is NOT_REACHABLE only when nothing can load it."""
import textwrap

from tracelock import app_graph, verdict
from tracelock.lib_graph import ExposureSet
from tracelock.models import NOT_REACHABLE, TIER_NONE, UNCERTAIN, Advisory, Dependency, VulnSpec

JWT = Dependency("pyjwt", "2.3.0", import_names=["jwt"])
FLASK = Dependency("flask", "2.2.4", import_names=["flask"], requires=["werkzeug", "jinja2", "itsdangerous", "click"])
WERKZEUG = Dependency("werkzeug", "2.2.2", import_names=["werkzeug"], requires=["markupsafe"])
JINJA = Dependency("jinja2", "3.1.2", import_names=["jinja2"], requires=["markupsafe"])
LIBS = {"flask": ["flask", "werkzeug", "jinja2", "click", "itsdangerous"], "werkzeug": ["werkzeug"], "jinja2": ["jinja2", "markupsafe"]}


def _app(tmp_path, files):
    root = tmp_path / "app"
    for name, code in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(code))
    return app_graph.build(root)


def _decide(app, deps, libs=LIBS, dep=JWT):
    spec = VulnSpec("GHSA-jwt", dep.name, tier=TIER_NONE, confidence=0.0)
    return verdict.decide(app, dep, Advisory("GHSA-jwt"), spec, ExposureSet(), all_deps=deps, library_imports=libs)


FLASK_APP = {"app.py": "from flask import Flask\n\napp = Flask(__name__)\n\n@app.route('/')\ndef index():\n    return 'hi'\n"}


def test_unused_pyjwt_is_not_reachable(tmp_path):
    f = _decide(_app(tmp_path, FLASK_APP), [FLASK, WERKZEUG, JINJA, JWT])
    assert f.verdict == NOT_REACHABLE, [r.detail for r in f.reasons]
    assert f.checklist["package_absent_from_dependency_graph"] is True


def test_direct_import_stays_uncertain(tmp_path):
    f = _decide(_app(tmp_path, {**FLASK_APP, "auth.py": "import jwt\n\ndef check(t):\n    return t\n"}), [FLASK, WERKZEUG, JINJA, JWT])
    assert f.verdict == UNCERTAIN and any(r.kind == "no_function_data" for r in f.reasons)


def test_cross_module_import(tmp_path):
    files = {**FLASK_APP, "pkg/__init__.py": "", "pkg/tokens.py": "from jwt import decode as d\n", "pkg/use.py": "from .tokens import d\n"}
    assert _decide(_app(tmp_path, files), [FLASK, WERKZEUG, JINJA, JWT]).verdict == UNCERTAIN


def test_transitive_requirement(tmp_path):
    ext = Dependency("flask-jwt-extended", "4.5.0", import_names=["flask_jwt_extended"], requires=["flask", "pyjwt"])
    app = _app(tmp_path, {"app.py": "import flask_jwt_extended\n"})
    f = _decide(app, [FLASK, WERKZEUG, JINJA, ext, JWT], libs={**LIBS, "flask-jwt-extended": ["flask", "jwt"]})
    assert f.verdict == UNCERTAIN and any(r.kind == "transitive" for r in f.reasons)


def test_two_hop_transitive_requirement(tmp_path):
    mid = Dependency("authlib-shim", "1.0", import_names=["shim_unused"], requires=["pyjwt"])
    top = Dependency("toplib", "1.0", import_names=["toplib"], requires=["authlib-shim"])
    f = _decide(_app(tmp_path, {"app.py": "import toplib\n"}), [top, mid, JWT], libs={"toplib": ["toplib"]})
    assert f.verdict == UNCERTAIN and any("toplib -> authlib-shim -> pyjwt" in r.detail for r in f.reasons)


def test_library_optional_import(tmp_path):
    libs = {**LIBS, "flask": ["flask", "jwt"]}   # e.g. `try: import jwt` inside the library, not in Requires-Dist
    f = _decide(_app(tmp_path, FLASK_APP), [FLASK, WERKZEUG, JINJA, JWT], libs=libs)
    assert f.verdict == UNCERTAIN and any("own source imports jwt" in r.detail for r in f.reasons)


def test_library_source_unknown(tmp_path):
    f = _decide(_app(tmp_path, FLASK_APP), [FLASK, WERKZEUG, JINJA, JWT], libs={"werkzeug": ["werkzeug"], "jinja2": ["jinja2"]})
    assert f.verdict == UNCERTAIN and any(r.kind == "dependency_graph_incomplete" for r in f.reasons)


def test_unknown_requirement_metadata(tmp_path):
    odd = Dependency("mystery", "1.0", import_names=["mystery"], requires=["never-heard-of-it"])
    f = _decide(_app(tmp_path, {"app.py": "import mystery\n"}), [odd, JWT], libs={"mystery": ["mystery"]})
    assert f.verdict == UNCERTAIN and any("never-heard-of-it" in r.detail for r in f.reasons)


def test_dynamic_import(tmp_path):
    files = {**FLASK_APP, "plug.py": "import importlib\n\ndef load(name):\n    return importlib.import_module(name)\n"}
    f = _decide(_app(tmp_path, files), [FLASK, WERKZEUG, JINJA, JWT])
    assert f.verdict == UNCERTAIN and any(r.kind == "dynamic" for r in f.reasons)


def test_string_reference(tmp_path):
    files = {**FLASK_APP, "cfg.py": "BACKEND = 'jwt.api_jwt'\n"}
    f = _decide(_app(tmp_path, files), [FLASK, WERKZEUG, JINJA, JWT])
    assert f.verdict == UNCERTAIN and any(r.kind == "string_ref" for r in f.reasons)


def test_unknown_dynamic_loading(tmp_path):
    files = {**FLASK_APP, "x.py": "def f(mod, name):\n    return getattr(mod, name)\n"}
    assert _decide(_app(tmp_path, files), [FLASK, WERKZEUG, JINJA, JWT]).verdict == UNCERTAIN


def test_unpinned_package_stays_uncertain(tmp_path):
    f = _decide(_app(tmp_path, FLASK_APP), [FLASK, WERKZEUG, JINJA, Dependency("pyjwt", "", import_names=["jwt"])],
                dep=Dependency("pyjwt", "", import_names=["jwt"]))
    assert f.verdict == UNCERTAIN
