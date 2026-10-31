"""A vulnerable function that is passed around instead of called, re-exported, or stored on `self` must
never come out NOT_REACHABLE. Safe look-alikes must stay NOT_REACHABLE."""
import textwrap

import pytest

from tracelock import scan

PYYAML = ("pyyaml==5.3", {"CVE-2020-14343", "CVE-2020-1747"})
REQUESTS = ("requests==2.30.0", {"CVE-2023-32681"})
PYJWT = ("pyjwt==2.3.0", {"CVE-2022-29217"})

VULNERABLE = {
    "map_reference": (PYYAML, {"app.py": "import yaml\ndef parse_all(files):\n    return list(map(yaml.load, files))\n"}),
    "partial": (PYYAML, {"app.py": """
        import functools, yaml
        loader = functools.partial(yaml.load, Loader=yaml.FullLoader)
        def main():
            return loader(open("c.yaml"))
        """}),
    "sorted_key": (PYYAML, {"app.py": "import yaml\ndef main(docs):\n    return sorted(docs, key=yaml.unsafe_load)\n"}),
    "decorator_registry": (PYYAML, {"app.py": """
        import yaml
        HANDLERS = []
        def register(fn):
            HANDLERS.append(fn)
            return fn
        register(yaml.full_load)
        """}),
    "dispatch_dict": (PYYAML, {"app.py": """
        import json, yaml
        PARSERS = {"j": json.loads, "y": yaml.unsafe_load}
        def parse(kind, text):
            return PARSERS[kind](text)
        """}),
    "class_attribute": (PYYAML, {"app.py": """
        import yaml
        class Reader:
            loader = yaml.load
            def read(self, fh):
                return self.loader(fh)
        """}),
    "default_argument": (PYYAML, {"app.py": "import yaml\ndef parse(text, fn=yaml.load):\n    return fn(text)\n"}),
    "returned_function": (PYYAML, {"app.py": "import yaml\ndef get_parser():\n    return yaml.full_load\n"}),
    "reexport_through_app_module": (PYYAML, {
        "helpers.py": "from yaml import load\n",
        "app.py": "from helpers import load\ndef main():\n    return load(open('c.yaml'))\n",
    }),
    "module_on_self": (PYYAML, {"app.py": """
        import yaml
        class Cfg:
            def __init__(self):
                self.parser = yaml
            def read(self, fh):
                return self.parser.load(fh)
        """}),
    "session_on_self": (REQUESTS, {"app.py": """
        import requests
        class Client:
            def __init__(self):
                self.session = requests.Session()
            def fetch(self, url):
                return self.session.get(url)
        """}),
    "session_from_factory_defined_later": (REQUESTS, {"app.py": """
        import requests
        class Client:
            def __init__(self):
                self.session = make_session()
            def fetch(self, url):
                return self.session.get(url)
        def make_session():
            return requests.Session()
        """}),
    "session_from_factory_in_other_module": (REQUESTS, {
        "app.py": """
        from factory import make_session
        class Client:
            def __init__(self):
                self.session = make_session()
            def fetch(self, url):
                return self.session.get(url)
        """,
        "factory.py": "import requests\ndef make_session():\n    return requests.Session()\n",
    }),
}

# Receivers we cannot type: the honest answer is UNCERTAIN, never NOT_REACHABLE.
UNTYPED = {
    "untyped_session_parameter": (REQUESTS, {"app.py": """
        import requests
        def fetch(http, url):
            return http.get(url)
        def main():
            return fetch(requests.Session(), "https://example.com")
        """}),
    "untyped_jwt_codec": (PYJWT, {"app.py": """
        import jwt
        def verify(codec, token, key):
            return codec.decode(token, key, algorithms=["HS256", "RS256"])
        def main(token, key):
            return verify(jwt, token, key)
        """}),
}

SAFE = {
    "isinstance_check": (PYYAML, {"app.py": """
        import yaml
        def describe(loader):
            yaml.safe_load("a: 1")
            return isinstance(loader, yaml.FullLoader)
        """}),
    "partial_with_safe_loader": (PYYAML, {"app.py": """
        import functools, yaml
        loader = functools.partial(yaml.load, Loader=yaml.SafeLoader)
        def main():
            return loader(open("c.yaml"))
        """}),
    "map_safe_load": (PYYAML, {"app.py": "import yaml\ndef parse_all(files):\n    return list(map(yaml.safe_load, files))\n"}),
    "annotation_only": (PYYAML, {"app.py": "import yaml\nloader_cls: yaml.FullLoader = None\ndef main(fh):\n    return yaml.safe_load(fh)\n"}),
    "safe_loader_keyword": (PYYAML, {"app.py": "import yaml\ndef main(fh):\n    return yaml.load(fh, Loader=yaml.SafeLoader)\n"}),
}


def verdicts(tmp_path, case):
    (requirement, cves), files = case
    for name, source in files.items():
        (tmp_path / name).write_text(textwrap.dedent(source))
    (tmp_path / "requirements.txt").write_text(requirement + "\n")
    got = {}
    for f in scan(tmp_path, offline=True).findings:
        hit = cves & {f.advisory.id, *f.advisory.aliases}
        if hit:
            got[hit.pop()] = f.verdict
    assert got, f"none of {cves} reported for {requirement}"
    return set(got.values())


@pytest.mark.parametrize("name", sorted(VULNERABLE))
def test_function_used_indirectly_is_reachable(tmp_path, name):
    assert verdicts(tmp_path, VULNERABLE[name]) == {"REACHABLE"}


@pytest.mark.parametrize("name", sorted(UNTYPED))
def test_untyped_receiver_in_a_file_importing_the_package_is_uncertain(tmp_path, name):
    assert verdicts(tmp_path, UNTYPED[name]) == {"UNCERTAIN"}


@pytest.mark.parametrize("name", sorted(SAFE))
def test_safe_look_alike_stays_not_reachable(tmp_path, name):
    assert verdicts(tmp_path, SAFE[name]) == {"NOT_REACHABLE"}


def test_reference_is_explained_in_the_evidence(tmp_path):
    (tmp_path / "app.py").write_text("import yaml\ndef parse_all(files):\n    return list(map(yaml.load, files))\n")
    (tmp_path / "requirements.txt").write_text("pyyaml==5.3\n")
    finding = next(f for f in scan(tmp_path, offline=True).findings if "CVE-2020-14343" in f.advisory.aliases)
    assert finding.path[-2].code == "return list(map(yaml.load, files))"
    assert any(r.kind == "reference" and r.line == 3 for r in finding.reasons)
