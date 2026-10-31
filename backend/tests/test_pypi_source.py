import io
import stat
import subprocess
import tarfile
import zipfile

import pytest

from tracelock import pypi_source
from tracelock.models import Dependency

REQUESTS_METADATA = """\
Metadata-Version: 2.1
Name: requests
Version: 2.31.0
Requires-Dist: charset-normalizer (<4,>=2)
Requires-Dist: idna (<4,>=2.5)
Requires-Dist: urllib3 (<3,>=1.21.1)
Requires-Dist: certifi (>=2017.4.17)
Requires-Dist: PySocks (!=1.5.7,>=1.5.6) ; extra == 'socks'
Requires-Dist: chardet (<6,>=3.0.2) ; extra == "use_chardet_on_py3"
Requires-Dist: importlib_metadata ; python_version < "3.8"

Long description.
"""


@pytest.fixture()
def dirs(tmp_path, monkeypatch):
    """Isolated seed and cache dirs; any pip call fails the test."""
    seeds = tmp_path / "wheels"
    seeds.mkdir()
    monkeypatch.setattr(pypi_source, "DATA_WHEELS", seeds)
    monkeypatch.setattr(pypi_source, "CACHE_SRC", tmp_path / "cache" / "src")
    monkeypatch.setattr(pypi_source, "CACHE_DL", tmp_path / "cache" / "dl")

    def no_subprocess(*args, **kwargs):
        raise AssertionError("pip must not run")

    monkeypatch.setattr(subprocess, "run", no_subprocess)
    return seeds


def write_zip(path, members):
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in members.items():
            info = zipfile.ZipInfo(name)
            if isinstance(data, tuple):
                data, info.external_attr = data
            zf.writestr(info, data)
    return path


def write_tar(path, members, symlinks=()):
    with tarfile.open(path, "w:gz") as tf:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        for name, target in symlinks:
            info = tarfile.TarInfo(name)
            info.type, info.linkname = tarfile.SYMTYPE, target
            tf.addfile(info)
    return path


def test_seed_wheel_is_unpacked_and_metadata_read(dirs, tmp_path):
    write_zip(dirs / "PyYAML-5.3-cp38-cp38-win32.whl", {
        "yaml/__init__.py": b"def load(stream, Loader=None): pass\n",
        "_yaml.cp38-win32.pyd": b"\x00",
        "PyYAML-5.3.dist-info/top_level.txt": b"_yaml\nyaml\n",
        "PyYAML-5.3.dist-info/METADATA": b"Metadata-Version: 2.1\nName: PyYAML\nVersion: 5.3\n",
    })
    dep = Dependency("pyyaml", "5.3")

    root = pypi_source.fetch(dep, offline=True)

    assert root == (tmp_path / "cache" / "src" / "pyyaml-5.3").resolve()
    assert (root / "yaml" / "__init__.py").is_file()
    assert dep.import_names == ["yaml", "_yaml"]
    assert dep.requires == []
    assert not list(root.parent.glob(".tmp-*"))  # staging dir cleaned up


def test_requires_drops_extras_and_keeps_markers(dirs):
    write_zip(dirs / "requests-2.31.0-py3-none-any.whl", {
        "requests/__init__.py": b"",
        "requests-2.31.0.dist-info/METADATA": REQUESTS_METADATA.encode(),
        "requests-2.31.0.dist-info/RECORD": b"requests/__init__.py,,\nrequests-2.31.0.dist-info/METADATA,,\n",
    })
    dep = Dependency("requests", "2.31.0", import_names=["requests"])

    pypi_source.fetch(dep, offline=True)

    assert dep.requires == ["charset-normalizer", "idna", "urllib3", "certifi", "importlib-metadata"]
    assert dep.import_names == ["requests"]  # from RECORD, since there is no top_level.txt


def test_import_names_are_merged_not_replaced(dirs):
    write_zip(dirs / "python_multipart-0.0.6-py3-none-any.whl", {
        "multipart/__init__.py": b"",
        "python_multipart-0.0.6.dist-info/top_level.txt": b"multipart\n",
    })
    dep = Dependency("python-multipart", "0.0.6", import_names=["python_multipart"])
    pypi_source.fetch(dep, offline=True)
    assert dep.import_names == ["python_multipart", "multipart"]


def test_sdist_uses_lib3_and_egg_info(dirs):
    write_tar(dirs / "PyYAML-5.3.tar.gz", {
        "PyYAML-5.3/setup.py": b"raise SystemExit('must never run')\n",
        "PyYAML-5.3/PKG-INFO": b"Metadata-Version: 1.1\nName: PyYAML\nVersion: 5.3\n",
        "PyYAML-5.3/lib/yaml/__init__.py": b"# python 2\n",
        "PyYAML-5.3/lib3/yaml/__init__.py": b"# python 3\n",
        "PyYAML-5.3/tests/__init__.py": b"",
    })
    dep = Dependency("pyyaml", "5.3", import_names=["yaml"])

    root = pypi_source.fetch(dep, offline=True)

    assert root.name == "pyyaml-5.3"
    assert (root / "yaml" / "__init__.py").read_text() == "# python 3\n"
    assert not (root / "setup.py").exists() and not (root / "tests").exists()
    assert dep.import_names == ["yaml"] and dep.requires == []


def test_sdist_src_layout_requires_txt(dirs):
    write_tar(dirs / "demo-1.0.tar.gz", {
        "demo-1.0/src/demo/__init__.py": b"",
        "demo-1.0/src/demo.egg-info/top_level.txt": b"demo\n",
        "demo-1.0/src/demo.egg-info/requires.txt": (
            b"urllib3>=1\n[:python_version < \"3.8\"]\ntyping_extensions\n[socks]\nPySocks\n"
        ),
    })
    dep = Dependency("demo", "1.0")
    root = pypi_source.fetch(dep, offline=True)
    assert (root / "demo" / "__init__.py").is_file()
    assert dep.import_names == ["demo"]
    assert dep.requires == ["urllib3", "typing-extensions"]


@pytest.mark.parametrize("bad", ["../evil.py", "/tmp/evil.py", "pkg/../../evil.py"])
def test_zip_slip_wheel_is_refused(dirs, tmp_path, bad):
    write_zip(dirs / "evil-1.0-py3-none-any.whl", {"evil/__init__.py": b"", bad: b"pwned"})

    assert pypi_source.fetch(Dependency("evil", "1.0"), offline=True) is None
    assert not (tmp_path / "cache" / "src" / "evil-1.0").exists()
    assert not (tmp_path / "cache" / "evil.py").exists() and not (tmp_path / "evil.py").exists()


def test_tar_slip_and_links_are_refused(dirs, tmp_path):
    write_tar(dirs / "evil-1.0.tar.gz", {"evil-1.0/evil/__init__.py": b"", "evil-1.0/../../evil.py": b"x"})
    assert pypi_source.fetch(Dependency("evil", "1.0"), offline=True) is None

    write_tar(dirs / "linky-1.0.tar.gz", {"linky-1.0/linky/__init__.py": b""},
              symlinks=[("linky-1.0/linky/passwd", "/etc/passwd")])
    root = pypi_source.fetch(Dependency("linky", "1.0"), offline=True)
    assert (root / "linky" / "__init__.py").is_file()
    assert not (root / "linky" / "passwd").exists() and not (root / "linky" / "passwd").is_symlink()


def test_zip_symlink_members_are_skipped(dirs):
    write_zip(dirs / "linky-2.0-py3-none-any.whl", {
        "linky/__init__.py": b"",
        "linky/passwd": (b"/etc/passwd", (stat.S_IFLNK | 0o777) << 16),
    })
    root = pypi_source.fetch(Dependency("linky", "2.0"), offline=True)
    assert not (root / "linky" / "passwd").exists() and not (root / "linky" / "passwd").is_symlink()


def test_offline_without_seed_or_cache_returns_none(dirs):
    assert pypi_source.fetch(Dependency("flask", "2.2.5"), offline=True) is None


def test_suspicious_requirement_never_reaches_pip(dirs):
    assert pypi_source.fetch(Dependency("--index-url=http://evil", "1.0")) is None
    assert pypi_source.fetch(Dependency("flask", "1.0 --pre")) is None


def test_online_falls_back_to_pypi_file_when_pip_fails(dirs, monkeypatch, tmp_path):
    import hashlib
    import json

    wheel = write_zip(tmp_path / "built.whl", {
        "yaml/__init__.py": b"",
        "PyYAML-5.3.dist-info/top_level.txt": b"yaml\n",
    }).read_bytes()
    release = {"urls": [
        {"packagetype": "bdist_wheel", "filename": "PyYAML-5.3-cp27-cp27m-win32.whl", "url": "https://x/py2", "size": 1},
        {"packagetype": "sdist", "filename": "PyYAML-5.3.tar.gz", "url": "https://x/sdist", "size": 1},
        {"packagetype": "bdist_wheel", "filename": "PyYAML-5.3-cp38-cp38-win32.whl", "url": "https://x/cp38",
         "size": len(wheel), "digests": {"sha256": hashlib.sha256(wheel).hexdigest()}},
    ]}
    fetched = []

    def fake_urlopen(url, timeout):
        fetched.append(url)
        return io.BytesIO(json.dumps(release).encode() if "pypi.org" in url else wheel)

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 1, "", "no wheel"))
    monkeypatch.setattr(pypi_source.urllib.request, "urlopen", fake_urlopen)
    dep = Dependency("pyyaml", "5.3")

    root = pypi_source.fetch(dep)

    assert fetched == ["https://pypi.org/pypi/pyyaml/5.3/json", "https://x/cp38"]
    assert (root / "yaml" / "__init__.py").is_file() and dep.import_names == ["yaml"]


def test_sha256_mismatch_is_refused(dirs, monkeypatch, tmp_path):
    monkeypatch.setattr(pypi_source.urllib.request, "urlopen", lambda url, timeout: io.BytesIO(b"tampered"))
    with pytest.raises(pypi_source.ArchiveError, match="sha256"):
        pypi_source._http_download("https://x/f.whl", tmp_path / "f.whl", "0" * 64)
    assert not (tmp_path / "f.whl").exists()
