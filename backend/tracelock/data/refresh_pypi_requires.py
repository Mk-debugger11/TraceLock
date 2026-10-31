#!/usr/bin/env python3
"""Rebuild tracelock/data/pypi_requires.json: runtime requirements of the seed pins. OWNER: Vaibhav.

    python backend/tracelock/data/refresh_pypi_requires.py [name==version ...]

Reads https://pypi.org/pypi/<name>/<version>/json -> info.requires_dist. Requirements that only
apply under an extra (`; extra == "socks"`) are dropped; other markers are kept (over-approximate,
which only makes the transitive rule more cautious). deps.py uses this file to fill
Dependency.requires when the project gives no dependency graph (requirements.txt / Pipfile.lock).
"""
from __future__ import annotations

import json
import re
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

OUT = Path(__file__).resolve().parent / "pypi_requires.json"
SEED_PINS = [
    "pyyaml==5.3", "jinja2==3.1.2", "jinja2==3.1.3", "requests==2.30.0", "requests==2.31.0",
    "urllib3==1.26.17", "urllib3==2.0.6", "pillow==9.3.0", "pillow==10.1.0", "werkzeug==2.2.2",
    "werkzeug==3.0.2", "flask==2.2.5", "setuptools==69.0.3", "pyjwt==2.3.0", "python-multipart==0.0.6",
    "aiohttp==3.9.1", "black==23.12.1", "cryptography==41.0.5", "certifi==2022.9.24", "tqdm==4.66.1",
]
_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def runtime_requires(requires_dist: list[str] | None) -> list[str]:
    names = []
    for req in requires_dist or []:
        marker = req.split(";", 1)[1] if ";" in req else ""
        if re.search(r"\bextra\s*==", marker):
            continue
        m = _NAME.match(req)
        if m and norm(m.group(1)) not in names:
            names.append(norm(m.group(1)))
    return sorted(names)


def main(argv: list[str]) -> int:
    pins = argv or SEED_PINS
    data = json.loads(OUT.read_text(encoding="utf-8")) if OUT.exists() else {}
    for pin in pins:
        name, _, version = pin.partition("==")
        name = norm(name)
        with urllib.request.urlopen(f"https://pypi.org/pypi/{name}/{version}/json", timeout=30) as resp:
            info = json.loads(resp.read().decode("utf-8"))["info"]
        data.setdefault(name, {})[version] = runtime_requires(info.get("requires_dist"))
        print(f"{name}=={version}: {data[name][version]}", file=sys.stderr)
    data["_comment"] = ("Runtime Requires-Dist (extras dropped) per pinned version, from pypi.org JSON API. "
                        "Regenerate with backend/tracelock/data/refresh_pypi_requires.py.")
    data["_meta"] = {"generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                     "source": "https://pypi.org/pypi/<name>/<version>/json info.requires_dist"}
    OUT.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
