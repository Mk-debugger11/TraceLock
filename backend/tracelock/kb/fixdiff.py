"""Fix-commit tier: map a GitHub fix commit's hunks to the functions they touch. OWNER: Vaibhav.

Pipeline (BRIEF_VAIBHAV.md task 4):
 1. Commit URLs from adv.fix_urls (then other github.com/<o>/<r>/commit/<sha> references in the
    OSV record); /pull/<n> URLs are expanded to their commits via <pr>.patch ("From <sha>" lines).
 2. GET https://github.com/<o>/<r>/commit/<sha>.diff  (unified diff).
 3. For every changed .py file outside tests/docs: parse the hunks; record each deleted old line,
    and each inserted line's position between two old lines.
 4. Fetch the PRE-fix file: GitHub contents API with ref=<sha>^ (raw media type; GITHUB_TOKEN used
    when set), falling back to `git fetch --depth 2 --filter=blob:none` + `git show <sha>^:<path>`
    when the API is rate-limited.
 5. ast.parse it and map every changed line to the innermost enclosing def (decorators included);
    the `@@ ... def foo` header text is never used. Inserted lines belong to the def that contains
    the line before them when they are indented deeper than that def (so appended statements count
    and new sibling defs do not). Lines outside any def: changed class/module attributes that
    existed before the fix (Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT), and references in changed
    module-level lines to functions/methods defined in the file (pyyaml's add_multi_constructor
    registrations).
 6. Registration aliases: a module-level dict mapping a string key to a vulnerable function
    (jinja2 FILTERS = {"xmlattr": do_xmlattr}) adds '<module>.<DICT>.<key>', because templates and
    dispatch tables reach the function by that key, which app_graph records as a string ref.
 7. Module = path minus a leading src/ lib/ lib3/ python/, '/' -> '.', '__init__' dropped. Only
    qualnames under the dependency's import names are returned.
 8. Results are cached per commit in .tracelock/cache/fixes/<sha>.json; the seed advisories' results
    are committed in tracelock/data/fixes/<sha>.json (with the raw .diff) so --offline works.

    python -m tracelock.kb.fixdiff <commit-or-pr-url> [import_name ...]   # print one result
    python -m tracelock.kb.fixdiff --seed                                  # rebuild data/fixes/*.json
"""
from __future__ import annotations

import ast
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Optional

from ..models import Advisory, Dependency

DATA_FIXES = Path(__file__).resolve().parent.parent / "data" / "fixes"
CACHE_DIR = Path(".tracelock") / "cache" / "fixes"
COMMIT_RE = re.compile(r"^https?://github\.com/([\w.-]+)/([\w.-]+)/commit/([0-9a-fA-F]{7,40})")
PULL_RE = re.compile(r"^https?://github\.com/([\w.-]+)/([\w.-]+)/pull/(\d+)")
HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)$")
SKIP_PATH_RE = re.compile(r"(^|/)(tests?|testing|docs?|examples?|benchmarks?|dummyserver|\.github)/|(^|/)(test_[^/]*|[^/]*_test|conftest|setup|noxfile)\.py$")
SRC_PREFIXES = {"src", "lib", "lib3", "python"}
MAX_COMMITS = 6
MAX_HUNKS = 12
MAX_HUNK_LINES = 60
USER_AGENT = "tracelock-fixdiff/0.1"
RETRIES = 3


# --- network --------------------------------------------------------------------------------

def _get(url: str, headers: Optional[dict] = None, timeout: int = 30) -> bytes:
    last: Exception = RuntimeError("no attempt")
    for attempt in range(RETRIES):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read()
        except urllib.error.HTTPError as exc:
            if exc.code in (403, 404, 410, 422, 429):
                raise  # not transient for our purposes (missing, or rate limited)
            last = exc
        except Exception as exc:
            last = exc
        if attempt < RETRIES - 1:
            time.sleep(0.5 * (2 ** attempt))
    raise last


def _prefix_source_api(owner: str, repo: str, sha: str, path: str) -> str:
    url = (f"https://api.github.com/repos/{owner}/{repo}/contents/{urllib.parse.quote(path)}"
           f"?ref={sha}%5E")
    headers = {"Accept": "application/vnd.github.raw"}
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return _get(url, headers).decode("utf-8", errors="replace")


def _prefix_source_git(owner: str, repo: str, sha: str, path: str) -> str:
    if not shutil.which("git"):
        raise RuntimeError("git not installed")
    gitdir = CACHE_DIR / "repos" / f"{owner}__{repo}.git"
    run = lambda *args: subprocess.run(["git", "-C", str(gitdir), *args], check=True, capture_output=True, text=True, timeout=180)
    if not (gitdir / "HEAD").exists():
        gitdir.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "init", "-q", "--bare", str(gitdir)], check=True, capture_output=True, timeout=60)
        run("remote", "add", "origin", f"https://github.com/{owner}/{repo}.git")
    try:
        run("cat-file", "-e", f"{sha}^{{commit}}")
    except subprocess.CalledProcessError:
        run("fetch", "-q", "--depth", "2", "--filter=blob:none", "origin", sha)
        run("config", "remote.origin.promisor", "true")
        run("config", "remote.origin.partialclonefilter", "blob:none")
    return run("show", f"{sha}^:{path}").stdout


def _prefix_source(owner: str, repo: str, sha: str, path: str) -> tuple[Optional[str], str]:
    errors = []
    for name, fn in (("api", _prefix_source_api), ("git", _prefix_source_git)):
        try:
            return fn(owner, repo, sha, path), name
        except Exception as exc:
            errors.append(f"{name}: {exc}")
    return None, "; ".join(errors)


def _pr_commits(owner: str, repo: str, number: str, offline: bool) -> list[str]:
    key = DATA_FIXES / f"pr_{owner}__{repo}__{number}.json"
    cache = CACHE_DIR / key.name
    for path in (key, cache):
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))["commits"]
    if offline:
        return []
    patch = _get(f"https://github.com/{owner}/{repo}/pull/{number}.patch").decode("utf-8", errors="replace")
    shas = re.findall(r"(?m)^From ([0-9a-f]{40}) ", patch)
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache.write_text(json.dumps({"pr": f"https://github.com/{owner}/{repo}/pull/{number}", "commits": shas}), encoding="utf-8")
    return shas


# --- diff parsing ---------------------------------------------------------------------------

def parse_diff(text: str) -> list[dict]:
    """[{path, new_file, deleted, hunks: [{header, old_start, lines, changes: [(kind, old_pos, text)]}]}]"""
    files: list[dict] = []
    cur: Optional[dict] = None
    hunk: Optional[dict] = None
    old_ln = 0
    for line in text.splitlines():
        if line.startswith("diff --git "):
            m = re.match(r"diff --git a/(.+?) b/(.+)$", line)
            cur = {"path": m.group(2) if m else line[11:], "old_path": m.group(1) if m else None,
                   "new_file": False, "deleted": False, "hunks": []}
            files.append(cur)
            hunk = None
            continue
        if cur is None:
            continue
        if hunk is None:
            if line.startswith("new file mode"):
                cur["new_file"] = True
            elif line.startswith("deleted file mode"):
                cur["deleted"] = True
            elif line.startswith("rename from "):
                cur["old_path"] = line[len("rename from "):]
        m = HUNK_RE.match(line)
        if m:
            old_ln = int(m.group(1))
            hunk = {"header": line, "old_start": old_ln, "old_len": int(m.group(2) or 1), "lines": [line], "changes": []}
            cur["hunks"].append(hunk)
            continue
        if hunk is None:
            continue
        tag = line[:1]
        if tag == "-":
            hunk["changes"].append(("del", old_ln, line[1:]))
            old_ln += 1
        elif tag == "+":
            hunk["changes"].append(("ins", old_ln, line[1:]))
        elif tag == "\\":
            continue
        else:  # context (' ' or an empty line from a stripped diff)
            old_ln += 1
        hunk["lines"].append(line)
    return files


def module_name(path: str) -> str:
    parts = [p for p in Path(path).with_suffix("").parts]
    if len(parts) > 1 and parts[0] in SRC_PREFIXES:
        parts = parts[1:]
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


class _Defs:
    """Functions, classes and attribute assignments of one pre-fix module, with line spans."""

    def __init__(self, source: str):
        tree = ast.parse(source)
        self.lines = source.splitlines()
        self.funcs: list[tuple[int, int, int, str]] = []    # (start, end, col, qualname)
        self.classes: list[tuple[int, int, int, str]] = []
        self.attrs: list[tuple[int, int, str, bool]] = []    # (start, end, qualname, class_level)
        self.module_funcs: dict[str, str] = {}               # bare name -> qualname
        self.class_methods: dict[str, set] = {}              # class qualname -> method names
        self.dicts: list[tuple[str, dict]] = []              # (DICTNAME, {key: function name})
        self._walk(tree, "", None)

    def _walk(self, node: ast.AST, prefix: str, cls: Optional[str]) -> None:
        for ch in ast.iter_child_nodes(node):
            if isinstance(ch, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                qual = f"{prefix}.{ch.name}" if prefix else ch.name
                start = min([ch.lineno, *[d.lineno for d in ch.decorator_list]])
                end = ch.end_lineno or ch.lineno
                if isinstance(ch, ast.ClassDef):
                    self.classes.append((start, end, ch.col_offset, qual))
                    self.class_methods.setdefault(qual, set())
                    self._walk(ch, qual, qual)
                else:
                    self.funcs.append((start, end, ch.col_offset, qual))
                    if not prefix:
                        self.module_funcs[ch.name] = qual
                    if cls is not None and prefix == cls:
                        self.class_methods[cls].add(ch.name)
                    self._walk(ch, qual, None)
            elif isinstance(ch, (ast.Assign, ast.AnnAssign)) and (cls is not None or not prefix):
                targets = ch.targets if isinstance(ch, ast.Assign) else [ch.target]
                for t in targets:
                    if isinstance(t, ast.Name):
                        qual = f"{prefix}.{t.id}" if prefix else t.id
                        self.attrs.append((ch.lineno, ch.end_lineno or ch.lineno, qual, cls is not None))
                        if not prefix and isinstance(ch.value, ast.Dict):
                            mapping = {k.value: v.id for k, v in zip(ch.value.keys, ch.value.values)
                                       if isinstance(k, ast.Constant) and isinstance(k.value, str) and isinstance(v, ast.Name)}
                            if mapping:
                                self.dicts.append((t.id, mapping))
            elif isinstance(ch, (ast.stmt, ast.excepthandler)) and not isinstance(ch, (ast.Assign, ast.AnnAssign)):
                self._walk(ch, prefix, cls)  # if/try/with/for blocks: same scope

    def func_at(self, line: int) -> Optional[str]:
        inner = [f for f in self.funcs if f[0] <= line <= f[1]]
        return max(inner, key=lambda f: f[0])[3] if inner else None

    def func_for_insert(self, pos: int, text: str) -> tuple[Optional[str], int]:
        """Insertion before old line `pos`: (def containing line pos-1 that the new line is indented into, its column)."""
        indent = len(text) - len(text.lstrip())
        inner = [f for f in self.funcs if f[0] <= pos - 1 <= f[1] and indent > f[2]]
        if not inner:
            return None, -1
        best = max(inner, key=lambda f: f[0])
        return best[3], best[2]

    def attr_at(self, line: int) -> Optional[str]:
        for start, end, qual, class_level in self.attrs:
            if start <= line <= end:
                last = qual.rsplit(".", 1)[-1]
                if last.startswith("__") and last.endswith("__"):
                    return None
                if not class_level and last.startswith("_"):
                    return None
                return qual
        return None

    def refs_in(self, text: str) -> set[str]:
        """Functions/methods defined in this module that a changed module-level line refers to."""
        found = set()
        for cls_name, meth in re.findall(r"\b([A-Za-z_]\w*)\.([A-Za-z_]\w*)\b", text):
            for cls, methods in self.class_methods.items():
                if cls.rsplit(".", 1)[-1] == cls_name and meth in methods:
                    found.add(f"{cls}.{meth}")
        for name in re.findall(r"\b([A-Za-z_]\w*)\b", text):
            if name in self.module_funcs:
                found.add(self.module_funcs[name])
        return found


def analyze_commit(owner: str, repo: str, sha: str, diff_text: str) -> dict:
    """Map one commit's diff to pre-fix qualnames. Network only for pre-fix sources."""
    files_out, hunks_out, all_quals = [], [], set()
    for f in parse_diff(diff_text):
        path = f.get("old_path") or f["path"]
        if not path.endswith(".py") or f["new_file"] or SKIP_PATH_RE.search(path):
            continue
        module = module_name(path)
        source, how = _prefix_source(owner, repo, sha, path)
        if source is None:
            files_out.append({"path": path, "module": module, "error": how})
            continue
        try:
            defs = _Defs(source)
        except SyntaxError as exc:  # e.g. Python 2 sources (pyyaml lib/)
            files_out.append({"path": path, "module": module, "error": f"pre-fix file does not parse: {exc.msg}"})
            continue
        file_quals: set[str] = set()
        for hunk in f["hunks"]:
            quals: set[str] = set()
            run_pos, run_owner, run_col = None, None, -1
            for kind, pos, text in hunk["changes"]:
                if kind == "ins" and pos != run_pos:
                    run_pos, run_owner, run_col = pos, None, -1  # new run of inserted lines
                if not text.strip():
                    continue
                if kind == "del":
                    run_pos = None
                    func = defs.func_at(pos)
                else:
                    # The first non-blank line of a run decides; a later line dedented to or past the
                    # owner's def column has left that def (statement continuation lines stay with it).
                    indent = len(text) - len(text.lstrip())
                    if run_owner is None or indent <= run_col:
                        if run_owner is None and run_col == -2:
                            func = None  # run already decided as outside any def
                        else:
                            run_owner, run_col = defs.func_for_insert(pos, text)
                            if run_owner is None:
                                run_col = -2
                    func = run_owner
                if func:
                    quals.add(func)
                    continue
                if kind == "del":
                    attr = defs.attr_at(pos)
                    if attr:
                        quals.add(attr)
                if not text.startswith((" ", "\t")) or kind == "del":
                    quals |= defs.refs_in(text)
            full = {f"{module}.{q}" for q in quals}
            if full:
                hunks_out.append({"path": path, "header": hunk["header"], "functions": sorted(full),
                                  "text": "\n".join(hunk["lines"][:MAX_HUNK_LINES])})
            file_quals |= quals
        # registration aliases: FILTERS = {"xmlattr": do_xmlattr}
        for dict_name, mapping in defs.dicts:
            for key, fn in mapping.items():
                if fn in file_quals:
                    file_quals.add(f"{dict_name}.{key}")
        files_out.append({"path": path, "module": module, "prefix_source": how,
                          "functions": sorted(f"{module}.{q}" for q in file_quals)})
        all_quals |= {f"{module}.{q}" for q in file_quals}
    return {"commit_url": f"https://github.com/{owner}/{repo}/commit/{sha}", "owner": owner, "repo": repo, "sha": sha,
            "qualnames": sorted(all_quals), "files": files_out, "hunks": hunks_out}


def _load_or_analyze(owner: str, repo: str, sha: str, offline: bool) -> Optional[dict]:
    for path in (DATA_FIXES / f"{sha}.json", CACHE_DIR / f"{sha}.json"):
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    if offline:
        return None
    diff_file = DATA_FIXES / f"{sha}.diff"
    if diff_file.exists():
        diff_text = diff_file.read_text(encoding="utf-8", errors="replace")
    else:
        diff_text = _get(f"https://github.com/{owner}/{repo}/commit/{sha}.diff", timeout=60).decode("utf-8", errors="replace")
    result = analyze_commit(owner, repo, sha, diff_text)
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    (CACHE_DIR / f"{sha}.json").write_text(json.dumps(result, indent=1), encoding="utf-8")
    (CACHE_DIR / f"{sha}.diff").write_text(diff_text, encoding="utf-8")
    return result


def candidate_commits(adv: Advisory, offline: bool = False) -> list[tuple[str, str, str]]:
    urls = list(adv.fix_urls) + [r.get("url", "") for r in adv.raw.get("references", []) if r.get("type") != "FIX"]
    out: list[tuple[str, str, str]] = []
    for url in urls:
        m = COMMIT_RE.match(url or "")
        if m:
            item = (m.group(1), m.group(2), m.group(3).lower())
            if item not in out:
                out.append(item)
            continue
        m = PULL_RE.match(url or "")
        if m and url in adv.fix_urls:
            try:
                for sha in _pr_commits(m.group(1), m.group(2), m.group(3), offline):
                    item = (m.group(1), m.group(2), sha)
                    if item not in out:
                        out.append(item)
            except Exception:
                continue
    return out[:MAX_COMMITS]


def functions_from_fix(adv: Advisory, dep: Dependency, offline: bool = False) -> tuple[list[str], list[str], Optional[str]]:
    """Return (vulnerable function qualnames under dep's import names, evidence hunks, commit url).

    Offline: only results already in data/fixes/ or the local cache are used."""
    tops = set(dep.import_names)
    quals: set[str] = set()
    hunks: list[str] = []
    first_url: Optional[str] = None
    for owner, repo, sha in candidate_commits(adv, offline):
        try:
            result = _load_or_analyze(owner, repo, sha, offline)
        except Exception:
            continue
        if not result:
            continue
        mine = {q for q in result["qualnames"] if q.split(".", 1)[0] in tops}
        if not mine:
            continue
        quals |= mine
        first_url = first_url or result["commit_url"]
        for h in result["hunks"]:
            if len(hunks) < MAX_HUNKS and any(q in mine for q in h["functions"]):
                hunks.append(f"{result['repo']}@{sha[:10]} {h['path']}\n{h['text']}")
    return sorted(quals), hunks, first_url


def persist(adv: Advisory) -> int:
    """Copy this advisory's cached fix-commit analyses (and diffs) into data/fixes/ for --offline use."""
    copied = 0
    for _owner, _repo, sha in candidate_commits(adv, offline=True):
        for suffix in (".json", ".diff"):
            src, dst = CACHE_DIR / f"{sha}{suffix}", DATA_FIXES / f"{sha}{suffix}"
            if src.exists() and not dst.exists():
                dst.write_bytes(src.read_bytes())
                copied += 1
    return copied


def cached_hunks(commit_url: Optional[str], dep: Dependency) -> list[str]:
    """Evidence hunks for a curated entry's fix commit, from data/fixes only (never the network)."""
    m = COMMIT_RE.match(commit_url or "")
    if not m:
        return []
    path = DATA_FIXES / f"{m.group(3).lower()}.json"
    if not path.exists():
        return []
    result = json.loads(path.read_text(encoding="utf-8"))
    tops = set(dep.import_names)
    return [f"{result['repo']}@{result['sha'][:10]} {h['path']}\n{h['text']}" for h in result["hunks"]
            if any(q.split(".", 1)[0] in tops for q in h["functions"])][:MAX_HUNKS]


def _seed() -> int:
    """Rebuild data/fixes/<sha>.json for every fix commit named in kb/curated.json."""
    curated = json.loads((Path(__file__).parent / "curated.json").read_text(encoding="utf-8"))
    commits = []
    for key, entry in curated.items():
        if key.startswith("_"):
            continue
        for url in entry.get("fix_commits") or [entry.get("fix_commit")]:
            m = COMMIT_RE.match(url or "")
            if m and m.groups() not in commits:
                commits.append(m.groups())
    for owner, repo, sha in commits:
        diff_file = DATA_FIXES / f"{sha}.diff"
        if not diff_file.exists():
            diff_file.write_bytes(_get(f"https://github.com/{owner}/{repo}/commit/{sha}.diff", timeout=60))
        result = analyze_commit(owner, repo, sha, diff_file.read_text(encoding="utf-8", errors="replace"))
        (DATA_FIXES / f"{sha}.json").write_text(json.dumps(result, indent=1) + "\n", encoding="utf-8")
        errors = [f["error"] for f in result["files"] if "error" in f]
        print(f"{owner}/{repo}@{sha[:10]}: {result['qualnames']}" + (f"  (skipped: {errors})" if errors else ""), file=sys.stderr)
    return 0


def main(argv: list[str]) -> int:
    if argv[:1] == ["--seed"]:
        return _seed()
    if not argv:
        print(__doc__)
        return 2
    url, tops = argv[0], argv[1:]
    adv = Advisory(id="adhoc", fix_urls=[url])
    from ..deps import import_names_for
    m = COMMIT_RE.match(url) or PULL_RE.match(url)
    dep = Dependency(name=m.group(2).lower() if m else "x", version="0", import_names=tops or (import_names_for(m.group(2)) if m else []))
    funcs, hunks, commit = functions_from_fix(adv, dep)
    print(json.dumps({"commit": commit, "functions": funcs, "hunks": len(hunks)}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
