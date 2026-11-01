"""Native-extension analysis: C / Rust code changed by a fix commit -> the Python names that reach it. OWNER: Mukul.

Many advisories (Pillow, cryptography) are fixed in C or Rust. fixdiff only maps `.py` hunks, so these
end up with no function data and stay UNCERTAIN. This module maps them deterministically:

 1. changed_native_functions(): the fix commit's diff -> native functions it changes. Changed lines are
    mapped to the enclosing function of the PRE-fix file (GitHub, like fixdiff), else to the hunk header.
 2. NativeIndex(sdist root of the PINNED version): every C/Rust function with its calls and the
    functions it uses as values (function pointers), #define macros, and the binding tables that make
    native code Python-visible:
        C:     PyMethodDef / PyGetSetDef tables, attached through tp_methods, Py_tp_methods,
               PyModuleDef / m_methods, Py_InitModule, PyModule_AddFunctions
        PyO3:  #[pyfunction], #[pymethods] impl blocks (#[getter] #[setter] #[new], #[pyo3(name=..)]),
               #[pyclass(name=.., module=..)], #[pymodule] + wrap_pyfunction! / add_class
 3. map_to_python(): walk callers upward from the changed functions to registered implementations,
    then find the Python functions of the pinned package that use those Python-visible names
    (`core.fill(...)`, `self.im.rankfilter(...)`, `getattr(core, name + "_decoder")`).

Nothing is guessed silently. Every step that could hide a path (a function pointer, a dynamic
getattr, a common method name on an unknown receiver, a changed function missing from the pinned
version, a native root nobody registers) is recorded in `gaps`. A mapping with gaps can support
REACHABLE (a path was found) but never NOT_REACHABLE: verdict.py turns gaps into a blocking reason.
"""
from __future__ import annotations

import ast
import bisect
import hashlib
import json
import pickle
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

C_SUFFIXES = (".c", ".h", ".cc", ".cpp", ".cxx", ".hh", ".hpp")
RUST_SUFFIXES = (".rs",)
NATIVE_SUFFIXES = C_SUFFIXES + RUST_SUFFIXES
SKIP_DIR_RE = re.compile(r"(^|/)(tests?|Tests|testing|docs?|examples?|benchmarks?|winbuild|depends|\.github|fuzz|target)(/|$)")
MAX_FILES = 4000
MAX_FILE_BYTES = 2_000_000
MAX_NATIVE_DEPTH = 14
INDEX_VERSION = 6
CACHE_DIR = Path(".tracelock") / "cache" / "native"

C_KEYWORDS = {"if", "for", "while", "switch", "return", "sizeof", "do", "else", "case", "goto", "typeof", "__typeof__",
              "defined", "_Generic", "alignof", "_Alignof", "__attribute__", "__declspec", "static_assert",
              "_Static_assert", "__builtin_expect", "offsetof", "va_arg", "assert"}
RUST_KEYWORDS = {"if", "while", "for", "match", "return", "loop", "fn", "let", "in", "as", "move", "where", "impl",
                 "Some", "None", "Ok", "Err", "Box", "Vec", "unsafe", "dyn", "ref", "mut", "self", "Self", "super", "crate"}
# Method names that also exist on str/bytes/dict/list/file objects: an unknown receiver calling one of
# these is no evidence of native code, so such a use is recorded as a gap instead of a wrapper.
COMMON_METHODS = {"get", "put", "set", "copy", "close", "read", "write", "open", "load", "save", "update", "keys",
                  "values", "items", "pop", "append", "extend", "insert", "remove", "clear", "count", "index",
                  "sort", "reverse", "split", "join", "strip", "replace", "format", "encode", "decode", "lower",
                  "upper", "find", "seek", "tell", "flush", "send", "recv", "start", "stop", "run", "reset",
                  "new", "convert", "filter", "map", "add", "sub", "size", "mode", "name", "id", "type", "info",
                  "data", "getdata", "tobytes", "frombytes", "setdefault", "fileno", "truncate", "verify",
                  "sign", "finalize", "digest", "hexdigest", "next", "draw", "render", "resize", "crop",
                  "paste", "transform", "point", "fill", "line", "text", "bbox", "box", "path", "apply"}

_C_TOKEN_RE = re.compile(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'', re.S)
_RS_TOKEN_RE = re.compile(r'//[^\n]*|/\*.*?\*/|\bb?r(#*)".*?"\1|\bb?"(?:\\.|[^"\\])*"|(?<!\w)"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\\n])\'', re.S)
_IDENT_CALL_RE = re.compile(r"\b([A-Za-z_]\w*)\b(\s*\()?")
_C_HEADER_RE = re.compile(r"([A-Za-z_]\w*)\s*\((?:[^()]|\([^()]*\))*\)\s*(?:__attribute__\s*\(\(.*?\)\)\s*)?$", re.S)


# --- data model -----------------------------------------------------------------------------

@dataclass
class NativeFunction:
    name: str
    file: str                  # path relative to the sdist root
    start: int
    end: int
    lang: str                  # "c" | "rust"
    calls: set = field(default_factory=set)
    refs: set = field(default_factory=set)      # identifiers used as values (function pointers), filled per index
    static: bool = False
    exposed: bool = False      # #[pyfunction] / method in a #[pymethods] block
    lines: list = field(default_factory=list)   # normalised body lines, for version-equivalence checks


@dataclass
class Registration:
    py_name: str               # the name Python code uses: "rankfilter", "libtiff_decoder", "PolicyBuilder"
    impl: str                  # native function (or Rust struct) behind it
    kind: str                  # module_function | method | getset | pyo3_function | pyo3_method | pyo3_class | unknown
    owner: Optional[str]       # extension module or type name when known
    file: str
    line: int
    table: str = ""
    module: Optional[str] = None   # extension module defined in the same file (PyInit_<name>), when known


@dataclass
class Gap:
    kind: str                  # function_pointer | file_scope_table | unregistered_root | missing_in_pinned | depth_limit
                               # | ambiguous_name | dynamic_getattr | import_time | no_registration | no_python_use
    detail: str
    file: Optional[str] = None
    line: Optional[int] = None

    def to_dict(self) -> dict:
        return {"kind": self.kind, "detail": self.detail, "file": self.file, "line": self.line}


# --- source helpers -------------------------------------------------------------------------

def _blank(m: re.Match, keep_strings: bool) -> str:
    text = m.group(0)
    if keep_strings and (text.startswith('"') or text.startswith("'") or text.startswith(("r", "b"))):
        return text
    return re.sub(r"[^\n]", " ", text)


def strip_source(text: str, lang: str, keep_strings: bool = False) -> str:
    """Comments (and string literals unless keep_strings) replaced by spaces; offsets and lines are preserved."""
    pattern = _RS_TOKEN_RE if lang == "rust" else _C_TOKEN_RE
    return pattern.sub(lambda m: _blank(m, keep_strings), text)


def _norm_line(line: str) -> str:
    return re.sub(r"\s+", " ", line.strip())


def _significant(line: str) -> bool:
    s = _norm_line(line)
    return len(s) >= 12 and s not in {"return NULL;", "return 0;", "return -1;", "} else {", "break;"}


class _Lines:
    def __init__(self, text: str):
        self.starts = [0] + [m.end() for m in re.finditer(r"\n", text)]

    def line(self, offset: int) -> int:
        return bisect.bisect_right(self.starts, offset)


def _match_brace(code: str, open_pos: int) -> int:
    depth = 0
    for m in re.finditer(r"[{}]", code[open_pos:]):
        depth += 1 if m.group(0) == "{" else -1
        if depth == 0:
            return open_pos + m.start()
    return len(code) - 1


def _split_top(text: str) -> list[str]:
    """Split on commas outside parentheses."""
    out, depth, cur = [], 0, []
    for ch in text:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    out.append("".join(cur))
    return [p.strip() for p in out]


def _last_ident(text: str) -> Optional[str]:
    idents = [i for i in re.findall(r"[A-Za-z_]\w*", text) if i not in {"NULL", "void", "PyCFunction", "getter", "setter",
                                                                          "PyCFunctionWithKeywords", "PyNoArgsFunction"}]
    return idents[-1] if idents else None


# --- C parsing ------------------------------------------------------------------------------

def parse_c(text: str, rel: str) -> tuple[list[NativeFunction], dict, list[Registration], list[tuple[str, int, set]], set]:
    """(functions, macros {name: (calls, line)}, registrations, file-scope references, extension module names)."""
    with_strings = strip_source(text, "c", keep_strings=True)
    code = strip_source(text, "c")
    lines = _Lines(code)
    raw_lines = text.splitlines()

    # Preprocessor: #define bodies become pseudo-functions; every directive is blanked before brace matching.
    macros: dict[str, tuple[set, int]] = {}
    def _pp(m: re.Match) -> str:
        directive = m.group(0)
        d = re.match(r"\s*#\s*define\s+([A-Za-z_]\w*)(\([^)]*\))?(.*)", directive, re.S)
        if d:
            body = d.group(3).replace("\\\n", " ")
            idents = {i for i in re.findall(r"\b[A-Za-z_]\w*\b", body)} - C_KEYWORDS
            macros[d.group(1)] = (idents, lines.line(m.start()))
        return re.sub(r"[^\n]", " ", directive)
    code = re.sub(r"(?m)^[ \t]*#(?:[^\n\\]|\\\n|\\.)*", _pp, code)

    functions: list[NativeFunction] = []
    file_scope: list[tuple[int, int]] = []      # (start, end) spans of code outside function bodies
    depth, boundary, i = 0, 0, 0
    tokens = list(re.finditer(r"[{};]", code))
    k = 0
    while k < len(tokens):
        tok = tokens[k]
        ch, pos = tok.group(0), tok.start()
        if depth == 0 and ch == "{":
            header = code[boundary:pos]
            m = _C_HEADER_RE.search(header)
            is_func = bool(m) and m.group(1) not in C_KEYWORDS and "=" not in header.split("(")[0] \
                and not re.search(r"\b(struct|union|enum)\s+\w*\s*$", header.split("(")[0].strip() + " ")
            end = _match_brace(code, pos)
            if is_func:
                name = m.group(1)
                body = code[pos:end + 1]
                calls, refs = set(), set()
                for cm in _IDENT_CALL_RE.finditer(body):
                    ident = cm.group(1)
                    if ident in C_KEYWORDS:
                        continue
                    (calls if cm.group(2) else refs).add(ident)
                start_line = lines.line(boundary + (len(header) - len(header.lstrip())))
                end_line = lines.line(end)
                functions.append(NativeFunction(
                    name=name, file=rel, start=start_line, end=end_line, lang="c", calls=calls - {name}, refs=refs,
                    static=bool(re.search(r"\bstatic\b", header)),
                    lines=[_norm_line(x) for x in raw_lines[start_line - 1:end_line] if _significant(x)]))
            else:
                file_scope.append((boundary, end + 1))
            while k < len(tokens) and tokens[k].start() <= end:
                k += 1
            boundary = end + 1
            continue
        if ch == ";" and depth == 0:
            file_scope.append((boundary, pos + 1))
            boundary = pos + 1
        k += 1

    regs: list[Registration] = []
    ext_modules = set(re.findall(r"\bPyInit_([A-Za-z_]\w*)\s*\(", code))
    owners = _c_table_owners(with_strings, code)
    for kind_name, kind in (("PyMethodDef", "method_table"), ("PyGetSetDef", "getset")):
        for m in re.finditer(rf"\b{kind_name}\s+([A-Za-z_]\w*)\s*\[[^\]]*\]\s*=\s*\{{", code):
            table = m.group(1)
            open_pos = m.end() - 1
            close = _match_brace(code, open_pos)
            body = with_strings[open_pos + 1:close]
            owner_kind, owner = owners.get(table, ("unknown", None))
            if kind == "getset":
                reg_kind = "getset"
            else:
                reg_kind = {"type": "method", "module": "module_function"}.get(owner_kind, "unknown")
            for em in re.finditer(r"\{([^{}]*)\}", body):
                fields = _split_top(em.group(1))
                if len(fields) < 2:
                    continue
                nm = re.fullmatch(r'"([^"]+)"', fields[0])
                if not nm:
                    continue
                impls = [_last_ident(fields[1])] + ([_last_ident(fields[2])] if kind == "getset" and len(fields) > 2 else [])
                line = lines.line(open_pos + 1 + em.start())
                for impl in impls:
                    if impl:
                        regs.append(Registration(nm.group(1), impl, reg_kind, owner, rel, line, table))
    if len(ext_modules) == 1:
        for r in regs:
            r.module = next(iter(ext_modules))
    file_refs = []
    for start, end in file_scope:
        seg = code[start:end]
        idents = {cm.group(1) for cm in _IDENT_CALL_RE.finditer(seg) if not cm.group(2)}
        file_refs.append((rel, lines.line(start), idents))
    return functions, macros, regs, file_refs, ext_modules


def _c_table_owners(with_strings: str, code: str) -> dict[str, tuple[str, Optional[str]]]:
    """table name -> ("type" | "module", owner name) from PyTypeObject / PyType_Spec / PyModuleDef usage."""
    owners: dict[str, tuple[str, Optional[str]]] = {}
    for m in re.finditer(r"\b(PyTypeObject|PyModuleDef)\s+([A-Za-z_]\w*)\s*=\s*\{", code):
        close = _match_brace(code, m.end() - 1)
        body_code = code[m.end():close]
        body_str = with_strings[m.end():close]
        first = re.search(r'"([^"]+)"', body_str)
        kind = "type" if m.group(1) == "PyTypeObject" else "module"
        for ident in set(re.findall(r"\b[A-Za-z_]\w*\b", body_code)):
            owners.setdefault(ident, (kind, first.group(1) if first else None))
    for m in re.finditer(r"\.(tp_methods|tp_getset|m_methods)\s*=\s*([A-Za-z_]\w*)", code):
        owners[m.group(2)] = ("module" if m.group(1) == "m_methods" else "type", owners.get(m.group(2), (None, None))[1])
    for m in re.finditer(r"\{\s*Py_tp_(methods|getset)\s*,\s*(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\}", code):
        owners[m.group(2)] = ("type", None)
    for m in re.finditer(r'\bPy_InitModule\d?\s*\(\s*"([^"]+)"\s*,\s*([A-Za-z_]\w*)', with_strings):
        owners[m.group(2)] = ("module", m.group(1))
    for m in re.finditer(r"\bPyModule_AddFunctions\s*\(\s*\w+\s*,\s*([A-Za-z_]\w*)", code):
        owners[m.group(1)] = ("module", None)
    return owners


# --- Rust / PyO3 parsing --------------------------------------------------------------------

_PYO3_ATTR = r"#\[\s*(?:[\w:]*::)?{}\b"


def _attrs_before(with_strings: str, pos: int) -> str:
    """Attribute text directly above an item starting at pos (up to the previous item boundary)."""
    window = with_strings[max(0, pos - 600):pos]
    cut = max(window.rfind("}"), window.rfind(";"))
    return window[cut + 1:] if cut >= 0 else window


def _pyo3_name(attrs: str) -> Optional[str]:
    m = re.search(r'\bname\s*=\s*"([^"]+)"', attrs)
    return m.group(1) if m else None


def parse_rust(text: str, rel: str) -> tuple[list[NativeFunction], list[Registration], set]:
    with_strings = strip_source(text, "rust", keep_strings=True)
    code = strip_source(text, "rust")
    lines = _Lines(code)
    raw_lines = text.splitlines()
    regs: list[Registration] = []
    modules: set = set()

    classes: dict[str, tuple[str, Optional[str]]] = {}   # struct ident -> (python name, module)
    for m in re.finditer(r"(?:pub(?:\([^)]*\))?\s+)?(?:struct|enum)\s+([A-Za-z_]\w*)", code):
        attrs = _attrs_before(with_strings, m.start())
        pc = re.search(_PYO3_ATTR.format("pyclass") + r"(?:\s*\(([^)]*)\))?", attrs)
        if pc:
            args = pc.group(1) or ""
            mod = re.search(r'\bmodule\s*=\s*"([^"]+)"', args)
            classes[m.group(1)] = (_pyo3_name(args) or m.group(1), mod.group(1) if mod else None)
            regs.append(Registration(classes[m.group(1)][0], m.group(1), "pyo3_class",
                                     mod.group(1) if mod else None, rel, lines.line(m.start())))

    impl_spans = []   # (start, end, struct ident)
    for m in re.finditer(r"\bimpl\s*(?:<[^{]*?>)?\s*([A-Za-z_][\w:]*)(?:<[^{]*?>)?\s*\{", code):
        attrs = _attrs_before(with_strings, m.start())
        if re.search(_PYO3_ATTR.format("pymethods"), attrs):
            impl_spans.append((m.end() - 1, _match_brace(code, m.end() - 1), m.group(1).split("::")[-1]))

    functions: list[NativeFunction] = []
    for m in re.finditer(r"\bfn\s+([A-Za-z_]\w*)", code):
        name = m.group(1)
        j, depth = m.end(), 0
        open_pos = None
        while j < len(code):
            ch = code[j]
            if ch in "(<[":
                depth += 1
            elif ch in ")>]":
                depth = max(0, depth - 1) if not (ch == ">" and code[j - 1] == "-") else depth
            elif ch == ";" and depth == 0:
                break
            elif ch == "{" and depth == 0:
                open_pos = j
                break
            j += 1
        if open_pos is None:
            continue   # trait method declaration without a body
        close = _match_brace(code, open_pos)
        body = code[open_pos:close + 1]
        calls, refs = set(), set()
        for cm in re.finditer(r"\b([A-Za-z_]\w*)\b\s*(?:::\s*<[^>()]*>\s*)?(\()?", body):
            ident = cm.group(1)
            if ident in RUST_KEYWORDS:
                continue
            (calls if cm.group(2) else refs).add(ident)
        start_line, end_line = lines.line(m.start()), lines.line(close)
        attrs = _attrs_before(with_strings, m.start())
        fn = NativeFunction(name=name, file=rel, start=start_line, end=end_line, lang="rust",
                            calls=calls - {name}, refs=refs, static=not re.search(r"\bpub\b", attrs + code[m.start() - 12:m.start()]),
                            lines=[_norm_line(x) for x in raw_lines[start_line - 1:end_line] if _significant(x)])
        functions.append(fn)
        owner_struct = next((s for a, b, s in impl_spans if a < m.start() < b), None)
        if re.search(_PYO3_ATTR.format("pyfunction"), attrs):
            fn.exposed = True
            regs.append(Registration(_pyo3_name(attrs) or name, name, "pyo3_function", None, rel, start_line))
        elif owner_struct is not None:
            fn.exposed = True
            cls_name = classes.get(owner_struct, (owner_struct, None))[0]
            if re.search(_PYO3_ATTR.format("new"), attrs):
                regs.append(Registration(cls_name, name, "pyo3_new", cls_name, rel, start_line))
            else:
                py = _pyo3_name(attrs)
                g = re.search(_PYO3_ATTR.format("(getter|setter)") + r"(?:\s*\(\s*([A-Za-z_]\w*)\s*\))?", attrs)
                if g and not py:
                    py = g.group(2) or re.sub(r"^(get|set)_", "", name)
                regs.append(Registration(py or name, name, "pyo3_method", cls_name, rel, start_line))
        if re.search(_PYO3_ATTR.format("pymodule"), attrs):
            # The module init only registers names (wrap_pyfunction!, add_class); it is not a caller of them.
            modules.add(_pyo3_name(attrs) or name)
            fn.exposed = True
            fn.refs = set()
    for m in re.finditer(r'PyModule::new\s*\(\s*\w+\s*,\s*"([A-Za-z_]\w*)"', with_strings):
        modules.add(m.group(1))
    return functions, regs, modules


# --- the index ------------------------------------------------------------------------------

class NativeIndex:
    """All native functions, macros and Python bindings of one unpacked sdist."""

    def __init__(self, root: Path):
        self.root = Path(root)
        self.functions: dict[str, list[NativeFunction]] = {}
        self.macros: dict[str, tuple[set, str, int]] = {}
        self.registrations: list[Registration] = []
        self.file_refs: list[tuple[str, int, set]] = []
        self.ext_modules: set = set()
        self.files = 0
        for path in sorted(self.root.rglob("*")):
            if not path.is_file() or not path.name.endswith(NATIVE_SUFFIXES):
                continue
            rel = path.relative_to(self.root).as_posix()
            if SKIP_DIR_RE.search(rel) or path.stat().st_size > MAX_FILE_BYTES:
                continue
            self.files += 1
            if self.files > MAX_FILES:
                break
            text = path.read_text(encoding="utf-8", errors="replace")
            if path.suffix == ".rs":
                funcs, regs, mods = parse_rust(text, rel)
                self.ext_modules |= mods
            else:
                funcs, macros, regs, refs, mods = parse_c(text, rel)
                for name, (calls, line) in macros.items():
                    self.macros.setdefault(name, (calls, rel, line))
                self.file_refs.extend(refs)
                self.ext_modules |= mods
            for f in funcs:
                self.functions.setdefault(f.name, []).append(f)
            self.registrations.extend(regs)
        known = set(self.functions)
        for funcs in self.functions.values():
            for f in funcs:
                f.refs &= known
                f.refs -= f.calls
        self.callers: dict[str, set] = {}
        self.pointer_users: dict[str, set] = {}
        for funcs in self.functions.values():
            for f in funcs:
                for c in f.calls:
                    self.callers.setdefault(c, set()).add(f.name)
                for r in f.refs:
                    self.pointer_users.setdefault(r, set()).add(f.name)
        for name, (calls, _rel, _line) in self.macros.items():
            for c in calls:
                self.callers.setdefault(c, set()).add(name)
        self.table_refs: dict[str, list[tuple[str, int]]] = {}
        registered_tables = {r.table for r in self.registrations if r.table}
        reg_impls = {r.impl for r in self.registrations}
        for rel, line, idents in self.file_refs:
            for ident in idents & known:
                if ident not in reg_impls:
                    self.table_refs.setdefault(ident, []).append((rel, line))
        self.by_impl: dict[str, list[Registration]] = {}
        for r in self.registrations:
            self.by_impl.setdefault(r.impl, []).append(r)
        del registered_tables

    def has(self, name: str) -> bool:
        return name in self.functions or name in self.macros

    def get_in_file(self, name: str, path: str) -> Optional[NativeFunction]:
        for f in self.functions.get(name) or []:
            if path and (f.file == path or f.file.endswith("/" + path) or path.endswith("/" + f.file)):
                return f
        return None

    def get(self, name: str, file_hint: Optional[str] = None) -> Optional[NativeFunction]:
        cands = self.functions.get(name) or []
        if file_hint:
            for f in cands:
                if f.file.endswith(file_hint) or file_hint.endswith(f.file):
                    return f
        return cands[0] if cands else None

    def source_hash(self) -> str:
        h = hashlib.sha256()
        for name in sorted(self.functions):
            for f in self.functions[name]:
                h.update(f"{f.file}:{f.name}:{len(f.lines)}".encode())
        return h.hexdigest()[:16]


def load_index(root: Path) -> NativeIndex:
    """Parse once per sdist; pickled under .tracelock/cache/native/index/."""
    root = Path(root)
    key = hashlib.sha1(f"{root.resolve()}|{INDEX_VERSION}".encode()).hexdigest()[:16]
    cache = CACHE_DIR / "index" / f"{root.name}-{key}.pkl"
    if cache.exists():
        try:
            return pickle.loads(cache.read_bytes())
        except Exception:
            pass
    index = NativeIndex(root)
    try:
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_bytes(pickle.dumps(index))
    except OSError:
        pass
    return index


# --- fix commit -> changed native functions -------------------------------------------------

def _lang(path: str) -> Optional[str]:
    if path.endswith(RUST_SUFFIXES):
        return "rust"
    if path.endswith(C_SUFFIXES):
        return "c"
    return None


def changed_functions(diff_text: str, prefix_source) -> dict:
    """Map a commit diff's native hunks to the functions they change.

    prefix_source(path) -> pre-fix file text or None. Returns
    {"files": [...], "functions": {name: {"file", "lang", "how"}}, "hunks": [{"path", "functions", "text", "pre_lines"}]}"""
    from .kb import fixdiff  # local: fixdiff imports nothing from here
    out: dict = {"files": [], "functions": {}, "hunks": []}
    for f in fixdiff.parse_diff(diff_text):
        path = f.get("old_path") or f["path"]
        lang = _lang(path)
        if lang is None or f["new_file"] or fixdiff.SKIP_PATH_RE.search(path) or SKIP_DIR_RE.search(path):
            continue
        source = None
        try:
            source = prefix_source(path)
        except Exception:
            source = None
        spans: list[NativeFunction] = []
        if source:
            spans = parse_rust(source, path)[0] if lang == "rust" else parse_c(source, path)[0]
        out["files"].append({"path": path, "lang": lang, "how": "prefix_source" if source else "hunk_header"})

        def at(line: int) -> Optional[str]:
            inner = [s for s in spans if s.start <= line <= s.end]
            return max(inner, key=lambda s: s.start).name if inner else None

        for hunk in f["hunks"]:
            names: set = set()
            for kind, pos, text in hunk["changes"]:
                if not text.strip():
                    continue
                name = at(pos) if kind == "del" else (at(pos) or at(pos - 1))
                if name:
                    names.add(name)
            how = "prefix_source"
            if not names and not spans:
                # No pre-fix file: the hunk header carries git's function context (C/Rust headers are reliable enough
                # to name a candidate; the pinned-version check below still has to find it).
                context = hunk["header"].split("@@")[-1]
                if lang == "rust":
                    hm = re.findall(r"\bfn\s+([A-Za-z_]\w*)", context)
                else:
                    hm = [h for h in re.findall(r"\b([A-Za-z_]\w*)\s*\(", context) if h not in C_KEYWORDS]
                if hm:
                    names.add(hm[0])
                    how = "hunk_header"
            pre_lines = [_norm_line(t) for k, _p, t in hunk["changes"] if k == "del" and _significant(t)]
            pre_lines += [_norm_line(l[1:]) for l in hunk["lines"][1:] if l[:1] == " " and _significant(l[1:])]
            for name in names:
                out["functions"].setdefault(name, {"file": path, "lang": lang, "how": how})
            out["hunks"].append({"path": path, "functions": sorted(names), "text": "\n".join(hunk["lines"][:60]),
                                 "pre_lines": pre_lines[:80]})
    return out


def overlap(pre_lines: list[str], candidate: NativeFunction) -> tuple[int, float]:
    """How many significant pre-fix lines of a hunk appear verbatim (whitespace-normalised) in a function body."""
    if not pre_lines:
        return 0, 0.0
    body = set(candidate.lines)
    hits = sum(1 for l in set(pre_lines) if l in body)
    return hits, hits / len(set(pre_lines))


def equivalents(index: NativeIndex, missing: str, info: dict, hunks: list[dict], min_hits: int = 3, min_ratio: float = 0.5) -> list[tuple[str, int, float]]:
    """Functions of the pinned version whose body contains the pre-fix code of `missing` (renamed or moved)."""
    pre = [l for h in hunks if missing in h["functions"] for l in h["pre_lines"]]
    if not pre:
        return []
    same_file = [f for funcs in index.functions.values() for f in funcs
                 if f.file.endswith(info.get("file", "")) or info.get("file", "").endswith(f.file)]
    pool = same_file or [f for funcs in index.functions.values() for f in funcs if f.lang == info.get("lang")]
    scored = []
    for f in pool:
        hits, ratio = overlap(pre, f)
        if hits >= min_hits and ratio >= min_ratio:
            scored.append((f.name, hits, round(ratio, 2)))
    return sorted(scored, key=lambda s: (-s[2], -s[1], s[0]))[:3]


# --- native call graph -> registrations ------------------------------------------------------

@dataclass
class NativeClosure:
    hops: dict                  # function -> (next function towards the changed code, edge kind)
    registrations: list         # Registration objects whose impl is in the closure
    gaps: list                  # Gap objects

    def chain(self, name: str, limit: int = 12) -> list[str]:
        out, cur = [name], name
        while cur in self.hops and len(out) < limit:
            cur = self.hops[cur][0]
            out.append(cur)
        return out


def closure(index: NativeIndex, targets: list[str]) -> NativeClosure:
    hops: dict[str, tuple[str, str]] = {}
    seen = set(t for t in targets if index.has(t))
    frontier = list(seen)
    gaps: list[Gap] = []
    reg_impls = set(index.by_impl)
    for _depth in range(MAX_NATIVE_DEPTH):
        nxt = []
        for t in frontier:
            for caller in sorted(index.callers.get(t, ())):
                if caller not in seen:
                    seen.add(caller)
                    hops[caller] = (t, "call")
                    nxt.append(caller)
            for user in sorted(index.pointer_users.get(t, ())):
                if user not in seen:
                    seen.add(user)
                    hops[user] = (t, "pointer")
                    nxt.append(user)
                    f = index.get(user)
                    gaps.append(Gap("function_pointer", f"{t} is used as a value (function pointer) in {user}; "
                                    "the call goes through a pointer the analyser cannot follow exactly",
                                    f.file if f else None, f.start if f else None))
            for rel, line in index.table_refs.get(t, []):
                gaps.append(Gap("file_scope_table", f"{t} is stored in a file-scope table; whatever reads the table can call it", rel, line))
        if not nxt:
            break
        frontier = nxt
    else:
        if frontier:
            gaps.append(Gap("depth_limit", f"native call graph walk stopped after {MAX_NATIVE_DEPTH} levels"))
    regs = [r for name in sorted(seen) for r in index.by_impl.get(name, [])]
    # pyo3 classes: a reached method makes its class reachable by construction
    for name in sorted(seen):
        if name in reg_impls:
            continue
        has_callers = bool(index.callers.get(name) or index.pointer_users.get(name))
        if not has_callers:
            f = index.get(name)
            if f is not None and (name.startswith("PyInit_") or f.exposed):
                gaps.append(Gap("import_time", f"the changed code is reached from module initialisation ({name}); "
                                "importing the extension runs it", f.file, f.start))
                continue
            if f is None or (f.lang == "c" and f.static):
                continue  # a static C function nobody calls is dead code; a macro is expanded at its users
            gaps.append(Gap("unregistered_root", f"native function {name} has no caller and no Python registration; it may be "
                            "called through a mechanism the analyser does not model (cffi, ctypes, another extension)",
                            f.file, f.start))
    return NativeClosure(hops=hops, registrations=regs, gaps=gaps)


# --- Python side: who uses the Python-visible names ------------------------------------------

@dataclass
class PythonUse:
    name: str
    qualname: str              # enclosing Python function (lib_graph qualname) or "<module>.<module>"
    file: str
    line: int
    mode: str                  # module | object | direct | name_match | dynamic
    code: str = ""


def _recv_last(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _getattr_pattern(node: ast.AST) -> Optional[str]:
    """Regex for the attribute name of a dynamic getattr; None when it is a literal."""
    if isinstance(node, ast.Constant):
        return None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _getattr_pattern(node.left), _getattr_pattern(node.right)
        lp = re.escape(node.left.value) if isinstance(node.left, ast.Constant) and isinstance(node.left.value, str) else (left or ".*")
        rp = re.escape(node.right.value) if isinstance(node.right, ast.Constant) and isinstance(node.right.value, str) else (right or ".*")
        return lp + rp
    if isinstance(node, ast.JoinedStr):
        parts = []
        for v in node.values:
            parts.append(re.escape(v.value) if isinstance(v, ast.Constant) and isinstance(v.value, str) else ".*")
        return "".join(parts)
    return ".*"


def python_uses(lib_root: Path, import_names: list[str], ext_modules: set, regs: list, model=None) -> tuple[list, list, dict, list]:
    """Uses of Python-visible native names inside the pinned package's own Python code.

    Returns (uses, gaps, reexports {public dotted name: native py name}, ambiguous uses). An ambiguous use is a
    common method name on an unknown receiver: it is a gap, and only an LLM candidate whose call path the
    verifier proves can turn it into a wrapper."""
    from . import app_graph, lib_graph  # local imports: lib_graph -> app_graph
    root = lib_graph._source_root(Path(lib_root))
    model = model or lib_graph.load_model(root)
    spans: dict[str, list[tuple[int, int, str]]] = {}
    for q, info in model.functions.items():
        if not info.is_class:
            spans.setdefault(info.file, []).append((info.line, info.end_line, q))

    def enclosing(rel: str, module: str, line: int) -> str:
        inner = [s for s in spans.get(rel, []) if s[0] <= line <= s[1]]
        return max(inner, key=lambda s: s[0])[2] if inner else f"{module}.<module>"

    files = []
    for module, rel in model.modules.items():
        if module.split(".")[0] not in import_names:
            continue
        try:
            source = (root / rel).read_text(encoding="utf-8", errors="replace")
            files.append((module, rel, source, ast.parse(source)))
        except (SyntaxError, OSError):
            continue

    reg_names = {r.py_name for r in regs}
    reg_modules: dict[str, set] = {}
    for r in regs:
        reg_modules.setdefault(r.py_name, set()).add(r.module)

    def fits(name: str, modules: Optional[set]) -> bool:
        """A receiver known to come from extension module M can only reach M's registrations."""
        if not modules:
            return True
        mods = reg_modules.get(name, {None})
        return None in mods or bool(mods & modules)

    ext_segments = set(ext_modules) | {m.rsplit(".", 1)[-1] for m in ext_modules}
    # Module aliases are per file (`core` is _imaging in Image.py but _imagingcms in ImageCms.py);
    # `X.core` from another file uses the union over all files, which can only add matches.
    file_aliases: dict[str, dict[str, set]] = {}
    direct: dict[str, str] = {}
    for module, rel, _src, tree in files:
        local = file_aliases.setdefault(rel, {})
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    segs = set(a.name.split(".")) & ext_segments
                    if segs:
                        local.setdefault(a.asname or a.name.split(".")[0], set()).update(segs)
            elif isinstance(node, ast.ImportFrom):
                mod_segs = set((node.module or "").split(".")) & ext_segments
                for a in node.names:
                    if a.name in ext_segments:
                        local.setdefault(a.asname or a.name, set()).add(a.name)
                    elif mod_segs:
                        if a.name in reg_names:
                            direct[a.asname or a.name] = a.name
                        else:
                            local.setdefault(a.asname or a.name, set()).update(mod_segs)   # `from ._rust import x509 as rust_x509`
        for _ in range(2):   # `core = _imagingcms`
            for node in ast.walk(tree):
                if isinstance(node, ast.Assign) and isinstance(node.value, ast.Name) and node.value.id in local:
                    for t in node.targets:
                        if isinstance(t, ast.Name):
                            local.setdefault(t.id, set()).update(local[node.value.id])
    any_alias: dict[str, set] = {}
    for local in file_aliases.values():
        for name, mods in local.items():
            any_alias.setdefault(name, set()).update(mods)

    def receiver(node: ast.AST, rel: str) -> tuple[Optional[str], Optional[set]]:
        """('module' | 'object' | None, extension modules) for the receiver expression of an attribute use."""
        local = file_aliases.get(rel, {})
        if isinstance(node, ast.Name):
            if node.id in local:
                return "module", local[node.id]
            if node.id in objects:
                return "object", objects[node.id]
            return None, None
        if isinstance(node, ast.Attribute):
            if node.attr in any_alias:
                return "module", any_alias[node.attr]
            if node.attr in objects:
                return "object", objects[node.attr]
        return None, None

    # Names bound to native objects: `self.im = core.new(...)`, `self.font = core.getfont(...)`, with their module.
    objects: dict[str, set] = {}
    for _ in range(3):
        before = sum(len(v) for v in objects.values())
        for module, rel, _src, tree in files:
            for node in ast.walk(tree):
                if isinstance(node, (ast.Assign, ast.AnnAssign)) and isinstance(node.value, ast.Call) \
                        and isinstance(node.value.func, ast.Attribute):
                    _kind, mods = receiver(node.value.func.value, rel)
                    if mods is not None:
                        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                        for t in targets:
                            last = _recv_last(t)
                            if last and last not in any_alias:
                                objects.setdefault(last, set()).update(mods)
        if sum(len(v) for v in objects.values()) == before:
            break

    uses: list[PythonUse] = []
    ambiguous: list[PythonUse] = []
    gaps: list[Gap] = []
    reexports: dict[str, str] = {}
    for module, rel, src, tree in files:
        lines = src.splitlines()
        code = lambda ln: lines[ln - 1].strip() if 0 < ln <= len(lines) else ""
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr in reg_names:
                mode, mods = receiver(node.value, rel)
                if mode:
                    pass
                elif node.attr not in COMMON_METHODS:
                    mode, mods = "name_match", None
                else:
                    gaps.append(Gap("ambiguous_name", f".{node.attr} on an unknown receiver may be the native '{node.attr}'", rel, node.lineno))
                    ambiguous.append(PythonUse(node.attr, enclosing(rel, module, node.lineno), rel, node.lineno, "ambiguous", code(node.lineno)))
                    continue
                if fits(node.attr, mods):
                    uses.append(PythonUse(node.attr, enclosing(rel, module, node.lineno), rel, node.lineno, mode, code(node.lineno)))
            elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id in direct:
                uses.append(PythonUse(direct[node.id], enclosing(rel, module, node.lineno), rel, node.lineno, "direct", code(node.lineno)))
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "getattr" and len(node.args) >= 2:
                _kind, mods = receiver(node.args[0], rel)
                pattern = _getattr_pattern(node.args[1])
                if pattern is None:
                    lit = node.args[1].value if isinstance(node.args[1], ast.Constant) else None
                    if isinstance(lit, str) and lit in reg_names:
                        if mods is not None or lit not in COMMON_METHODS:
                            if fits(lit, mods):
                                uses.append(PythonUse(lit, enclosing(rel, module, node.lineno), rel, node.lineno,
                                                      "module" if mods is not None else "name_match", code(node.lineno)))
                        else:
                            gaps.append(Gap("ambiguous_name", f'getattr(..., "{lit}") on an unknown receiver may be the native one', rel, node.lineno))
                    continue
                matched = sorted(n for n in reg_names if re.fullmatch(pattern, n) and fits(n, mods))
                if mods is not None:
                    for n in matched:
                        uses.append(PythonUse(n, enclosing(rel, module, node.lineno), rel, node.lineno, "dynamic", code(node.lineno)))
                    if pattern == ".*" and matched:
                        gaps.append(Gap("dynamic_getattr", "getattr on a native object with a fully dynamic name", rel, node.lineno))
                elif matched and pattern != ".*":
                    gaps.append(Gap("dynamic_getattr", f"getattr with name pattern {pattern} on an unknown receiver could reach {matched[0]}", rel, node.lineno))
        # `PolicyBuilder = rust_x509.PolicyBuilder` at module level: the public name *is* the native object
        for node in tree.body:
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Attribute) and node.value.attr in reg_names \
                    and receiver(node.value.value, rel)[0] == "module":
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        reexports[f"{module}.{t.id}"] = node.value.attr
    for u in uses:
        if u.qualname.endswith(".<module>"):
            gaps.append(Gap("import_time", f"native '{u.name}' is used at module level in {u.file}; importing the module runs it", u.file, u.line))
    return uses, gaps, reexports, ambiguous


# --- the whole mapping ----------------------------------------------------------------------

@dataclass
class NativeMapping:
    changed: dict = field(default_factory=dict)          # changed native function -> info (+ "pinned": bool)
    equivalents: dict = field(default_factory=dict)      # missing function -> [(pinned name, hits, ratio)]
    registrations: list = field(default_factory=list)    # reached Registration objects
    uses: list = field(default_factory=list)             # PythonUse objects
    wrappers: dict = field(default_factory=dict)         # Python qualname -> [native py names it uses]
    ambiguous: dict = field(default_factory=dict)        # Python qualname -> [common names used on unknown receivers]
    entry_symbols: list = field(default_factory=list)    # public names that are native objects themselves
    chains: dict = field(default_factory=dict)           # Python wrapper -> native chain (display)
    gaps: list = field(default_factory=list)             # Gap objects
    closure: Optional[NativeClosure] = None

    @property
    def complete(self) -> bool:
        return bool(self.wrappers or self.entry_symbols) and not self.gaps

    def summary(self) -> dict:
        return {
            "changed_functions": [{"name": k, **{x: v[x] for x in ("file", "lang", "how", "pinned") if x in v}} for k, v in sorted(self.changed.items())],
            "equivalents": {k: [{"name": n, "matching_lines": h, "ratio": r} for n, h, r in v] for k, v in self.equivalents.items()},
            "registrations": [{"python_name": r.py_name, "native": r.impl, "kind": r.kind, "owner": r.owner, "file": r.file, "line": r.line}
                              for r in self.registrations[:20]],
            "python_wrappers": [{"symbol": q, "uses": sorted(set(n))} for q, n in sorted(self.wrappers.items())][:30],
            "entry_symbols": self.entry_symbols[:20],
            "complete": self.complete,
            "gaps": [g.to_dict() for g in self.gaps[:12]],
            "gap_count": len(self.gaps),
        }


def map_to_python(index: NativeIndex, changes: dict, lib_src: Optional[Path], import_names: list[str]) -> NativeMapping:
    """Deterministic mapping from changed native functions (in the pinned index) to Python wrappers."""
    result = NativeMapping()
    targets: list[str] = []
    for name, info in changes.get("functions", {}).items():
        # Present means: same name in the same file of the pinned version (a same-named function elsewhere is
        # other code), or a macro of that name. Moved/renamed code is only accepted through equivalents().
        present = name in index.macros or index.get_in_file(name, info.get("file", "")) is not None
        result.changed[name] = {**info, "pinned": present}
        if present:
            targets.append(name)
            continue
        eq = equivalents(index, name, info, changes.get("hunks", []))
        if eq:
            result.equivalents[name] = eq
            targets.extend(n for n, _h, _r in eq)
        else:
            result.gaps.append(Gap("missing_in_pinned", f"{name} (changed by the fix) does not exist in the pinned version's "
                                   "source and no function there contains its pre-fix code", info.get("file")))
    if not targets:
        return result
    clo = closure(index, targets)
    result.closure = clo
    result.gaps.extend(clo.gaps)
    result.registrations = clo.registrations
    if not clo.registrations:
        result.gaps.append(Gap("no_registration", "no Python-visible registration (PyMethodDef / PyO3) reaches the changed native code"))
        return result
    if lib_src is None:
        result.gaps.append(Gap("no_python_use", "the pinned package's Python source is unavailable, so its wrappers cannot be found"))
        return result
    # A reached PyO3 method or constructor makes its class reachable: Python code reaches methods through it.
    owners = {r.owner for r in clo.registrations if r.kind in ("pyo3_method", "pyo3_new")}
    clo.registrations = clo.registrations + [r for r in index.registrations
                                             if r.kind == "pyo3_class" and r.py_name in owners and r not in clo.registrations]
    result.registrations = clo.registrations
    reg_names = {r.py_name for r in clo.registrations}
    uses, py_gaps, reexports, ambiguous = python_uses(lib_src, import_names, index.ext_modules | {r.owner for r in clo.registrations if r.owner}, clo.registrations)
    result.uses = uses
    result.gaps.extend(py_gaps)
    for u in ambiguous:
        if not u.qualname.endswith(".<module>"):
            result.ambiguous.setdefault(u.qualname, []).append(u.name)
    by_name: dict[str, list[Registration]] = {}
    for r in clo.registrations:
        by_name.setdefault(r.py_name, []).append(r)
    for u in uses:
        if u.qualname.endswith(".<module>"):
            continue
        result.wrappers.setdefault(u.qualname, []).append(u.name)
        reg = by_name[u.name][0]
        chain = [f"{reg.file}::{reg.impl}"] + [f"native::{n}" for n in clo.chain(reg.impl)[1:]]
        result.chains.setdefault(u.qualname, chain)
    for public, py_name in sorted(reexports.items()):
        result.entry_symbols.append(public)
        reg = by_name[py_name][0]
        result.chains.setdefault(public, [f"{reg.file}::{reg.impl}"] + [f"native::{n}" for n in clo.chain(reg.impl)[1:]])
        # methods of a re-exported PyO3 class are reached through instances of it
        for r in clo.registrations:
            if r.kind in ("pyo3_method", "pyo3_new") and r.owner == py_name:
                sym = public if r.kind == "pyo3_new" else f"{public}.{r.py_name}"
                if sym not in result.entry_symbols:
                    result.entry_symbols.append(sym)
                    result.chains.setdefault(sym, [f"{r.file}::{r.impl}"] + [f"native::{n}" for n in clo.chain(r.impl)[1:]])
    if not result.wrappers and not result.entry_symbols:
        result.gaps.append(Gap("no_python_use", "registrations reach the changed code, but no Python function of the package "
                               "uses them in a way the analyser can follow: " + ", ".join(sorted(reg_names)[:6])))
    return result


def snippet(index: NativeIndex, name: str, max_lines: int = 40) -> Optional[tuple[str, int, str]]:
    """(path, start line, numbered source) of a native function in the pinned sdist, for prompts."""
    f = index.get(name)
    if f is None:
        return None
    try:
        lines = (index.root / f.file).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    body = lines[f.start - 1:min(f.end, f.start - 1 + max_lines)]
    return f.file, f.start, "\n".join(f"{f.start + i}: {l}" for i, l in enumerate(body))


def to_json(obj) -> str:
    return json.dumps(obj, indent=1, sort_keys=True, default=lambda o: sorted(o) if isinstance(o, set) else str(o))
