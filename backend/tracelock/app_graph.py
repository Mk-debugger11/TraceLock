"""App analyzer: AST model of the scanned application. OWNER: Kartik.

Scaffold status: WORKING MINIMUM. Resolves `import x [as y]`, `from x import y [as z]`,
attribute chains, constructor-typed locals (`s = requests.Session(); s.get()`), `self.`
inside classes, annotated parameters, literal getattr, decorators, dynamic markers,
string refs (incl. template filters), entry-point tagging, and a caller->callee edge list.

TODO (Kartik, BRIEF_KARTIK.md): relative-import resolution inside the app, base-class
method lookup, `with`/`for` target typing, return-type propagation for app functions,
`from pkg import *` symbol expansion using the library source, better template scanning,
conditional/try-import tracking, and the `trace`-mode hooks.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

SKIP_DIRS = {".git", ".venv", "venv", "env", "__pycache__", "node_modules", "dist", "build", ".tracelock", "site-packages"}
TEMPLATE_SUFFIXES = {".html", ".htm", ".jinja", ".jinja2", ".j2", ".txt", ".yaml", ".yml", ".toml", ".cfg", ".ini", ".json"}
ROUTE_DECORATORS = {"route", "get", "post", "put", "delete", "patch", "api_route", "websocket",
                    "task", "shared_task", "command", "on_event", "middleware", "exception_handler"}
DYNAMIC_CALLS = {"getattr", "setattr", "eval", "exec", "compile", "__import__",
                 "importlib.import_module", "importlib.__import__", "globals", "locals", "vars",
                 "pickle.loads", "pickle.load", "marshal.loads", "shelve.open", "dill.loads", "jsonpickle.decode"}
BUILTIN_NAMES = {"getattr", "setattr", "eval", "exec", "compile", "__import__", "globals", "locals", "vars"}
DESERIALIZERS = ("pickle", "marshal", "shelve", "dill", "jsonpickle")
_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*$")
_FILTER_RE = re.compile(r"\|\s*([A-Za-z_][A-Za-z0-9_]*)")


@dataclass
class FunctionInfo:
    qualname: str
    file: str
    line: int
    end_line: int
    entry_kind: Optional[str] = None       # main | module | route | test | None
    decorators: list[str] = field(default_factory=list)
    is_class: bool = False


@dataclass
class CallSite:
    caller: str                            # qualname of the enclosing function (or "<mod>.<module>")
    callee: Optional[str]                  # resolved dotted name, or None if unresolved
    last_name: str                         # last attribute / name of the call target
    file: str
    line: int
    code: str
    kwargs: dict = field(default_factory=dict)   # kwarg name -> source text of the value
    receiver: Optional[str] = None         # resolved receiver for attribute calls


@dataclass
class DynamicMarker:
    kind: str                              # getattr | eval | exec | import | deserialize | sys_modules | globals
    file: str
    line: int
    detail: str


@dataclass
class StringRef:
    file: str
    line: int
    value: str


@dataclass
class AppModel:
    root: str
    modules: dict = field(default_factory=dict)            # module name -> relative file
    functions: dict = field(default_factory=dict)          # qualname -> FunctionInfo
    calls: list = field(default_factory=list)              # list[CallSite]
    dynamic: list = field(default_factory=list)            # list[DynamicMarker]
    strings: list = field(default_factory=list)            # list[StringRef]
    star_imports: list = field(default_factory=list)       # (module imported from, file, line)
    imported_top_levels: dict = field(default_factory=dict)  # top-level module -> [(file, line)]
    warnings: list = field(default_factory=list)

    def callers_of(self, qualname: str) -> list:
        return [c for c in self.calls if c.callee == qualname and c.caller != qualname]

    def imports_any(self, top_levels: list[str]) -> list:
        hits = []
        for name in top_levels:
            hits.extend(self.imported_top_levels.get(name, []))
        return hits


def _module_name(root: Path, file: Path) -> str:
    rel = file.relative_to(root).with_suffix("")
    parts = list(rel.parts)
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts) or file.stem


class _ModuleAnalyzer:
    def __init__(self, model: AppModel, module: str, rel_file: str, source: str):
        self.model, self.module, self.file = model, module, rel_file
        self.lines = source.splitlines()

    # --- helpers -------------------------------------------------------------
    def code_at(self, line: int) -> str:
        return self.lines[line - 1].strip() if 0 < line <= len(self.lines) else ""

    def resolve(self, node: ast.AST, scope: dict) -> Optional[str]:
        """Dotted name for an expression, using the scope's bindings. None if unknown."""
        if isinstance(node, ast.Name):
            bound = scope.get(node.id)
            if bound is None and node.id in BUILTIN_NAMES:
                return node.id
            return bound
        if isinstance(node, ast.Attribute):
            base = self.resolve(node.value, scope)
            return f"{base}.{node.attr}" if base else None
        if isinstance(node, ast.Call):
            # getattr(x, "name") used as a value, or a constructor call used as a value
            if isinstance(node.func, ast.Name) and node.func.id == "getattr":
                if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str):
                    base = self.resolve(node.args[0], scope)
                    return f"{base}.{node.args[1].value}" if base else None
                return None  # dynamic getattr: value unknown (the call itself is recorded as a marker)
            return self.resolve(node.func, scope)
        return None

    def add_import_hit(self, top: str, line: int) -> None:
        self.model.imported_top_levels.setdefault(top, []).append((self.file, line))

    # --- walking -------------------------------------------------------------
    def analyze(self, tree: ast.Module) -> None:
        scope: dict = {}
        module_fn = f"{self.module}.<module>"
        has_main_block = any(
            isinstance(n, ast.If) and isinstance(n.test, ast.Compare)
            and isinstance(n.test.left, ast.Name) and n.test.left.id == "__name__"
            for n in tree.body
        )
        self.model.functions[module_fn] = FunctionInfo(module_fn, self.file, 1, len(self.lines),
                                                       entry_kind="main" if has_main_block else "module")
        self.visit_block(tree.body, scope, self.module, module_fn, class_qual=None)

    def visit_block(self, body: list, scope: dict, prefix: str, caller: str, class_qual: Optional[str]) -> None:
        for node in body:
            self.visit_stmt(node, scope, prefix, caller, class_qual)

    def visit_stmt(self, node: ast.AST, scope: dict, prefix: str, caller: str, class_qual: Optional[str]) -> None:
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                scope[alias.asname or top] = alias.name if alias.asname else top
                self.add_import_hit(top, node.lineno)
            return
        if isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if node.level:  # relative import: resolve against the current module path
                base_parts = self.module.split(".")
                base_parts = base_parts[: max(len(base_parts) - node.level, 0)]
                mod = ".".join(p for p in [*base_parts, mod] if p)
            else:
                self.add_import_hit(mod.split(".")[0], node.lineno)
            for alias in node.names:
                if alias.name == "*":
                    self.model.star_imports.append((mod, self.file, node.lineno))
                    continue
                scope[alias.asname or alias.name] = f"{mod}.{alias.name}" if mod else alias.name
            return
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self.visit_function(node, scope, prefix, class_qual)
            return
        if isinstance(node, ast.ClassDef):
            qual = f"{prefix}.{node.name}"
            scope[node.name] = qual
            self.model.functions[qual] = FunctionInfo(qual, self.file, node.lineno, node.end_lineno or node.lineno, is_class=True)
            inner = dict(scope)
            self.visit_block(node.body, inner, qual, caller, class_qual=qual)
            return
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = node.value
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            resolved = self.resolve(value, scope) if value is not None else None
            if resolved is None and isinstance(node, ast.AnnAssign):
                resolved = self.resolve(node.annotation, scope)
            if resolved:
                for t in targets:
                    if isinstance(t, ast.Name):
                        scope[t.id] = resolved
                    elif isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name) and t.value.id == "self" and class_qual:
                        scope[f"self.{t.attr}"] = resolved
        # Generic: scan every expression in this statement for calls, markers and strings,
        # then recurse into nested statement bodies with the same scope.
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.stmt):
                self.visit_stmt(child, scope, prefix, caller, class_qual)
            elif isinstance(child, ast.excepthandler):
                if child.type is not None:
                    self.visit_expr(child.type, scope, caller)
                self.visit_block(child.body, scope, prefix, caller, class_qual)
            elif hasattr(ast, "match_case") and isinstance(child, ast.match_case):
                self.visit_block(child.body, scope, prefix, caller, class_qual)
            else:
                self.visit_expr(child, scope, caller)

    def visit_function(self, node: ast.AST, scope: dict, prefix: str, class_qual: Optional[str]) -> None:
        qual = f"{prefix}.{node.name}"
        scope[node.name] = qual  # later calls to this function by bare name resolve to it
        decorators = []
        entry_kind = None
        for dec in node.decorator_list:
            target = dec.func if isinstance(dec, ast.Call) else dec
            resolved = self.resolve(target, scope)
            last = target.attr if isinstance(target, ast.Attribute) else getattr(target, "id", "")
            decorators.append(resolved or last)
            if last in ROUTE_DECORATORS:
                entry_kind = "route"
            self.model.calls.append(CallSite(caller=qual, callee=resolved, last_name=last, file=self.file,
                                             line=dec.lineno, code=self.code_at(dec.lineno), receiver=None))
        if node.name == "main" and class_qual is None:
            entry_kind = entry_kind or "main"
        if node.name.startswith("test_"):
            entry_kind = entry_kind or "test"
        self.model.functions[qual] = FunctionInfo(qual, self.file, node.lineno, node.end_lineno or node.lineno,
                                                  entry_kind=entry_kind, decorators=decorators)
        inner = dict(scope)
        args = node.args
        all_args = [*args.posonlyargs, *args.args, *args.kwonlyargs]
        if args.vararg:
            all_args.append(args.vararg)
        if args.kwarg:
            all_args.append(args.kwarg)
        for i, a in enumerate(all_args):
            if class_qual and i == 0 and a.arg in ("self", "cls"):
                inner[a.arg] = class_qual
            elif a.annotation is not None:
                resolved = self.resolve(a.annotation, inner)
                if resolved:
                    inner[a.arg] = resolved
        self.visit_block(node.body, inner, qual, qual, class_qual=class_qual)

    def visit_expr(self, node: ast.AST, scope: dict, caller: str) -> None:
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call):
                self.record_call(sub, scope, caller)
            elif isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                if 2 < len(sub.value) < 80 and _IDENT_RE.match(sub.value):
                    self.model.strings.append(StringRef(self.file, getattr(sub, "lineno", 0), sub.value))
            elif isinstance(sub, ast.Subscript):
                base = self.resolve(sub.value, scope)
                if base in ("sys.modules",) or (isinstance(sub.value, ast.Call) and self.resolve(sub.value.func, scope) in ("globals", "locals", "vars")):
                    self.model.dynamic.append(DynamicMarker("globals" if base != "sys.modules" else "sys_modules",
                                                            self.file, sub.lineno, self.code_at(sub.lineno)))
            elif isinstance(sub, (ast.Lambda,)):
                pass

    def record_call(self, call: ast.Call, scope: dict, caller: str) -> None:
        func = call.func
        resolved = self.resolve(func, scope)
        if isinstance(func, ast.Attribute):
            last, receiver = func.attr, self.resolve(func.value, scope)
            if receiver is None and isinstance(func.value, ast.Attribute) and isinstance(func.value.value, ast.Name) \
                    and func.value.value.id == "self":
                receiver = scope.get(f"self.{func.value.attr}")
                resolved = f"{receiver}.{last}" if receiver else None
        elif isinstance(func, ast.Name):
            last, receiver = func.id, None
            if resolved is None and func.id in ("getattr", "setattr", "eval", "exec", "compile", "__import__", "globals", "locals", "vars"):
                resolved = func.id  # builtins
        elif isinstance(func, ast.Call):  # getattr(x, "name")(...) style
            last = "<call>"
            receiver = None
            resolved = self.resolve(func, scope)
            if resolved:
                last = resolved.rsplit(".", 1)[-1]
        else:
            last, receiver = "<expr>", None
        kwargs = {}
        for kw in call.keywords:
            if kw.arg:
                try:
                    kwargs[kw.arg] = ast.unparse(kw.value)
                except Exception:
                    kwargs[kw.arg] = "?"
        # dynamic-feature markers
        if resolved in DYNAMIC_CALLS or last in ("getattr", "setattr", "eval", "exec", "__import__"):
            name = resolved or last
            literal_attr = name in ("getattr", "setattr") and len(call.args) >= 2 and isinstance(call.args[1], ast.Constant)
            if name == "getattr" and literal_attr:
                base = self.resolve(call.args[0], scope)
                attr = call.args[1].value
                resolved = f"{base}.{attr}" if base else None
                last = str(attr)
                receiver = base
            else:
                if any(name.startswith(d + ".") for d in DESERIALIZERS):
                    kind = "deserialize"
                else:
                    kind = {"eval": "eval", "exec": "exec", "compile": "exec", "__import__": "import",
                            "importlib.import_module": "import", "importlib.__import__": "import",
                            "globals": "globals", "locals": "globals", "vars": "globals"}.get(name, "getattr")
                self.model.dynamic.append(DynamicMarker(kind, self.file, call.lineno, self.code_at(call.lineno)))
                return
        self.model.calls.append(CallSite(caller=caller, callee=resolved, last_name=last, file=self.file,
                                         line=call.lineno, code=self.code_at(call.lineno), kwargs=kwargs, receiver=receiver))


def build(root: Path) -> AppModel:
    """Parse every .py file under root (and scan templates/config for symbol strings)."""
    root = Path(root).resolve()
    model = AppModel(root=str(root))
    for path in sorted(root.rglob("*")):
        if any(part in SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        if path.is_dir() or path.is_symlink():
            continue
        rel = path.relative_to(root).as_posix()
        if path.suffix == ".py":
            try:
                source = path.read_text(encoding="utf-8", errors="replace")
                tree = ast.parse(source)
            except SyntaxError as exc:
                model.warnings.append(f"{rel}: syntax error, skipped ({exc.msg} line {exc.lineno})")
                continue
            module = _module_name(root, path)
            model.modules[module] = rel
            _ModuleAnalyzer(model, module, rel, source).analyze(tree)
        elif path.suffix.lower() in TEMPLATE_SUFFIXES and path.stat().st_size < 2_000_000:
            try:
                for i, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                    for m in _FILTER_RE.finditer(line):
                        model.strings.append(StringRef(rel, i, m.group(1)))
                    for tok in re.findall(r"[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_.]*", line):
                        if len(tok) < 80:
                            model.strings.append(StringRef(rel, i, tok))
            except OSError:
                pass
    return model
