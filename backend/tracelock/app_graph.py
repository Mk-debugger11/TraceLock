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
# Calls that inspect their arguments without calling them: `isinstance(x, yaml.FullLoader)` is not a use.
NON_USE_CALLS = {"isinstance", "issubclass", "hasattr", "callable", "id", "type"}
UNKNOWN = "?"            # an attribute assigned a value we could not resolve
DEFERRED = "?call:"      # an attribute assigned the result of a module function defined further down
_AMBIGUOUS = object()
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
    bases: list[str] = field(default_factory=list)   # classes only: resolved base-class dotted names


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
    kwargs_resolved: dict = field(default_factory=dict)  # kwarg name -> dotted name the value resolves to (or None)


@dataclass
class Reference:
    """A symbol used as a value instead of called: `map(yaml.load, xs)`, `key=yaml.unsafe_load`, `loader = yaml.load`.
    Whoever receives the value can call it, so the verdict engine treats a reference like a call."""
    caller: str                            # qualname of the enclosing function (or "<mod>.<module>")
    target: str                            # resolved dotted name of the referenced symbol
    file: str
    line: int
    code: str
    arg_of: Optional[str] = None           # resolved callee when the value is passed straight to a call
    kwarg: Optional[str] = None            # the keyword it is passed as, if any


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
    returns: dict = field(default_factory=dict)            # function qualname -> dotted name its last `return` evaluates to
    references: list = field(default_factory=list)         # list[Reference]
    exports: dict = field(default_factory=dict)            # app module -> {top-level name: dotted name it is bound to}
    attributes: dict = field(default_factory=dict)         # app class -> {attribute: set of dotted values (or UNKNOWN)}
    warnings: list = field(default_factory=list)
    canonical_cache: dict = field(default_factory=dict, repr=False, compare=False)  # pass 2 only; emptied by build()

    def callers_of(self, qualname: str) -> list:
        return [c for c in self.calls if c.callee == qualname and c.caller != qualname]

    def referrers_of(self, qualname: str) -> list:
        """Functions that pass `qualname` around as a value (a callback registered, stored or returned)."""
        return [r for r in self.references if r.target == qualname and r.caller != qualname]

    def method_in_bases(self, class_qual: str, method: str, _depth: int = 0) -> Optional[str]:
        """Resolve `class_qual.method` through the class's bases. Returns the first app method found,
        or `<external base>.method` when the chain leaves the app (e.g. a subclass of yaml.SafeLoader)."""
        info = self.functions.get(class_qual)
        if info is None or not info.is_class or _depth > 8:
            return None
        for base in info.bases:
            cand = f"{base}.{method}"
            if cand in self.functions:
                return cand
            if base in self.functions:
                found = self.method_in_bases(base, method, _depth + 1)
                if found:
                    return found
            else:
                return cand  # external base class: keep the dotted name rooted at the library
        return None

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
    def __init__(self, model: AppModel, module: str, rel_file: str, source: str, collect_tables: bool = False):
        self.model, self.module, self.file = model, module, rel_file
        self.lines = source.splitlines()
        self.collect_tables = collect_tables   # pass 1 fills model.exports / model.attributes; pass 2 reads them

    # --- helpers -------------------------------------------------------------
    def code_at(self, line: int) -> str:
        return self.lines[line - 1].strip() if 0 < line <= len(self.lines) else ""

    def canonical(self, dotted: Optional[str]) -> Optional[str]:
        """Follow app-level indirections to the real symbol: re-exports (`helpers.load` -> `yaml.load` when
        helpers.py does `from yaml import load`) and class attributes (`app.Cfg.parser.load` -> `yaml.load`
        when a method does `self.parser = yaml`). An attribute with several or unknown values is None."""
        if not self.collect_tables and dotted is not None:  # pass 2: the tables are final, so memoise
            cache = self.model.canonical_cache
            if dotted not in cache:
                cache[dotted] = self._canonical(dotted)
            return cache[dotted]
        return self._canonical(dotted)

    def _canonical(self, dotted: Optional[str]) -> Optional[str]:
        for _ in range(8):
            if not dotted or "." not in dotted:
                return dotted
            step = self._canonical_step(dotted)
            if step is _AMBIGUOUS:
                return None
            if step is None or step == dotted:
                return dotted
            dotted = step
        return dotted

    def _canonical_step(self, dotted: str):
        parts = dotted.split(".")
        for i in range(len(parts) - 1, 0, -1):
            owner, name, rest = ".".join(parts[:i]), parts[i], parts[i + 1:]
            values = self.model.attributes.get(owner, {}).get(name)
            if values:
                if len(values) > 1 or UNKNOWN in values:
                    return _AMBIGUOUS
                return ".".join([next(iter(values)), *rest])
            if owner in self.model.modules:
                target = self.model.exports.get(owner, {}).get(name)
                if target and target != f"{owner}.{name}":
                    return ".".join([target, *rest])
                return None
        return None

    def note_attribute(self, class_qual: str, name: str, value: Optional[str], node: Optional[ast.AST], scope: dict) -> None:
        if not self.collect_tables:
            return
        if value is None and isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id not in scope:
            # `self.session = make_session()` with `def make_session` further down: settled by _type_tables
            value = f"{DEFERRED}{self.module}.{node.func.id}"
        self.model.attributes.setdefault(class_qual, {}).setdefault(name, set()).add(value or UNKNOWN)

    def resolve(self, node: ast.AST, scope: dict) -> Optional[str]:
        """Dotted name for an expression, using the scope's bindings. None if unknown."""
        if isinstance(node, ast.Name):
            bound = scope.get(node.id)
            if bound is None and node.id in BUILTIN_NAMES:
                return node.id
            return self.canonical(bound)
        if isinstance(node, ast.Attribute):
            base = self.resolve(node.value, scope)
            return self.canonical(f"{base}.{node.attr}") if base else None
        if isinstance(node, ast.Call):
            # getattr(x, "name") used as a value, or a constructor call used as a value
            if isinstance(node.func, ast.Name) and node.func.id == "getattr":
                if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str):
                    base = self.resolve(node.args[0], scope)
                    return f"{base}.{node.args[1].value}" if base else None
                return None  # dynamic getattr: value unknown (the call itself is recorded as a marker)
            target = self.resolve(node.func, scope)
            if not target:
                return None
            # x = make_parser()  ->  x is the class make_parser() returns (one level, collected in pass 1).
            return _returned_class(self.model, target)
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
        if self.collect_tables:  # what `from <this module> import name` gives other app modules
            self.model.exports[self.module] = {k: v for k, v in scope.items()
                                               if not k.startswith("self.") and v != f"{self.module}.{k}"}

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
            bases = []
            for b in node.bases:
                resolved = self.resolve(b, scope)
                bases.append(resolved or (b.attr if isinstance(b, ast.Attribute) else getattr(b, "id", "object")))
            self.model.functions[qual] = FunctionInfo(qual, self.file, node.lineno, node.end_lineno or node.lineno,
                                                      is_class=True, bases=bases)
            for b in node.bases:
                self.visit_expr(b, scope, caller)
            inner = dict(scope)
            self.visit_block(node.body, inner, qual, caller, class_qual=qual)
            return
        if isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                self.visit_expr(item.context_expr, scope, caller)
                if isinstance(item.optional_vars, ast.Name):
                    resolved = self.resolve(item.context_expr, scope)
                    if resolved:
                        scope[item.optional_vars.id] = resolved
            self.visit_block(node.body, scope, prefix, caller, class_qual)
            return
        if isinstance(node, ast.Return) and node.value is not None and caller:
            resolved = self.resolve(node.value, scope)
            if resolved and not resolved.startswith(caller + "."):
                self.model.returns[caller] = resolved  # last return wins; used by pass 2
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = node.value
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            resolved = self.resolve(value, scope) if value is not None else None
            if resolved is None and isinstance(node, ast.AnnAssign):
                resolved = self.resolve(node.annotation, scope)
            for t in targets:
                if isinstance(t, ast.Name):
                    if resolved:
                        scope[t.id] = resolved
                    if class_qual and prefix == class_qual:  # class body: `loader = yaml.load`
                        self.note_attribute(class_qual, t.id, resolved, value, scope)
                elif isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name) and t.value.id == "self" and class_qual:
                    if resolved:
                        scope[f"self.{t.attr}"] = resolved
                    self.note_attribute(class_qual, t.attr, resolved, value, scope)  # visible to every method of the class
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
                # `x: yaml.FullLoader = None` names a type, it does not use the symbol
                annotation = isinstance(node, ast.AnnAssign) and child is node.annotation
                self.visit_expr(child, scope, caller, references=not annotation)

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
        # `def parse(s, fn=yaml.load)` and `@retry(on=handler)`: evaluated in the enclosing scope, used by this function
        decorator_args = [a for d in node.decorator_list if isinstance(d, ast.Call) for a in (*d.args, *(k.value for k in d.keywords))]
        for expr in (*args.defaults, *(d for d in args.kw_defaults if d is not None), *decorator_args):
            self.visit_expr(expr, scope, qual)
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

    def visit_expr(self, node: ast.AST, scope: dict, caller: str, references: bool = True) -> None:
        # ast.walk is breadth-first, so a parent is seen before its children: `skip` and `context` are
        # filled in time. Skipped: call targets (`yaml.load` in `yaml.load(x)` is a call, not a value),
        # the inner links of attribute chains, and the arguments of isinstance()/issubclass()/...
        skip: set = set()
        context: dict = {}   # id(argument node) -> (resolved callee it is passed to, keyword or None)
        references = references and not self.collect_tables  # pass 1 output is discarded except its tables
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call):
                skip.add(id(sub.func))
                if references:
                    if isinstance(sub.func, ast.Name) and sub.func.id in NON_USE_CALLS:
                        skip.update(id(a) for a in sub.args)
                    callee = self.resolve(sub.func, scope)
                    for a in sub.args:
                        context[id(a)] = (callee, None)
                    for kw in sub.keywords:
                        context[id(kw.value)] = (callee, kw.arg)
                self.record_call(sub, scope, caller, skip)
            elif isinstance(sub, (ast.Name, ast.Attribute)):
                if isinstance(sub, ast.Attribute):
                    skip.add(id(sub.value))
                if references and id(sub) not in skip and isinstance(sub.ctx, ast.Load):
                    self.record_reference(sub, scope, caller, *context.get(id(sub), (None, None)))
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

    def record_reference(self, node: ast.AST, scope: dict, caller: str, arg_of: Optional[str], kwarg: Optional[str]) -> None:
        target = self.resolve(node, scope)
        if target and "." in target:  # bare module names (`verify(jwt, ...)`) are not symbols that can be called
            self.model.references.append(Reference(caller, target, self.file, node.lineno, self.code_at(node.lineno),
                                                   arg_of=arg_of, kwarg=kwarg))

    def record_call(self, call: ast.Call, scope: dict, caller: str, skip: Optional[set] = None) -> None:
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
        kwargs, kwargs_resolved = {}, {}
        for kw in call.keywords:
            if kw.arg:
                try:
                    kwargs[kw.arg] = ast.unparse(kw.value)
                except Exception:
                    kwargs[kw.arg] = "?"
                kwargs_resolved[kw.arg] = self.resolve(kw.value, scope)
        # dynamic-feature markers
        if resolved in DYNAMIC_CALLS or (resolved is None and receiver is None and last in ("getattr", "setattr", "eval", "exec", "__import__")):
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
        if resolved == "functools.partial" and call.args:
            # partial(f, k=v) is a deferred call f(k=v): record it as one, so safe-argument rules still apply
            inner = self.resolve(call.args[0], scope)
            if inner:
                if skip is not None:
                    skip.add(id(call.args[0]))
                self.model.calls.append(CallSite(caller=caller, callee=inner, last_name=inner.rsplit(".", 1)[-1],
                                                 file=self.file, line=call.lineno, code=self.code_at(call.lineno),
                                                 kwargs=kwargs, receiver=None, kwargs_resolved=kwargs_resolved))
        self.model.calls.append(CallSite(caller=caller, callee=resolved, last_name=last, file=self.file,
                                         line=call.lineno, code=self.code_at(call.lineno), kwargs=kwargs, receiver=receiver,
                                         kwargs_resolved=kwargs_resolved))


def _resolve_inherited(model: AppModel) -> None:
    """Post-pass: `self.m()` / `obj.m()` where m lives on a base class, or on an external base."""
    for cs in model.calls:
        if not cs.callee or cs.callee in model.functions:
            continue
        owner, _, method = cs.callee.rpartition(".")
        if owner and method and owner in model.functions and model.functions[owner].is_class:
            found = model.method_in_bases(owner, method)
            if found:
                cs.callee = found


def _returned_class(model: AppModel, target: str) -> str:
    """`make_session()` evaluates to the class make_session returns, when pass 1 knows it; else to `target` itself."""
    ret = model.returns.get(target)
    if ret and (model.functions.get(ret, FunctionInfo("", "", 0, 0)).is_class or ret.rsplit(".", 1)[-1][:1].isupper()):
        return ret
    return target


def _type_tables(model: AppModel) -> None:
    """Pass 1 fills the attribute and export tables while it is still collecting return types, so
    `self.session = make_session()` may be stored as the function. Re-type them now every return is known."""
    def settle(v: str) -> str:
        if v == UNKNOWN:
            return v
        if v.startswith(DEFERRED):
            fn = v[len(DEFERRED):]
            if fn not in model.functions:
                return UNKNOWN
            typed = _returned_class(model, fn)
            return typed if typed != fn or model.functions[fn].is_class else UNKNOWN
        return _returned_class(model, v)

    for table in model.attributes.values():
        for name, values in table.items():
            table[name] = {settle(v) for v in values}
    for table in model.exports.values():
        for name, value in table.items():
            table[name] = _returned_class(model, value)


def _app_prefixed(model: AppModel, dotted: str) -> bool:
    parts = dotted.split(".")
    return any(".".join(parts[:i]) in model.modules for i in range(1, len(parts)))


def _mark_phantoms(model: AppModel) -> None:
    """Post-pass: a callee under an app module that names nothing the app defines (`app.Cfg.client.get` where
    `self.client` is an untyped parameter, `helpers.CONFIG.load`) was never really resolved. Report it as
    unresolved, so the verdict engine's same-name check sees it instead of a confident wrong name."""
    for cs in model.calls:
        if cs.callee and cs.callee not in model.functions and _app_prefixed(model, cs.callee):
            cs.callee = None


def build(root: Path) -> AppModel:
    """Parse every .py file under root (and scan templates/config for symbol strings).

    Two passes over the Python files: pass 1 only collects function return types so that
    pass 2 can type `x = make_thing()`; pass 2 builds the real model.
    """
    root = Path(root).resolve()
    model = AppModel(root=str(root))
    parsed: list[tuple[str, str, str, ast.Module]] = []   # (module, rel, source, tree)
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
            except (OSError, ValueError) as exc:
                model.warnings.append(f"{rel}: unreadable, skipped ({exc})")
                continue
            module = _module_name(root, path)
            model.modules[module] = rel
            parsed.append((module, rel, source, tree))
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

    # Pass 1: return types, module exports and class attributes; everything else from this pass is discarded.
    for module, rel, source, tree in parsed:
        _ModuleAnalyzer(model, module, rel, source, collect_tables=True).analyze(tree)
    _type_tables(model)  # needs pass 1's functions (is_class), so before they are reset
    returns = dict(model.returns)
    model.functions, model.calls, model.dynamic, model.star_imports, model.imported_top_levels = {}, [], [], [], {}
    model.references = []
    model.strings = [s for s in model.strings if not s.file.endswith(".py")]
    model.returns = returns
    # Pass 2: the real model, now able to type `x = make_thing()`, follow re-exports and `self.attr` values.
    for module, rel, source, tree in parsed:
        _ModuleAnalyzer(model, module, rel, source).analyze(tree)
    _resolve_inherited(model)
    _mark_phantoms(model)
    model.canonical_cache.clear()
    return model
