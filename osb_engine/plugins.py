"""Per-file language plug-ins for repository intelligence (I01). Standard library only.

Runs inside an isolated child: input is untrusted file bytes, output is a small fact
document that the supervisor validates. extract(kind, data) never executes repository
code. SQL is parsed by SQLite itself on an in-memory database with an authorizer that
permits only schema definition.
"""
import ast
import json
import sqlite3

VERSION = "1"
_LIMIT = 5000


_VERBS = {"get", "post", "put", "patch", "delete"}


def _const(node):
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _is_docstring(statement):
    return isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Constant) and isinstance(statement.value.value, str)


def _domain(tree):
    """Routes, environment-variable reads and per-function implementation issues."""
    routes, env, issues = [], set(), []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for dec in node.decorator_list:
                if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute) and dec.args and _const(dec.args[0]) is not None:
                    attr = dec.func.attr.lower()
                    if attr in _VERBS:
                        methods = [attr.upper()]
                    elif attr == "route":
                        methods = ["GET"]
                        for kw in dec.keywords:
                            if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
                                methods = [str(_const(e)).upper() for e in kw.value.elts if _const(e) is not None]
                    else:
                        continue
                    routes.append({"path": _const(dec.args[0]), "methods": sorted(methods), "function": node.name, "line": dec.lineno})
            body = [s for s in node.body if not _is_docstring(s)] if node.body and _is_docstring(node.body[0]) else node.body
            if not body or all(isinstance(s, ast.Pass) or (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant)
                                                          and s.value.value is Ellipsis) for s in body):
                issues.append({"kind": "placeholder", "function": node.name, "line": node.lineno})
            elif len(body) == 1 and isinstance(body[0], ast.Raise) and body[0].exc is not None:
                exc = body[0].exc.func if isinstance(body[0].exc, ast.Call) else body[0].exc
                if isinstance(exc, ast.Name) and exc.id == "NotImplementedError":
                    issues.append({"kind": "not_implemented", "function": node.name, "line": node.lineno})
            for handler in ast.walk(node):
                if isinstance(handler, ast.ExceptHandler):
                    if handler.type is None:
                        issues.append({"kind": "bare_except", "function": node.name, "line": handler.lineno})
                    elif all(isinstance(s, ast.Pass) for s in handler.body):
                        issues.append({"kind": "swallowed_exception", "function": node.name, "line": handler.lineno})
        elif isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id in ("path", "re_path") and len(node.args) >= 2 and _const(node.args[0]) is not None:
                view = node.args[1]
                name = view.id if isinstance(view, ast.Name) else view.attr if isinstance(view, ast.Attribute) else None
                if name:
                    routes.append({"path": _const(node.args[0]), "methods": ["ANY"], "function": name, "line": node.lineno})
            if isinstance(func, ast.Attribute) and node.args and _const(node.args[0]) is not None and (
                    (func.attr == "getenv" and isinstance(func.value, ast.Name) and func.value.id == "os")
                    or (func.attr == "get" and isinstance(func.value, ast.Attribute) and func.value.attr == "environ")):
                env.add(_const(node.args[0]))
        elif isinstance(node, ast.Subscript) and isinstance(node.value, ast.Attribute) and node.value.attr == "environ" \
                and _const(node.slice) is not None:
            env.add(_const(node.slice))
    return routes, sorted(env), issues


_MUTATORS = {"append", "extend", "update", "add", "insert", "setdefault", "pop", "remove", "clear", "discard"}


def _functions(tree):
    """Per top-level function: names it calls and module-level names it mutates."""
    module_names = set()
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            module_names.update(t.id for t in targets if isinstance(t, ast.Name))
    out = {}
    for node in tree.body[:_LIMIT]:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        calls, mutates = set(), set()
        declared_global = {n for g in ast.walk(node) if isinstance(g, ast.Global) for n in g.names}
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call):
                f = sub.func
                if isinstance(f, ast.Name):
                    calls.add(f.id)
                elif isinstance(f, ast.Attribute):
                    calls.add(f.attr)
                    if f.attr in _MUTATORS and isinstance(f.value, ast.Name) and f.value.id in module_names:
                        mutates.add(f.value.id)
            elif isinstance(sub, (ast.Assign, ast.AugAssign)):
                for target in (sub.targets if isinstance(sub, ast.Assign) else [sub.target]):
                    if isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name) and target.value.id in module_names:
                        mutates.add(target.value.id)
                    elif isinstance(target, ast.Name) and target.id in declared_global:
                        mutates.add(target.id)
        out[node.name] = {"calls": sorted(calls)[:500], "mutates": sorted(mutates)[:100]}
    return out


def _python(data):
    try:
        tree = ast.parse(data)
    except (SyntaxError, ValueError, RecursionError, MemoryError) as exc:
        return {"state": "INDEXED", "error": f"{type(exc).__name__}: {exc}"[:300]}
    definitions, imports, references, exports, main_guard = [], [], set(), [], False
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            kind = "class" if isinstance(node, ast.ClassDef) else "function"
            definitions.append({"name": node.name, "kind": kind, "line": node.lineno})
        elif isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "__all__" for t in node.targets):
            if isinstance(node.value, (ast.List, ast.Tuple)):
                exports += [e.value for e in node.value.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)]
        elif isinstance(node, ast.If) and isinstance(node.test, ast.Compare) and isinstance(node.test.left, ast.Name) \
                and node.test.left.id == "__name__":
            main_guard = True
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports += [{"module": a.name, "names": [], "level": 0, "line": node.lineno} for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            imports.append({"module": node.module or "", "names": [a.name for a in node.names],
                            "level": node.level, "line": node.lineno})
            references.update(a.name for a in node.names)
        elif isinstance(node, ast.Name):
            references.add(node.id)
        elif isinstance(node, ast.Attribute):
            references.add(node.attr)
    routes, env, issues = _domain(tree)
    return {"state": "SYMBOL_INDEXED", "facts": {"routes": routes[:_LIMIT], "env": env[:_LIMIT], "issues": issues[:_LIMIT],
                                                 "functions": _functions(tree),
                                                 "definitions": definitions[:_LIMIT], "imports": imports[:_LIMIT],
                                                 "references": sorted(references)[:20 * _LIMIT],
                                                 "exports": exports[:_LIMIT], "main_guard": main_guard}}


def _json(data):
    try:
        value = json.loads(data)
    except (ValueError, RecursionError) as exc:
        return {"state": "INDEXED", "error": f"invalid JSON: {exc}"[:300]}
    keys = sorted(value)[:_LIMIT] if isinstance(value, dict) else []
    return {"state": "SYMBOL_INDEXED" if keys else "PARSED", "facts": {"keys": [str(k) for k in keys]}}


def _toml(data):
    try:
        import tomllib
    except ImportError:
        return {"state": "INDEXED", "reason": "unsupported: tomllib requires Python 3.11+"}
    try:
        value = tomllib.loads(data.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        return {"state": "INDEXED", "error": f"invalid TOML: {exc}"[:300]}
    return {"state": "SYMBOL_INDEXED", "facts": {"keys": sorted(value)[:_LIMIT]}}


_NAME = __import__("re").compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def _names(requirements):
    out = []
    for item in requirements:
        match = _NAME.match(item) if isinstance(item, str) else None
        if match:
            out.append(match.group(1))
    return sorted(set(out))[:_LIMIT]


def _pyproject(data):
    result = _toml(data)
    if result["state"] != "SYMBOL_INDEXED":
        return result
    import tomllib
    project = tomllib.loads(data.decode("utf-8")).get("project", {})
    declared = list(project.get("dependencies", []) if isinstance(project.get("dependencies"), list) else [])
    optional = project.get("optional-dependencies", {})
    if isinstance(optional, dict):
        for group in optional.values():
            declared += group if isinstance(group, list) else []
    result["facts"]["dependencies"] = _names(declared)
    return result


def _requirements(data):
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        return {"state": "INDEXED", "error": f"undecodable requirements file: {exc}"[:300]}
    entries = [line.split("#", 1)[0].strip() for line in lines]
    names = _names([e for e in entries if e and not e.startswith("-")])
    return {"state": "SYMBOL_INDEXED" if names else "PARSED", "facts": {"dependencies": names}}


_ALLOWED_SQL = {sqlite3.SQLITE_CREATE_TABLE, sqlite3.SQLITE_CREATE_INDEX, sqlite3.SQLITE_CREATE_VIEW,
                sqlite3.SQLITE_INSERT, sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_READ, sqlite3.SQLITE_SELECT,
                sqlite3.SQLITE_FUNCTION, sqlite3.SQLITE_TRANSACTION}


def _sql(data):
    conn = sqlite3.connect(":memory:")
    try:
        conn.set_authorizer(lambda action, *_: sqlite3.SQLITE_OK if action in _ALLOWED_SQL else sqlite3.SQLITE_DENY)
        try:
            conn.executescript(data.decode("utf-8"))
        except (sqlite3.Error, UnicodeDecodeError, ValueError) as exc:
            return {"state": "INDEXED", "error": f"SQL not understood by SQLite: {exc}"[:300]}
        conn.set_authorizer(None)
        tables = []
        for (name,) in conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"):
            columns = [row[1] for row in conn.execute(f'PRAGMA table_info("{name}")')]
            tables.append({"name": name, "columns": columns[:_LIMIT]})
        return {"state": "SYMBOL_INDEXED" if tables else "PARSED", "facts": {"tables": tables[:_LIMIT]}}
    finally:
        conn.close()


PLUGINS = {"python": _python, "json": _json, "toml": _toml, "sql": _sql, "pyproject": _pyproject,
           "requirements": _requirements}
EXTENSIONS = {".py": "python", ".json": "json", ".toml": "toml", ".sql": "sql",
              ".ts": "typescript", ".tsx": "typescript", ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript"}


def language(path):
    base = path.rsplit("/", 1)[-1].lower()
    if base == "pyproject.toml":
        return "pyproject"
    if base.startswith("requirements") and base.endswith(".txt"):
        return "requirements"
    for suffix, name in EXTENSIONS.items():
        if path.lower().endswith(suffix):
            return name
    return None


def extract(kind, data):
    plugin = PLUGINS.get(kind)
    if plugin is None:
        return {"state": "INDEXED", "reason": f"unsupported: no parser available for {kind}"}
    return plugin(data)
