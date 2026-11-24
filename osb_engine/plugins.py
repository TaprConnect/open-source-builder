"""Per-file language plug-ins for repository intelligence (I01). Standard library only.

Runs inside an isolated child: input is untrusted file bytes, output is a small fact
document that the supervisor validates. extract(kind, data) never executes repository
code. SQL is parsed by SQLite itself on an in-memory database with an authorizer that
permits only schema definition.
"""
import ast
import json
import re
import sqlite3

VERSION = "2"
_LIMIT = 5000


_VERBS = {"get", "post", "put", "patch", "delete"}
_CREDENTIAL_LAST = {"password", "passwd", "pwd", "secret", "token", "apikey", "secretkey"}
_KEY_PREFIXES = {"api", "secret", "access", "private", "signing", "encryption", "client"}
_PLACEHOLDERS = ("change", "example", "your", "xxx", "<", "${", "placeholder", "dummy", "redacted", "todo", "replace")
_LOG_METHODS = {"exception", "error", "warning", "warn", "critical", "fatal", "info", "debug", "log"}
_BROAD = {"Exception", "BaseException"}
_DECLARATIVE = {"group", "callback", "abstractmethod", "abstractproperty", "overload"}


def credential_name(name):
    """True when an identifier names a credential (DB_PASSWORD, apiKey, SECRET_KEY), not a label (password_field)."""
    parts = [p for p in re.split(r"[^a-z0-9]+", re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name).lower()) if p]
    if not parts:
        return False
    return parts[-1] in _CREDENTIAL_LAST or (parts[-1] == "key" and len(parts) > 1 and parts[-2] in _KEY_PREFIXES)


def real_secret(value):
    """Heuristic: a literal that looks like a real credential. Placeholders, words and phrases are excluded."""
    v = value.strip()
    return (len(v) >= 8 and not any(c.isspace() for c in v) and not re.fullmatch(r"[a-z]+(?:[-_.][a-z]+)*", v)
            and not any(p in v.lower() for p in _PLACEHOLDERS))


def _credentials(tree):
    """Credential-named targets bound to literal secrets. Names and lines only: values are never emitted."""
    found = []

    def check(name, value, line):
        literal = _const(value)
        if name and literal is not None and credential_name(name) and real_secret(literal):
            found.append({"kind": "literal", "name": name, "line": line})
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
            for target in (node.targets if isinstance(node, ast.Assign) else [node.target]):
                name = target.id if isinstance(target, ast.Name) else target.attr if isinstance(target, ast.Attribute) \
                    else _const(target.slice) if isinstance(target, ast.Subscript) else None
                check(name, node.value, node.lineno)
        elif isinstance(node, ast.Call):
            for kw in node.keywords:
                check(kw.arg, kw.value, getattr(kw, "lineno", node.lineno))
        elif isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if key is not None:
                    check(_const(key), value, key.lineno)
    return found[:_LIMIT]


def _broad(handler):
    types = handler.type.elts if isinstance(handler.type, ast.Tuple) else [handler.type]
    return any(isinstance(t, ast.Name) and t.id in _BROAD for t in types)


def _logs_or_raises(handler):
    return any(isinstance(n, ast.Raise) or (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                                            and n.func.attr in _LOG_METHODS) for n in ast.walk(handler))


def _const(node):
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _is_docstring(statement):
    return isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Constant) and isinstance(statement.value.value, str)


def _domain(tree):
    """Routes, environment-variable reads and per-function implementation issues."""
    routes, env, issues, required = [], set(), [], []
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
            declarative = {(d.func if isinstance(d, ast.Call) else d) for d in node.decorator_list}
            declarative = {d.id if isinstance(d, ast.Name) else d.attr if isinstance(d, ast.Attribute) else None
                           for d in declarative} & _DECLARATIVE
            if declarative:
                pass  # empty body is the idiom: click/typer groups and callbacks, abstract or overload declarations
            elif not body or all(isinstance(s, ast.Pass) or (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant)
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
                    elif _broad(handler) and not _logs_or_raises(handler):
                        issues.append({"kind": "unlogged_broad_handler", "function": node.name, "line": handler.lineno})
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
                if len(node.args) == 1 and not any(kw.arg == "default" for kw in node.keywords):
                    required.append({"name": _const(node.args[0]), "line": node.lineno})
        elif isinstance(node, ast.Subscript) and isinstance(node.value, ast.Attribute) and node.value.attr == "environ" \
                and _const(node.slice) is not None:
            env.add(_const(node.slice))
            if isinstance(node.ctx, ast.Load):
                required.append({"name": _const(node.slice), "line": node.lineno})
    return routes, sorted(env), issues, sorted(required, key=lambda r: (r["line"], r["name"]))


_MUTATORS = {"append", "extend", "update", "add", "insert", "setdefault", "pop", "remove", "clear", "discard"}
_CONTAINER_FACTORIES = {"set", "list", "dict", "deque", "defaultdict", "OrderedDict", "Counter"}


def _container(value):
    """A literal in-memory container: [], {}, set(), dict(), deque() ..."""
    if isinstance(value, (ast.List, ast.Dict, ast.Set, ast.ListComp, ast.DictComp, ast.SetComp)):
        return True
    return isinstance(value, ast.Call) and _call_name(value) in _CONTAINER_FACTORIES


def _constant_mapping(value):
    """A dict/set/tuple/list literal whose keys and values are all constants (a whitelist)."""
    if isinstance(value, ast.Dict):
        return all(isinstance(n, ast.Constant) for n in value.keys + value.values if n is not None) and None not in value.keys
    if isinstance(value, (ast.Set, ast.Tuple, ast.List)):
        return all(isinstance(n, ast.Constant) for n in value.elts)
    return False


def _functions(tree):
    """Per top-level function: names it calls and module-level names it mutates."""
    module_names, module_containers = set(), set()
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            names = {t.id for t in targets if isinstance(t, ast.Name)}
            module_names.update(names)
            if _container(node.value):
                module_containers.update(names)
    out = {}
    for node in tree.body[:_LIMIT]:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        calls, mutates = set(), set()
        declared_global = {n for g in ast.walk(node) if isinstance(g, ast.Global) for n in g.names}
        local_containers = {t.id for s in ast.walk(node) if isinstance(s, ast.Assign) and _container(s.value)
                            for t in s.targets if isinstance(t, ast.Name)}
        injected = list(node.args.defaults) + [d for d in node.args.kw_defaults if d is not None]
        for dec in node.decorator_list:  # route-level dependencies=[Depends(x)] (FastAPI)
            if isinstance(dec, ast.Call):
                for kw in dec.keywords:
                    if kw.arg == "dependencies" and isinstance(kw.value, (ast.List, ast.Tuple)):
                        injected += kw.value.elts
        for default in injected:
            if isinstance(default, ast.Call) and isinstance(default.func, (ast.Name, ast.Attribute)) and default.args:
                wrapper = default.func.id if isinstance(default.func, ast.Name) else default.func.attr
                target = default.args[0]
                if wrapper in ("Depends", "Security"):
                    calls.add(wrapper)
                    if isinstance(target, ast.Name):
                        calls.add(target.id)
                    elif isinstance(target, ast.Attribute):
                        calls.add(target.attr)
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call):
                f = sub.func
                if isinstance(f, ast.Name):
                    calls.add(f.id)
                elif isinstance(f, ast.Attribute):
                    receiver = f.value.id if isinstance(f.value, ast.Name) else None
                    if f.attr in _MUTATORS and receiver in module_containers:
                        mutates.add(receiver)  # in-memory state change, not a persistence call
                    elif f.attr in _MUTATORS and receiver in local_containers:
                        pass  # local scratch container
                    else:
                        calls.add(f.attr)
                        if f.attr in _MUTATORS and receiver in module_names:
                            mutates.add(receiver)
            elif isinstance(sub, (ast.Assign, ast.AugAssign)):
                for target in (sub.targets if isinstance(sub, ast.Assign) else [sub.target]):
                    if isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name) and target.value.id in module_names:
                        mutates.add(target.value.id)
                    elif isinstance(target, ast.Name) and target.id in declared_global:
                        mutates.add(target.id)
        decorators = set()
        for dec in node.decorator_list:
            target = dec.func if isinstance(dec, ast.Call) else dec
            if isinstance(target, ast.Name):
                decorators.add(target.id)
            elif isinstance(target, ast.Attribute):
                decorators.add(target.attr)
        out[node.name] = {"calls": sorted(calls)[:500], "mutates": sorted(mutates)[:100],
                          "decorators": sorted(decorators)[:100]}
    return out


_SOURCE_ATTRS = {"args", "form", "values", "json", "data", "files", "GET", "POST", "query_params", "path_params"}
_SANITISERS = {"int", "float", "bool", "quote", "basename", "secure_filename", "escape"}
_SUBPROCESS = {"run", "call", "check_call", "check_output", "Popen"}


def _call_name(call):
    f = call.func
    return f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else None


def _is_request(expr):
    return (isinstance(expr, ast.Name) and expr.id == "request") or (isinstance(expr, ast.Attribute) and expr.attr == "request")


def _tainted(expr, tainted, safe=frozenset()):
    """safe: module-level constant mappings; looking a value up in one yields a constant (whitelist)."""
    if expr is None:
        return False
    if isinstance(expr, ast.Subscript) and isinstance(expr.value, ast.Name) and expr.value.id in safe:
        return False
    if isinstance(expr, ast.Call):
        name = _call_name(expr)
        if name in _SANITISERS:
            return False
        if name == "get" and isinstance(expr.func, ast.Attribute) and isinstance(expr.func.value, ast.Name) \
                and expr.func.value.id in safe and not any(_tainted(a, tainted, safe) for a in expr.args[1:]):
            return False
        if name == "get_json" and isinstance(expr.func, ast.Attribute) and _is_request(expr.func.value):
            return True
        if name == "input" and isinstance(expr.func, ast.Name):
            return True
        return _tainted(expr.func, tainted, safe) or any(_tainted(a, tainted, safe) for a in expr.args) \
            or any(_tainted(k.value, tainted, safe) for k in expr.keywords)
    if isinstance(expr, ast.Attribute):
        if expr.attr in _SOURCE_ATTRS and _is_request(expr.value):
            return True
        return _tainted(expr.value, tainted, safe)
    if isinstance(expr, ast.Name):
        return expr.id in tainted
    return any(_tainted(child, tainted, safe) for child in ast.iter_child_nodes(expr))


def _constructed(expr):
    """A string built at the call site: f-string, concatenation, % formatting or .format()."""
    return isinstance(expr, ast.JoinedStr) or (isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.Add, ast.Mod))) \
        or (isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute) and expr.func.attr == "format")


def _taint(tree):
    """Flow-insensitive intraprocedural taint from request inputs to dangerous sinks."""
    findings = []
    safe = {t.id for n in tree.body if isinstance(n, ast.Assign) and _constant_mapping(n.value)
            for t in n.targets if isinstance(t, ast.Name)}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        handler = any(isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute) and d.func.attr.lower() in _VERBS | {"route"}
                      for d in node.decorator_list)
        tainted = {a.arg for a in node.args.args + node.args.kwonlyargs} if handler else set()
        for _ in range(10):
            before = len(tainted)
            for sub in ast.walk(node):
                if isinstance(sub, (ast.Assign, ast.AnnAssign, ast.AugAssign)) and _tainted(sub.value, tainted, safe):
                    targets = sub.targets if isinstance(sub, ast.Assign) else [sub.target]
                    for target in targets:
                        for name in ast.walk(target):
                            if isinstance(name, ast.Name):
                                tainted.add(name.id)
            if len(tainted) == before:
                break
        for call in ast.walk(node):
            if not isinstance(call, ast.Call) or not call.args:
                continue
            name, first = _call_name(call), call.args[0]
            owner = call.func.value.id if isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name) else None
            kind = None
            if name in ("execute", "executemany") and _tainted(first, tainted, safe):
                kind = "sql_injection"
            elif name in ("fetch", "fetchrow", "fetchval") and _constructed(first) and _tainted(first, tainted, safe):
                kind = "sql_injection"  # asyncpg-style query methods; a plain variable (e.g. HTTP fetch(url)) is not a query
            elif owner == "os" and name in ("system", "popen") and _tainted(first, tainted, safe):
                kind = "command_injection"
            elif owner == "subprocess" and name in _SUBPROCESS and _tainted(first, tainted, safe) and any(
                    k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True for k in call.keywords):
                kind = "command_injection"
            elif name in ("open", "send_file") and _tainted(first, tainted, safe):
                kind = "path_traversal"
            elif isinstance(call.func, ast.Name) and name in ("eval", "exec") and _tainted(first, tainted, safe):
                kind = "code_injection"
            if kind:
                findings.append({"kind": kind, "function": node.name, "line": call.lineno})
    return findings


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
    routes, env, issues, required = _domain(tree)
    return {"state": "SYMBOL_INDEXED", "facts": {"routes": routes[:_LIMIT], "env": env[:_LIMIT], "issues": issues[:_LIMIT],
                                                 "env_required": required[:_LIMIT], "credentials": _credentials(tree),
                                                 "functions": _functions(tree), "taint": _taint(tree)[:_LIMIT],
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


_TOML_STRING = __import__("re").compile(r'"(?:[^"\\\n]|\\.)*"|\'[^\'\n]*\'')
_TOML_HEADER = __import__("re").compile(r"^\s*\[\[?\s*([^\[\]]+?)\s*\]\]?\s*(?:#.*)?$")
_TOML_KEY = __import__("re").compile(r"^\s*([A-Za-z0-9_.\- ]+?)\s*=\s*(.*)$")
_SUBSET_REASON = "TOML subset parser (tomllib requires Python 3.11+): table names, keys and string arrays only"


def _toml_subset(text):
    """Python 3.10 fallback: top-level names and string-array values; never raises on bad input."""
    keys, arrays, table, key, buffer = set(), {}, (), None, ""
    for line in text.splitlines():
        if key is None:
            header = _TOML_HEADER.match(line)
            if header:
                table = tuple(part.strip().strip("\"'") for part in header.group(1).split("."))
                keys.add(table[0])
                continue
            match = _TOML_KEY.match(line)
            if not match:
                continue
            path = table + tuple(part.strip() for part in match.group(1).split("."))
            keys.add(path[0])
            if not match.group(2).lstrip().startswith("["):
                continue
            key, line = path, match.group(2)
        buffer += line + "\n"
        bare = _TOML_STRING.sub('""', buffer).split("\n")
        depth = sum(part.split("#", 1)[0].count("[") - part.split("#", 1)[0].count("]") for part in bare)
        if depth <= 0:
            values = []
            for token in _TOML_STRING.findall(buffer):
                try:
                    values.append(json.loads(token) if token.startswith('"') else token[1:-1])
                except ValueError:
                    continue
            arrays[key] = values
            key, buffer = None, ""
    return keys, arrays


def _toml(data):
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        return {"state": "INDEXED", "error": f"invalid TOML: {exc}"[:300]}
    try:
        import tomllib
    except ImportError:
        keys, _ = _toml_subset(text)
        return {"state": "PARSED", "reason": _SUBSET_REASON, "facts": {"keys": sorted(keys)[:_LIMIT]}}
    try:
        value = tomllib.loads(text)
    except ValueError as exc:
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
    if result["state"] == "INDEXED":
        return result
    try:
        import tomllib
    except ImportError:
        _, arrays = _toml_subset(data.decode("utf-8"))
        declared = list(arrays.get(("project", "dependencies"), []))
        for path, group in sorted(arrays.items()):
            if len(path) == 3 and path[:2] == ("project", "optional-dependencies"):
                declared += group
        result["facts"]["dependencies"] = _names(declared)
        return result
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
        # set_authorizer(None) only clears the hook from Python 3.11; allow reads explicitly instead.
        conn.set_authorizer(lambda *_: sqlite3.SQLITE_OK)
        tables = []
        for (name,) in conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"):
            columns = [row[1] for row in conn.execute(f'PRAGMA table_info("{name}")')]
            tables.append({"name": name, "columns": columns[:_LIMIT]})
        return {"state": "SYMBOL_INDEXED" if tables else "PARSED", "facts": {"tables": tables[:_LIMIT]}}
    finally:
        conn.close()


_ENV_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _dotenv(data, example=False):
    """Variable names of a dotenv file; credential names with real values unless it is an example file.
    Values are never emitted."""
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        return {"state": "INDEXED", "error": f"undecodable dotenv file: {exc}"[:300]}
    keys, credentials = [], []
    for number, line in enumerate(lines[:20 * _LIMIT], 1):
        text = line.strip()
        if text.startswith("export "):
            text = text[7:].lstrip()
        if not text or text.startswith("#") or "=" not in text:
            continue
        key, value = (part.strip() for part in text.split("=", 1))
        if not _ENV_KEY.fullmatch(key):
            continue
        keys.append(key)
        if value[:1] in ("'", '"'):
            value = value[1:value.find(value[0], 1)] if value.find(value[0], 1) > 0 else value[1:]
        else:
            value = value.split(" #", 1)[0].strip()
        if not example and credential_name(key) and real_secret(value):
            credentials.append({"kind": "dotenv", "name": key, "line": number})
    facts = {"keys": sorted(set(keys))[:_LIMIT], "credentials": credentials[:_LIMIT]}
    return {"state": "SYMBOL_INDEXED" if keys else "PARSED", "facts": facts}


PLUGINS = {"python": _python, "json": _json, "toml": _toml, "sql": _sql, "pyproject": _pyproject,
           "requirements": _requirements, "dotenv": _dotenv, "dotenv_example": lambda data: _dotenv(data, True)}
_EXAMPLE_SUFFIXES = {"example", "sample", "template", "dist", "defaults"}
EXTENSIONS = {".py": "python", ".json": "json", ".toml": "toml", ".sql": "sql",
              ".ts": "typescript", ".tsx": "typescript", ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript"}


def language(path):
    base = path.rsplit("/", 1)[-1].lower()
    if base == "pyproject.toml":
        return "pyproject"
    if base.startswith("requirements") and base.endswith(".txt"):
        return "requirements"
    if base == ".env" or base.startswith(".env."):
        return "dotenv_example" if base.rsplit(".", 1)[-1] in _EXAMPLE_SUFFIXES else "dotenv"
    for suffix, name in EXTENSIONS.items():
        if path.lower().endswith(suffix):
            return name
    return None


def extract(kind, data):
    plugin = PLUGINS.get(kind)
    if plugin is None:
        return {"state": "INDEXED", "reason": f"unsupported: no parser available for {kind}"}
    return plugin(data)
