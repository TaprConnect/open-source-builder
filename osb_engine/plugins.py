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
    return {"state": "SYMBOL_INDEXED", "facts": {"definitions": definitions[:_LIMIT], "imports": imports[:_LIMIT],
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
