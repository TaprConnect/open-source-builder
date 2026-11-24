"""Deterministic repair generators (S06-004) for Python modules.

Each repairer inspects the *current* working-tree source with the AST, decides whether its
defect pattern is present, and returns the full repaired source (or None). The pipeline turns
that into a unified diff; the kernel applies it, and only owner-frozen external acceptance
decides whether it worked. Repairers never touch tests, acceptance or policy files.

Supported defect classes:
  persist_store      module-level dict used as a record store -> SQLite-backed mapping (stdlib)
  enforce_ownership  record returned/deleted by id without comparing its owner to the caller
  complete_crud      update/delete/get function that raises NotImplementedError, synthesised
                     from the sibling functions that use the same store
  validate_required  owner rule {"function", "param", "rule": "non_empty"} enforced on entry
"""
import ast
import difflib
import re

OWNER_KEYS = ("owner", "user", "user_id", "owner_id", "author", "created_by")
_USER_PARAMS = ("user", "user_id", "owner", "current_user", "username", "actor")
_SENSITIVE = re.compile(r"(^|/)(tests?|__tests__|\.github|acceptance)(/|$)|(^|/)test_[^/]*$|_test\.py$|conftest\.py$")

_PERSIST_HELPER = '''

class _OsbPersistentStore:
    """SQLite-backed mapping (added by Open Source Builder): values survive process restarts."""

    def __init__(self, name):
        import os, sqlite3, tempfile
        default = os.path.join(tempfile.gettempdir(), name + ".sqlite3")
        self._path = os.environ.get("OSB_STORE_" + name.upper().strip("_"), default)
        self._conn = sqlite3.connect(self._path)
        self._conn.execute("CREATE TABLE IF NOT EXISTS records (k TEXT PRIMARY KEY, v TEXT NOT NULL)")
        self._conn.commit()

    def _rows(self):
        import json
        return [(json.loads(k), json.loads(v)) for k, v in self._conn.execute("SELECT k, v FROM records ORDER BY rowid")]

    def __setitem__(self, key, value):
        import json
        self._conn.execute("INSERT OR REPLACE INTO records VALUES (?, ?)", (json.dumps(key), json.dumps(value)))
        self._conn.commit()

    def __getitem__(self, key):
        import json
        row = self._conn.execute("SELECT v FROM records WHERE k = ?", (json.dumps(key),)).fetchone()
        if row is None:
            raise KeyError(key)
        return json.loads(row[0])

    def __delitem__(self, key):
        import json
        if self._conn.execute("DELETE FROM records WHERE k = ?", (json.dumps(key),)).rowcount == 0:
            raise KeyError(key)
        self._conn.commit()

    def __contains__(self, key):
        try:
            self[key]
            return True
        except KeyError:
            return False

    def __iter__(self):
        return iter([k for k, _ in self._rows()])

    def __len__(self):
        return self._conn.execute("SELECT COUNT(*) FROM records").fetchone()[0]

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    def keys(self):
        return [k for k, _ in self._rows()]

    def values(self):
        return [v for _, v in self._rows()]

    def items(self):
        return self._rows()

    def pop(self, key, *default):
        try:
            value = self[key]
        except KeyError:
            if default:
                return default[0]
            raise
        del self[key]
        return value
'''


def _module_stores(tree):
    """Module-level names bound to an empty dict and used with subscripts by functions."""
    stores = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and (
                isinstance(node.value, ast.Dict) and not node.value.keys
                or isinstance(node.value, ast.Call) and getattr(node.value.func, "id", "") == "_OsbPersistentStore"):
            stores[node.targets[0].id] = node
    used = set()
    for fn in _functions(tree):
        for sub in ast.walk(fn):
            if isinstance(sub, ast.Subscript) and isinstance(sub.value, ast.Name) and sub.value.id in stores:
                used.add(sub.value.id)
    return {name: node for name, node in stores.items() if name in used}


def _functions(tree):
    return [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]


def _user_param(fn):
    names = [a.arg for a in fn.args.args]
    return next((n for n in names if n in _USER_PARAMS), None)


def _id_param(fn, user):
    names = [a.arg for a in fn.args.args if a.arg != user]
    return next((n for n in names if n == "id" or n.endswith("_id")), None)


def _owner_key(tree, store):
    """The key that creation functions set from the caller's identity, e.g. {"owner": user}."""
    for fn in _functions(tree):
        user = _user_param(fn)
        if not user:
            continue
        for sub in ast.walk(fn):
            if isinstance(sub, ast.Assign) and any(isinstance(t, ast.Subscript) and isinstance(t.value, ast.Name)
                                                   and t.value.id == store for t in sub.targets) \
                    and isinstance(sub.value, ast.Dict):
                for k, v in zip(sub.value.keys, sub.value.values):
                    if isinstance(k, ast.Constant) and k.value in OWNER_KEYS and isinstance(v, ast.Name) and v.id == user:
                        return k.value
    return None


def _replace_lines(source, start, end, new_lines, indent):
    lines = source.splitlines(True)
    body = "".join(indent + line + "\n" if line else "\n" for line in new_lines)
    return "".join(lines[:start - 1]) + body + "".join(lines[end:])


def persist_store(source, task=None):
    tree = ast.parse(source)
    stores = _module_stores(tree)
    if not stores or "_OsbPersistentStore" in source:
        return None
    lines = source.splitlines(True)
    for name, node in sorted(stores.items(), key=lambda kv: -kv[1].lineno):
        line = lines[node.lineno - 1]
        lines[node.lineno - 1] = line[:node.col_offset] + f"{name} = _OsbPersistentStore({name!r})\n"
    first = min(n.lineno for n in stores.values())
    insert_at = first - 1
    return "".join(lines[:insert_at]) + _PERSIST_HELPER.lstrip("\n") + "\n\n" + "".join(lines[insert_at:])


def enforce_ownership(source, task=None):
    tree = ast.parse(source)
    changed = source
    for store in sorted(_module_stores(tree)):
        key = _owner_key(tree, store)
        if not key:
            continue
        for fn in sorted(_functions(tree), key=lambda f: -f.lineno):
            user, ident = _user_param(fn), None
            if not user:
                continue
            ident = _id_param(fn, user)
            if not ident or _is_not_implemented(fn):
                continue
            reads = any(isinstance(s, ast.Subscript) and isinstance(s.value, ast.Name) and s.value.id == store
                        and isinstance(s.slice, ast.Name) and s.slice.id == ident for s in ast.walk(fn))
            checks = any(isinstance(s, ast.Compare) and any(isinstance(n, ast.Name) and n.id == user for n in ast.walk(s))
                         for s in ast.walk(fn))
            if reads and not checks:
                first = _first_statement(fn)
                indent = " " * first.col_offset
                guard = [f"if {ident} not in {store} or {store}[{ident}].get({key!r}) != {user}:",
                         f"    raise PermissionError({fn.name!r} + ': not the owner of this record')"]
                changed = _replace_lines(changed, first.lineno, first.lineno - 1, guard, indent)
                tree = ast.parse(changed)
    return changed if changed != source else None


def _first_statement(fn):
    body = fn.body
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
        return body[1] if len(body) > 1 else body[0]
    return body[0]


def _is_not_implemented(fn):
    stmt = _first_statement(fn)
    target = stmt.exc.func if isinstance(stmt, ast.Raise) and isinstance(stmt.exc, ast.Call) else \
        stmt.exc if isinstance(stmt, ast.Raise) else None
    return isinstance(target, ast.Name) and target.id == "NotImplementedError" or isinstance(stmt, ast.Pass) and len(fn.body) == 1


def complete_crud(source, task=None):
    tree = ast.parse(source)
    stores = _module_stores(tree)
    if len(stores) != 1:
        return None  # ambiguous which store a stub should use: leave to a model or a person
    store = next(iter(stores))
    key = _owner_key(tree, store)
    changed = source
    for fn in sorted(_functions(tree), key=lambda f: -f.lineno):
        if not _is_not_implemented(fn):
            continue
        verb = fn.name.split("_", 1)[0]
        user = _user_param(fn)
        ident = _id_param(fn, user)
        params = [a.arg for a in fn.args.args if a.arg not in (user, ident)]
        guard = [f"if {ident} not in {store}:", f"    raise KeyError({ident})"] if ident else []
        if key and user and ident:
            guard += [f"if {store}[{ident}].get({key!r}) != {user}:",
                      f"    raise PermissionError({fn.name!r} + ': not the owner of this record')"]
        if verb in ("delete", "remove") and ident:
            body = guard + [f"del {store}[{ident}]", "return True"]
        elif verb in ("get", "read", "fetch") and ident:
            body = guard + [f"return {store}[{ident}]"]
        elif verb in ("update", "edit") and ident and params:
            body = guard + [f"record = dict({store}[{ident}])"] + [f"record[{p!r}] = {p}" for p in params] + \
                   [f"{store}[{ident}] = record", "return record"]
        else:
            continue
        stmt = _first_statement(fn)
        end = fn.end_lineno
        changed = _replace_lines(changed, stmt.lineno, end, body, " " * stmt.col_offset)
    return changed if changed != source else None


def validate_required(source, task=None):
    rules = [r for r in (task or {}).get("rules", []) if r.get("rule") == "non_empty"]
    if not rules:
        return None
    tree = ast.parse(source)
    changed = source
    for rule in rules:
        fn = next((f for f in _functions(tree) if f.name == rule.get("function")), None)
        param = rule.get("param")
        if fn is None or param not in [a.arg for a in fn.args.args]:
            continue
        if any(isinstance(s, ast.Raise) and isinstance(s.exc, ast.Call) and getattr(s.exc.func, "id", "") == "ValueError"
               for s in ast.walk(fn)):
            continue
        first = _first_statement(fn)
        guard = [f"if not isinstance({param}, str) or not {param}.strip():",
                 f"    raise ValueError({param!r} + ' must be a non-empty string')"]
        changed = _replace_lines(changed, first.lineno, first.lineno - 1, guard, " " * first.col_offset)
        tree = ast.parse(changed)
    return changed if changed != source else None


REPAIRERS = {"persist_store": persist_store, "enforce_ownership": enforce_ownership,
             "complete_crud": complete_crud, "validate_required": validate_required}


def diff(path, before, after):
    return "".join(difflib.unified_diff(before.splitlines(True), after.splitlines(True),
                                        fromfile="a/" + path, tofile="b/" + path))


def allowed_path(path, scope):
    """Repairs may only touch granted, non-sensitive paths."""
    return path in scope and not _SENSITIVE.search(path)


def propose(root, task, repairer):
    """Run one repairer over the task scope; return a patch (str) or None. Never raises on odd input."""
    patches = []
    for path in task["scope"]:
        if not path.endswith(".py") or not allowed_path(path, task["scope"]):
            continue
        try:
            before = (root / path).read_text(encoding="utf-8")
            after = REPAIRERS[repairer](before, task)
        except (OSError, SyntaxError, UnicodeDecodeError, ValueError, RecursionError):
            continue
        if after is not None and after != before:
            ast.parse(after)  # a repair must leave valid Python
            patches.append(diff(path, before, after))
    return "".join(patches) or None
