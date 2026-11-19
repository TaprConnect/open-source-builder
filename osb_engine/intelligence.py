"""Repository intelligence index (I01): cross-file analysis over validated per-file facts.

Per-file facts come from osb_engine.plugins, run in isolated children (or in-process
only when the operator asserts a trusted target). States are explicit: static
indexing reaches at most DEPENDENCIES_RESOLVED; SEMANTICALLY_REVIEWED and
RUNTIME_VERIFIED require evidence this module never produces.
"""
from . import plugins

STATES = ("INDEXED", "PARSED", "SYMBOL_INDEXED", "DEPENDENCIES_RESOLVED", "SEMANTICALLY_REVIEWED", "RUNTIME_VERIFIED")
_TEXT_MAX, _ITEMS_MAX = 4096, 100000


def _text(value):
    return isinstance(value, str) and len(value) <= _TEXT_MAX


def _texts(values, limit=_ITEMS_MAX):
    return isinstance(values, list) and len(values) <= limit and all(_text(v) for v in values)


def _count(value):
    return type(value) is int and 0 <= value <= 10 ** 9


def valid_facts(result):
    """Strict schema check of one plug-in result produced by an untrusted child."""
    if not isinstance(result, dict) or result.get("state") not in STATES[:3]:
        return False
    extra = set(result) - {"state", "facts", "error", "reason"}
    if extra or any(k in result and not _text(result[k]) for k in ("error", "reason")):
        return False
    facts = result.get("facts", {})
    if not isinstance(facts, dict):
        return False
    known = {"definitions", "imports", "references", "exports", "main_guard", "keys", "tables", "dependencies",
             "routes", "env", "issues", "functions", "taint", "env_required", "credentials"}
    if set(facts) - known:
        return False
    for r in facts.get("env_required", []):
        if not (isinstance(r, dict) and set(r) == {"name", "line"} and _text(r["name"]) and _count(r["line"])):
            return False
    for c in facts.get("credentials", []):
        if not (isinstance(c, dict) and set(c) == {"kind", "name", "line"} and c["kind"] in ("literal", "dotenv")
                and _text(c["name"]) and _count(c["line"])):
            return False
    for d in facts.get("definitions", []):
        if not (isinstance(d, dict) and set(d) == {"name", "kind", "line"} and _text(d["name"])
                and d["kind"] in ("function", "class") and _count(d["line"])):
            return False
    for i in facts.get("imports", []):
        if not (isinstance(i, dict) and set(i) == {"module", "names", "level", "line"} and _text(i["module"])
                and _texts(i["names"]) and _count(i["level"]) and _count(i["line"])):
            return False
    for r in facts.get("routes", []):
        if not (isinstance(r, dict) and set(r) == {"path", "methods", "function", "line"} and _text(r["path"])
                and _texts(r["methods"]) and _text(r["function"]) and _count(r["line"])):
            return False
    for f in facts.get("taint", []):
        if not (isinstance(f, dict) and set(f) == {"kind", "function", "line"} and _text(f["function"]) and _count(f["line"])
                and f["kind"] in ("sql_injection", "command_injection", "path_traversal", "code_injection")):
            return False
    for i in facts.get("issues", []):
        if not (isinstance(i, dict) and set(i) == {"kind", "function", "line"} and _text(i["function"]) and _count(i["line"])
                and i["kind"] in ("placeholder", "not_implemented", "swallowed_exception", "bare_except",
                                  "unlogged_broad_handler")):
            return False
    functions = facts.get("functions", {})
    if not isinstance(functions, dict) or len(functions) > _ITEMS_MAX:
        return False
    for name, info in functions.items():
        if not (_text(name) and isinstance(info, dict) and set(info) == {"calls", "mutates", "decorators"}
                and _texts(info["calls"], 500) and _texts(info["mutates"], 100) and _texts(info["decorators"], 100)):
            return False
    for t in facts.get("tables", []):
        if not (isinstance(t, dict) and set(t) == {"name", "columns"} and _text(t["name"]) and _texts(t["columns"])):
            return False
    if any(k in facts and not _texts(facts[k], 2_000_000) for k in ("references", "exports", "keys", "dependencies", "env")):
        return False
    return "main_guard" not in facts or isinstance(facts["main_guard"], bool)


# Import names that differ from their distribution names (documented heuristic).
_IMPORT_TO_DIST = {"yaml": "pyyaml", "PIL": "pillow", "sklearn": "scikit-learn", "cv2": "opencv-python",
                   "bs4": "beautifulsoup4", "dateutil": "python-dateutil", "jwt": "pyjwt", "google": "protobuf",
                   "attr": "attrs", "dotenv": "python-dotenv", "magic": "python-magic", "OpenSSL": "pyopenssl"}


def _normalise(name):
    return __import__("re").sub(r"[-_.]+", "-", name).lower()


def _classify(root, declared):
    import sys
    if root in sys.stdlib_module_names:
        return "stdlib"
    if _normalise(root) in declared or _normalise(_IMPORT_TO_DIST.get(root, root)) in declared:
        return "declared"
    return "undeclared"


_AUTH = __import__("re").compile(r"login|auth|permission|role|jwt|admin|token|current_user|authori[sz]e", __import__("re").I)
_PERSISTENCE = {"execute", "executemany", "commit", "add", "add_all", "save", "insert", "insert_one", "insert_many",
                "update_one", "put_item", "bulk_write", "connect"}


def _module_name(path):
    name = path[:-3].replace("/", ".")
    return name[:-9] if name.endswith(".__init__") else name


def _resolve(path, entry, modules):
    """Return (targets, external_root or None) for one import statement."""
    if entry["level"]:
        package = _module_name(path).split(".")
        if not path.endswith("__init__.py"):
            package = package[:-1]
        package = package[:len(package) - entry["level"] + 1] if entry["level"] > 1 else package
        base = ".".join(p for p in package + ([entry["module"]] if entry["module"] else []) if p)
    else:
        base = entry["module"]
    submodules = [f"{base}.{n}" for n in entry["names"] if f"{base}.{n}" in modules]
    needs_package = not entry["names"] or len(submodules) < len(entry["names"])
    targets = sorted({modules[c] for c in submodules} | ({modules[base]} if needs_package and base in modules else set()))
    if targets:
        return targets, None
    if entry["level"]:
        return [], None
    return [], base.split(".")[0] or None


def _cycles(nodes, edges):
    """Tarjan strongly connected components with more than one node (or a self loop)."""
    graph = {n: sorted({b for a, b in edges if a == n}) for n in nodes}
    index, low, stack, on, out, counter = {}, {}, [], set(), [], [0]

    def visit(v):
        index[v] = low[v] = counter[0]
        counter[0] += 1
        stack.append(v)
        on.add(v)
        for w in graph[v]:
            if w not in index:
                visit(w)
                low[v] = min(low[v], low[w])
            elif w in on:
                low[v] = min(low[v], index[w])
        if low[v] == index[v]:
            component = []
            while True:
                w = stack.pop()
                on.discard(w)
                component.append(w)
                if w == v:
                    break
            if len(component) > 1 or (v, v) in edges:
                out.append(sorted(component))

    import sys
    limit = sys.getrecursionlimit()
    sys.setrecursionlimit(max(limit, 10 * len(nodes) + 1000))
    try:
        for n in sorted(nodes):
            if n not in index:
                visit(n)
    finally:
        sys.setrecursionlimit(limit)
    return sorted(out)


def build_index(repo, extractor=None):
    """Index the pinned revision. extractor(items) -> {key: result}; None means in-process."""
    run = extractor or (lambda items: {k: plugins.extract(kind, data) for k, kind, data in items})
    blobs, items = [], []
    for blob in repo.inventory():
        kind = plugins.language(blob.path)
        blobs.append((blob, kind))
        if kind in plugins.PLUGINS and blob.kind == "blob" and blob.mode in ("100644", "100755") \
                and blob.size <= 4 * 1024 * 1024:
            items.append((blob.path, kind, repo.read(blob)))
    results = run(items)
    files, modules = [], {}
    for blob, kind in blobs:
        entry = {"path": blob.path, "language": kind, "state": "INDEXED"}
        result = results.get(blob.path)
        if kind is not None and kind not in plugins.PLUGINS:
            entry["reason"] = f"unsupported: no parser available for {kind}"
        elif kind is not None and blob.path in results and result is None:
            entry["error"] = "isolated extraction failed or result rejected"
        elif result is not None:
            entry.update({k: v for k, v in result.items() if k in ("state", "error", "reason")})
            entry["facts"] = result.get("facts", {})
        if kind == "python" and entry["state"] == "SYMBOL_INDEXED":
            modules[_module_name(blob.path)] = blob.path
        files.append(entry)
    declared = {_normalise(d) for f in files for d in f.get("facts", {}).get("dependencies", [])}
    edges, external, resolved, total = set(), set(), 0, 0
    classified, missing = {}, {}
    for entry in files:
        if entry["language"] != "python" or entry["state"] != "SYMBOL_INDEXED":
            continue
        unresolved = 0
        for imp in entry["facts"]["imports"]:
            total += 1
            targets, root = _resolve(entry["path"], imp, modules)
            if targets:
                resolved += 1
                edges.update((entry["path"], t) for t in targets if t != entry["path"])
            elif root:
                external.add(root)
                classified[root] = _classify(root, declared)
                if classified[root] == "undeclared":
                    missing.setdefault(root, set()).add(entry["path"])
                    unresolved += 1
                else:
                    resolved += 1
            else:
                unresolved += 1
        if unresolved == 0:
            entry["state"] = "DEPENDENCIES_RESOLVED"
    python = [f for f in files if f["language"] == "python" and "facts" in f]
    entry_points = sorted(f["path"] for f in python
                          if f["path"].endswith("__main__.py") or f["facts"].get("main_guard"))
    referenced = set()
    for f in python:
        referenced.update(f["facts"].get("references", []))
    dead = []
    for f in python:
        if f["path"] in entry_points:
            continue
        exports = set(f["facts"].get("exports", []))
        decorated = {n for n, info in f["facts"].get("functions", {}).items() if info.get("decorators")}
        for d in f["facts"].get("definitions", []):
            name = d["name"]
            if name.startswith("_") or name in exports or name in referenced or name in decorated:
                continue
            dead.append({"path": f["path"], "symbol": name, "kind": d["kind"], "line": d["line"],
                         "confidence": "candidate", "note": "no static reference in this repository"})
    routes, environment, issues, taint = [], {}, [], []
    for f in python:
        facts = f["facts"]
        routes += [{**r, "file": f["path"]} for r in facts.get("routes", [])]
        for name in facts.get("env", []):
            environment.setdefault(name, []).append(f["path"])
        issues += [{"path": f["path"], **i} for i in facts.get("issues", [])]
        taint += [{"file": f["path"], **x} for x in facts.get("taint", [])]
    credentials, required, declared_env = [], [], set()
    for f in files:
        facts = f.get("facts", {})
        credentials += [{"file": f["path"], **c} for c in facts.get("credentials", [])]
        required += [{"file": f["path"], **r} for r in facts.get("env_required", [])]
        if f["language"] in ("dotenv", "dotenv_example"):
            declared_env.update(facts.get("keys", []))

    def is_test(path):
        base = path.rsplit("/", 1)[-1]
        return base.startswith("test_") or base.endswith("_test.py") or path.startswith("tests/") or "/tests/" in path
    tests = {}
    for a, b in edges:
        if is_test(a) and not is_test(b):
            tests.setdefault(b, []).append(a)
    untested = sorted(f["path"] for f in python if not is_test(f["path"]) and not f["path"].endswith("__init__.py")
                      and f["path"] not in tests)
    dead = [d for d in dead if not (is_test(d["path"]) and (d["symbol"].startswith("test") or d["symbol"].startswith("Test")))]
    by_path = {f["path"]: f["facts"] for f in python}
    imports_of = {}
    for a, b in sorted(edges):
        imports_of.setdefault(a, []).append(b)
    completeness = []
    for route in routes:
        handler_file = next((c for c in [route["file"]] + imports_of.get(route["file"], [])
                             if route["function"] in by_path.get(c, {}).get("functions", {})), route["file"])
        facts = by_path.get(handler_file, {})
        reach, frontier = set(), [(handler_file, route["function"])]
        while frontier and len(reach) < 2000:
            node = frontier.pop()
            path, name = node
            info = by_path.get(path, {}).get("functions", {}).get(name)
            if node in reach or info is None:
                continue
            reach.add(node)
            for call in info["calls"]:
                for candidate in [path] + imports_of.get(path, []):
                    if call in by_path.get(candidate, {}).get("functions", {}):
                        frontier.append((candidate, call))
                        break
        infos = [by_path[p]["functions"][n] for p, n in reach]
        calls = {c for i in infos for c in i["calls"]}
        mutates = {m for i in infos for m in i["mutates"]}
        auth = "detected" if any(_AUTH.search(x) for i in infos for x in i["decorators"] + i["calls"]) else "not_detected"
        flags = []
        if any(i["function"] == route["function"] and i["kind"] in ("placeholder", "not_implemented")
               for i in facts.get("issues", [])):
            flags.append("unimplemented")
        elif set(route["methods"]) & {"POST", "PUT", "PATCH", "DELETE", "ANY"} - {"ANY"} and not calls & _PERSISTENCE:
            flags.append("in_memory_persistence" if mutates else "no_persistence")
        if route["file"] not in tests:
            flags.append("untested")
        completeness.append({"path": route["path"], "methods": route["methods"], "handler": route["function"],
                             "file": route["file"], "flags": flags, "auth": auth,
                             "evidence": {"persistence_calls": sorted(calls & _PERSISTENCE), "mutated_state": sorted(mutates)}})
    for f in files:
        facts = f.get("facts", {})
        if f["language"] == "python" and facts:
            f["facts"] = {"definitions": len(facts.get("definitions", [])), "imports": len(facts.get("imports", []))}
    states = {}
    for f in files:
        states[f["state"]] = states.get(f["state"], 0) + 1
    return {"schema": 1, "revision": repo.revision, "files": files,
            "graph": {"edges": sorted([a, b] for a, b in edges), "cycles": _cycles(set(modules.values()), edges),
                      "external": sorted(external), "external_classified": dict(sorted(classified.items()))},
            "missing_dependencies": [{"module": m, "files": sorted(fs)} for m, fs in sorted(missing.items())],
            "entry_points": entry_points, "dead_code_candidates": dead,
            "routes": sorted(routes, key=lambda r: (r["file"], r["line"], r["path"])),
            "completeness": sorted(completeness, key=lambda c: (c["file"], c["path"], c["methods"])),
            "completeness_summary": {"routes": len(completeness),
                                     "flagged": sum(1 for c in completeness if c["flags"]),
                                     "auth_not_detected": sum(1 for c in completeness if c["auth"] == "not_detected"),
                                     "frontend_analysis": "unsupported: no TypeScript/JavaScript parser available, so UI-to-API links are not analysed"},
            "environment": {k: sorted(set(v)) for k, v in sorted(environment.items())},
            "issues": sorted(issues, key=lambda i: (i["path"], i["line"], i["kind"])),
            "taint": sorted(taint, key=lambda x: (x["file"], x["line"], x["kind"])),
            "credentials": sorted(credentials, key=lambda c: (c["file"], c["line"], c["name"])),
            "configuration": {"declared": sorted(declared_env),
                              "required_without_default": sorted(({**r, "declared": r["name"] in declared_env} for r in required),
                                                                 key=lambda r: (r["file"], r["line"], r["name"]))},
            "tests": {k: sorted(v) for k, v in sorted(tests.items())}, "untested_sources": untested,
            "summary": {"states": dict(sorted(states.items())), "imports": total,
                        "resolution_rate": round(resolved / total, 4) if total else 1.0},
            "limits": ["Static indexing only: no file is SEMANTICALLY_REVIEWED or RUNTIME_VERIFIED.",
                       "Dynamic imports, runtime attribute access and reflection are not resolved.",
                       "Dead-code candidates may be used through dynamic access or external consumers."]}
