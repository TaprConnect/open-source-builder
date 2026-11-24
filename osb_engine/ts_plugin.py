"""TypeScript/JavaScript facts from a real parser (tree-sitter), in the shared plug-in schema (S05-009).

The parser is an optional dependency (``pip install open-source-builder[typescript]``).
Without it the plug-in returns an explicit unsupported state; it never falls back to
regular expressions. Traversal is iterative and bounded by a node budget, so hostile
nesting cannot exhaust the Python stack.
"""
import re

_LIMIT = 2000
NODE_BUDGET = 2_000_000
HTTP = {"get": "GET", "post": "POST", "put": "PUT", "patch": "PATCH", "delete": "DELETE", "all": "ANY"}
NEXT_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
_NOT_IMPLEMENTED = re.compile(r"not\s*implemented|todo|unimplemented", re.I)
_LOGGING = {"log", "error", "warn", "info", "debug", "exception", "trace", "fatal", "captureException"}
_SQL_SINKS = {"query", "execute", "raw", "$queryRawUnsafe", "$executeRawUnsafe", "exec", "run", "all", "get", "prepare"}
_SHELL_SINKS = {"exec", "execSync", "spawn", "spawnSync", "execFile", "execFileSync"}
_FS_SINKS = {"readFile", "readFileSync", "createReadStream", "sendFile", "writeFile", "writeFileSync", "unlink", "unlinkSync"}
_REQUEST_ROOTS = {"req", "request", "ctx", "event"}
_MUTATORS = {"push", "set", "delete", "splice", "unshift", "pop", "shift", "clear", "add"}
_parsers = {}


def _parser(path):
    tsx = path.endswith((".tsx", ".jsx"))
    key = "tsx" if tsx else ("ts" if path.endswith(".ts") else "js")
    if key not in _parsers:
        import tree_sitter
        if key == "js":
            import tree_sitter_javascript as grammar
            language = grammar.language()
        else:
            import tree_sitter_typescript as grammar
            language = grammar.language_tsx() if tsx else grammar.language_typescript()
        _parsers[key] = tree_sitter.Parser(tree_sitter.Language(language))
    return _parsers[key]


def available():
    try:
        import tree_sitter  # noqa: F401
        import tree_sitter_typescript  # noqa: F401
        import tree_sitter_javascript  # noqa: F401
        return True
    except ImportError:
        return False


def _text(node, source):
    return source[node.start_byte:node.end_byte].decode("utf-8", "replace")


def _string(node, source):
    if node is None:
        return None
    if node.type == "string":
        return _text(node, source)[1:-1]
    if node.type == "template_string" and not any(c.type == "template_substitution" for c in node.children):
        return _text(node, source)[1:-1]
    return None


def _callee(node, source):
    """Dotted name of a call target, or None when it is computed."""
    if node.type in ("identifier", "property_identifier", "private_property_identifier"):
        return _text(node, source)
    if node.type == "member_expression":
        obj, prop = node.child_by_field_name("object"), node.child_by_field_name("property")
        base = _callee(obj, source) if obj is not None else None
        name = _text(prop, source) if prop is not None else None
        if name is None:
            return None
        return f"{base}.{name}" if base else name
    if node.type == "call_expression":
        return _callee(node.child_by_field_name("function"), source)
    return None


def _walk(root, budget):
    stack, seen = [root], 0
    while stack:
        node = stack.pop()
        seen += 1
        if seen > budget:
            raise OverflowError("node budget exceeded")
        yield node
        stack.extend(reversed(node.children))


def _route_path_from_file(path):
    """Next.js App Router (app/**/route.ts) and Pages API (pages/api/**) URL paths."""
    parts = path.split("/")
    for marker in ("app",):
        if marker in parts and parts[-1].rsplit(".", 1)[0] == "route":
            segs = [p for p in parts[parts.index(marker) + 1:-1] if not (p.startswith("(") and p.endswith(")"))]
            return "/" + "/".join(segs), "app"
    if "pages" in parts and "api" in parts:
        i = parts.index("api")
        if i == parts.index("pages") + 1:
            leaf = parts[-1].rsplit(".", 1)[0]
            segs = parts[i:-1] + ([] if leaf == "index" else [leaf])
            return "/" + "/".join(segs), "pages"
    return None, None


def _request_derived(node, source, budget):
    for n in _walk(node, budget):
        if n.type == "member_expression":
            name = _callee(n, source) or ""
            if name.split(".", 1)[0] in _REQUEST_ROOTS and "." in name:
                return True
    return False


def _dynamic_string(node):
    return node.type == "template_string" and any(c.type == "template_substitution" for c in node.children) \
        or node.type == "binary_expression"


def _inside_function(node, func_types):
    parent = node.parent
    while parent is not None:
        if parent.type in func_types:
            return True
        parent = parent.parent
    return False


def extract(path, data):
    if not available():
        return {"state": "INDEXED", "reason": "unsupported: tree-sitter TypeScript/JavaScript parser not installed"}
    try:
        source = data if isinstance(data, bytes) else bytes(data)
        source.decode("utf-8")
    except UnicodeDecodeError as exc:
        return {"state": "INDEXED", "error": f"undecodable source: {exc}"[:300]}
    try:
        tree = _parser(path).parse(source)
        return _facts(path, tree.root_node, source)
    except OverflowError as exc:
        return {"state": "INDEXED", "error": f"analysis bounded: {exc}"}
    except RecursionError:
        return {"state": "INDEXED", "error": "analysis bounded: recursion limit"}


def _facts(path, root, source):
    budget = NODE_BUDGET
    definitions, imports, routes, env, env_required, issues, taint, fetches = [], [], [], set(), [], [], [], []
    exports, references, functions, a11y = set(), set(), {}, []
    module_state = set()
    for child in root.children:  # module-level mutable containers: in-memory persistence candidates
        decl = child.child_by_field_name("declaration") if child.type == "export_statement" else child
        if decl is not None and decl.type in ("lexical_declaration", "variable_declaration"):
            for d in decl.children:
                if d.type == "variable_declarator":
                    name, value = d.child_by_field_name("name"), d.child_by_field_name("value")
                    if name is not None and value is not None and (
                            value.type in ("array", "object") or value.type == "new_expression"
                            and _text(value, source).split("(")[0].replace("new", "").strip() in ("Map", "Set", "Array")):
                        module_state.add(_text(name, source))
    next_path, router_kind = _route_path_from_file(path)

    def function_name(node):
        name = node.child_by_field_name("name")
        if name is not None:
            return _text(name, source)
        parent = node.parent
        if parent is not None and parent.type == "variable_declarator":
            ident = parent.child_by_field_name("name")
            return _text(ident, source) if ident is not None else None
        if parent is not None and parent.type in ("pair", "method_definition"):
            key = parent.child_by_field_name("key") or parent.child_by_field_name("name")
            return _text(key, source) if key is not None else None
        return f"<anonymous@{node.start_point[0] + 1}>"

    def analyse_function(node, name, decorators=()):
        body = node.child_by_field_name("body")
        info = functions.setdefault(name, {"calls": [], "mutates": [], "decorators": list(decorators)})
        if body is None:
            return
        statements = [c for c in body.named_children if c.type != "comment"] if body.type == "statement_block" else [body]
        if body.type == "statement_block" and not statements:
            issues.append({"kind": "placeholder", "function": name, "line": node.start_point[0] + 1})
        for n in _walk(body, budget):
            if n.type == "throw_statement" and _NOT_IMPLEMENTED.search(_text(n, source)):
                issues.append({"kind": "not_implemented", "function": name, "line": n.start_point[0] + 1})
            elif n.type == "call_expression":
                target = _callee(n.child_by_field_name("function"), source)
                if target:
                    info["calls"].append(target.rsplit(".", 1)[-1])
                    head, _, last = target.rpartition(".")
                    if last in _MUTATORS and head in module_state:
                        info["mutates"].append(head)
                    args = n.child_by_field_name("arguments")
                    first = args.named_children[0] if args is not None and args.named_children else None
                    if first is not None:
                        if last in _SQL_SINKS and _dynamic_string(first) and _request_derived(first, source, budget):
                            taint.append({"kind": "sql_injection", "function": name, "line": n.start_point[0] + 1})
                        elif last in _SHELL_SINKS and _request_derived(args, source, budget):
                            taint.append({"kind": "command_injection", "function": name, "line": n.start_point[0] + 1})
                        elif last in _FS_SINKS and _request_derived(first, source, budget):
                            taint.append({"kind": "path_traversal", "function": name, "line": n.start_point[0] + 1})
                    if target in ("eval", "Function") and args is not None and _request_derived(args, source, budget):
                        taint.append({"kind": "code_injection", "function": name, "line": n.start_point[0] + 1})
            elif n.type == "assignment_expression":
                left = n.child_by_field_name("left")
                target = _callee(left, source) if left is not None else None
                if target and target.split(".", 1)[0] in module_state:
                    info["mutates"].append(target.split(".", 1)[0])
            elif n.type == "catch_clause":
                block = n.child_by_field_name("body")
                inner = [c for c in block.named_children if c.type != "comment"] if block is not None else []
                if not inner:
                    issues.append({"kind": "swallowed_exception", "function": name, "line": n.start_point[0] + 1})
                elif not any(m.type == "throw_statement" or m.type == "call_expression" and (
                        (_callee(m.child_by_field_name("function"), source) or "").rsplit(".", 1)[-1] in _LOGGING)
                        for m in _walk(block, budget)):
                    issues.append({"kind": "unlogged_broad_handler", "function": name, "line": n.start_point[0] + 1})
        info["calls"] = sorted(set(info["calls"]))[:500]
        info["mutates"] = sorted(set(info["mutates"]))[:100]

    func_types = ("function_declaration", "function_expression", "arrow_function", "method_definition",
                  "generator_function_declaration", "function")
    for node in _walk(root, budget):
        kind = node.type
        line = node.start_point[0] + 1
        if kind == "import_statement":
            src = _string(node.child_by_field_name("source"), source)
            if src:
                names = sorted({_text(n, source) for n in _walk(node, budget) if n.type == "identifier"})[:_LIMIT]
                imports.append({"module": src, "names": names, "level": 0, "line": line})
        elif kind == "call_expression":
            fn = node.child_by_field_name("function")
            target = _callee(fn, source) if fn is not None else None
            args = node.child_by_field_name("arguments")
            argv = args.named_children if args is not None else []
            if target == "require" and argv and _string(argv[0], source):
                imports.append({"module": _string(argv[0], source), "names": [], "level": 0, "line": line})
            elif target and "." in target and target.rsplit(".", 1)[-1] in HTTP and argv \
                    and (_string(argv[0], source) or "").startswith("/"):
                method = HTTP[target.rsplit(".", 1)[-1]]
                handler = argv[-1]
                middleware = [_callee(a, source) or "" for a in argv[1:-1]]
                middleware = [m for m in middleware if m]
                if handler.type in func_types:
                    name = f"<handler {method} {_string(argv[0], source)}@{line}>"
                    analyse_function(handler, name, middleware)
                else:
                    name = _callee(handler, source) or f"<handler@{line}>"
                    functions.setdefault(name, {"calls": [], "mutates": [], "decorators": []})["decorators"] += middleware
                routes.append({"path": _string(argv[0], source), "methods": [method], "function": name, "line": line})
            elif target in ("fetch", "axios", "axios.get", "axios.post", "axios.put", "axios.patch", "axios.delete",
                            "api.get", "api.post", "api.put", "api.patch", "api.delete") and argv:
                url = _string(argv[0], source)
                if url is None and argv[0].type == "template_string":
                    url = re.sub(r"\$\{[^}]*\}", ":param", _text(argv[0], source)[1:-1])
                if url and url.startswith("/"):
                    method = target.rsplit(".", 1)[-1].upper() if "." in target else "GET"
                    if target == "fetch" and len(argv) > 1:
                        m = re.search(r"method\s*:\s*['\"](\w+)['\"]", _text(argv[1], source))
                        method = m.group(1).upper() if m else "GET"
                    fetches.append({"path": url.split("?", 1)[0], "method": method, "line": line})
        elif kind == "member_expression":
            name = _callee(node, source) or ""
            if name.startswith("process.env.") and name.count(".") == 2:
                var = name.split(".")[2]
                env.add(var)
                parent = node.parent
                defaulted = parent is not None and parent.type == "binary_expression" and any(
                    c.type in ("??", "||") for c in parent.children)
                if not defaulted:
                    env_required.append({"name": var, "line": line})
        elif kind in ("function_declaration", "generator_function_declaration"):
            name = function_name(node)
            definitions.append({"name": name, "kind": "function", "line": line})
            exported = node.parent is not None and node.parent.type == "export_statement"
            if exported:
                exports.add(name)
            if next_path and router_kind == "app" and exported and name in NEXT_METHODS:
                routes.append({"path": next_path, "methods": [name], "function": name, "line": line})
            analyse_function(node, name)
        elif kind in ("arrow_function", "function_expression") and node.parent is not None \
                and node.parent.type == "variable_declarator":
            name = function_name(node)
            definitions.append({"name": name, "kind": "function", "line": line})
            analyse_function(node, name)
        elif kind == "method_definition":
            name = function_name(node)
            decorators = [_text(d, source).lstrip("@").split("(")[0] for d in node.children if d.type == "decorator"]
            prev = node.prev_named_sibling
            while prev is not None and prev.type == "decorator":
                decorators.append(_text(prev, source).lstrip("@").split("(")[0])
                prev = prev.prev_named_sibling
            definitions.append({"name": name, "kind": "function", "line": line})
            analyse_function(node, name, decorators)
        elif kind in ("class_declaration", "abstract_class_declaration"):
            definitions.append({"name": function_name(node), "kind": "class", "line": line})
        elif kind == "export_statement":
            if any(c.type == "default" for c in node.children):
                exports.add("default")
                decl = node.child_by_field_name("declaration") or next(
                    (c for c in node.named_children if c.type in func_types), None)
                if next_path and router_kind == "pages" and decl is not None:
                    name = function_name(decl) if decl.type in func_types else "default"
                    routes.append({"path": next_path, "methods": ["ANY"], "function": name, "line": line})
            for spec in (n for n in _walk(node, budget) if n.type == "export_specifier"):
                exports.add(_text(spec.child_by_field_name("name"), source))
            decl = node.child_by_field_name("declaration")
            if decl is not None and decl.type in ("lexical_declaration", "variable_declaration"):
                for d in decl.named_children:
                    ident = d.child_by_field_name("name") if d.type == "variable_declarator" else None
                    if ident is not None:
                        exports.add(_text(ident, source))
                        value = d.child_by_field_name("value")
                        if next_path and router_kind == "app" and _text(ident, source) in NEXT_METHODS \
                                and value is not None and value.type in func_types:
                            routes.append({"path": next_path, "methods": [_text(ident, source)],
                                           "function": _text(ident, source), "line": line})
        elif kind in ("jsx_opening_element", "jsx_self_closing_element"):
            tag = node.child_by_field_name("name")
            tag = _text(tag, source) if tag is not None else ""
            attrs = {_text(a.named_children[0], source) for a in node.named_children
                     if a.type == "jsx_attribute" and a.named_children}
            if tag == "img" and "alt" not in attrs and not any(a.type == "jsx_expression" for a in node.named_children):
                a11y.append({"kind": "img_missing_alt", "line": line})
            elif tag in ("div", "span", "li", "td", "p") and "onClick" in attrs \
                    and not attrs & {"role", "onKeyDown", "onKeyUp", "onKeyPress", "tabIndex"}:
                a11y.append({"kind": "click_without_keyboard", "line": line})
        elif kind == "catch_clause" and not _inside_function(node, func_types):
            block = node.child_by_field_name("body")
            if block is not None and not [c for c in block.named_children if c.type != "comment"]:
                issues.append({"kind": "swallowed_exception", "function": "<module>", "line": line})
        elif kind == "identifier" and len(references) < 50000:
            references.add(_text(node, source))
    facts = {"definitions": definitions[:_LIMIT], "imports": imports[:_LIMIT], "routes": routes[:_LIMIT],
             "env": sorted(env)[:_LIMIT], "env_required": env_required[:_LIMIT], "issues": issues[:_LIMIT],
             "taint": taint[:_LIMIT], "fetches": fetches[:_LIMIT], "a11y": a11y[:_LIMIT], "exports": sorted(exports)[:_LIMIT],
             "references": sorted(references)[:20000],
             "functions": dict(list(sorted(functions.items()))[:_LIMIT])}
    state = "SYMBOL_INDEXED" if not root.has_error else "PARSED"
    result = {"state": state, "facts": facts}
    if root.has_error:
        result["reason"] = "partial: the parser recovered from syntax errors; facts may be incomplete"
    return result
