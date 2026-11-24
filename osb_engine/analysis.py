"""Conservative static Python and manifest intelligence, not semantic proof."""
import ast
import json
from pathlib import PurePosixPath
import sys

VERSION = '2.0-python-'+str(sys.version_info.major)+'.'+str(sys.version_info.minor)


def dotted(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted(node.value)
        return base + '.' + node.attr if base else None
    return None


def result():
    return {'symbols': [], 'imports': [], 'calls': [], 'findings': [], 'facts': {}}


class PythonVisitor(ast.NodeVisitor):
    def __init__(self):
        self.out = result()
        self.scope = []

    def finding(self, rule, node, explanation):
        self.out['findings'].append({'rule': rule, 'line': node.lineno,
                                     'state': 'candidate', 'explanation': explanation})

    def definition(self, node, kind):
        name = '.'.join(self.scope + [node.name])
        self.out['symbols'].append({'name': name, 'kind': kind, 'line': node.lineno,
                                    'end': node.end_lineno})
        if kind != 'class':
            body = node.body[:]
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
                body.pop(0)
            if len(body) == 1:
                stmt = body[0]
                raised = stmt.exc if isinstance(stmt, ast.Raise) else None
                raised = raised.func if isinstance(raised, ast.Call) else raised
                if isinstance(stmt, ast.Pass) or isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant) and stmt.value.value is Ellipsis or dotted(raised) == 'NotImplementedError':
                    self.finding('python.placeholder_body', stmt, 'Placeholder; abstract or intentional stubs require review.')
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()

    def visit_FunctionDef(self, node):
        self.definition(node, 'function')

    def visit_AsyncFunctionDef(self, node):
        self.definition(node, 'async_function')

    def visit_ClassDef(self, node):
        self.definition(node, 'class')

    def visit_Import(self, node):
        for alias in node.names:
            self.out['imports'].append({'module': alias.name, 'name': None, 'alias': alias.asname, 'level': 0, 'line': node.lineno})

    def visit_ImportFrom(self, node):
        for alias in node.names:
            self.out['imports'].append({'module': node.module or '', 'name': alias.name, 'alias': alias.asname, 'level': node.level, 'line': node.lineno})

    def visit_Call(self, node):
        target = dotted(node.func)
        self.out['calls'].append({'caller': '.'.join(self.scope) or '<module>', 'target': target, 'line': node.lineno, 'resolution': 'unresolved'})
        if target in ('eval', 'exec', 'pickle.loads', 'pickle.load', 'yaml.load'):
            self.finding('python.unsafe_operation', node, 'Review trust boundary and input provenance; name match alone is not a vulnerability.')
        if any(x.arg == 'shell' and isinstance(x.value, ast.Constant) and x.value.value is True for x in node.keywords):
            self.finding('python.shell_execution', node, 'Review shell command composition and untrusted input.')
        if any(x.arg == 'verify' and isinstance(x.value, ast.Constant) and x.value.value is False for x in node.keywords):
            self.finding('python.disabled_verification', node, 'Review whether TLS or other verification has been disabled.')
        self.generic_visit(node)

    def visit_ExceptHandler(self, node):
        if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
            self.finding('python.swallowed_exception', node, 'Confirm failure handling is intentional and observable.')
        self.generic_visit(node)


def python_source(raw):
    visitor = PythonVisitor()
    try:
        tree = ast.parse(raw)
        visitor.visit(tree)
    except (SyntaxError, ValueError, RecursionError) as exc:
        out = result()
        out['findings'].append({'rule': 'python.parse_error', 'line': getattr(exc, 'lineno', None) or 1,
                                'state': 'candidate', 'explanation': 'Parser could not analyse this source.'})
        return 'parse_blocked', out
    return 'analysed', visitor.out


def manifest(raw):
    out = result()
    try:
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError('object required')
        scripts = data.get('scripts', {})
        deps = {}
        if not isinstance(scripts, dict) or any(not isinstance(v, str) for v in scripts.values()):
            raise ValueError('invalid scripts')
        for group in ('dependencies', 'devDependencies', 'optionalDependencies'):
            items = data.get(group, {})
            if not isinstance(items, dict) or any(not isinstance(v, str) for v in items.values()):
                raise ValueError('invalid dependencies')
            deps.update(items)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        out['findings'].append({'rule': 'manifest.invalid', 'line': 1, 'state': 'candidate', 'explanation': 'Manifest could not be interpreted.'})
        return 'parse_blocked', out
    # Never include script bodies or dependency URLs (may contain credentials).
    out['facts'] = {'scripts': sorted(k for k,v in scripts.items() if v.strip()), 'dependencies': sorted(deps)}
    for name in ('build', 'test', 'lint'):
        if name not in out['facts']['scripts']:
            out['findings'].append({'rule': 'manifest.missing_'+name, 'line': 1, 'state': 'candidate', 'explanation': 'Check inherited workspace and CI commands before classifying as missing.'})
    return 'analysed', out


def language(path):
    if PurePosixPath(path).name == 'package.json':
        return 'node_manifest'
    if path.endswith('.py'):
        return 'python'
    return None


def analyse(kind, raw):
    return python_source(raw) if kind == 'python' else manifest(raw)


def graph(files):
    """Resolve unambiguous Python import modules; calls remain syntactic references."""
    modules = {}
    for f in files:
        if f['language'] == 'python':
            path = f['path']
            name = path[:-3].replace('/', '.')
            if name.endswith('.__init__'):
                name = name[:-9]
            modules.setdefault(name, []).append(path)
    edges = []
    for f in files:
        if f['language'] != 'python' or 'analysis' not in f:
            continue
        own = f['path'][:-3].replace('/', '.')
        package = own.split('.')[:-1]
        # __init__.py is analysed in its package, as are ordinary module files.
        for imp in f['analysis']['imports']:
            level = imp['level']
            if level and level > len(package):
                candidates = []
            else:
                base = '.'.join(package[:len(package)-level+1]) if level else ''
                module = '.'.join(x for x in (base, imp['module']) if x)
                sub = '.'.join(x for x in (module, imp['name']) if x)
                candidates = modules.get(sub, []) or modules.get(module, [])
            edges.append({'from': f['path'], 'to': candidates[0] if len(candidates)==1 else None,
                          'import': imp, 'resolution': 'syntactic_local' if len(candidates)==1 else 'unresolved'})
    return edges
