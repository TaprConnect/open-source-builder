"""Analyse untrusted repository blobs in isolated, resource-limited children (S03-001).

Each cache-missing blob is analysed in its own child, so a child compromised by one
hostile file can only influence that file's result. Blob bytes go in on stdin and
results come back as JSON on stdout, bounded by run_isolated. Results are validated
against the analyser's schema before use or caching. A global wall-clock budget
bounds the total cost; files not analysed in time are reported as analysis_failed.
"""
import base64
import concurrent.futures
import json
import os
import tempfile
import time
from pathlib import Path

from . import analysis
from .isolation import available, run_isolated

_ENTRY = b"""import base64, json, sys
sys.path.insert(0, "/inputs")
import analysis
request = json.loads(sys.stdin.buffer.read())
results = {}
for key, kind, data in request["items"]:
    results[key] = analysis.analyse(kind, base64.b64decode(data), *([key] if getattr(analysis, "PATH_AWARE", False) else []))
sys.stdout.write(json.dumps({"version": analysis.VERSION, "results": results}))
"""
_MAX_RESULT = 8 * 1024 * 1024
_MAX_ITEMS = 100000
_STATUSES = ("analysed", "parse_blocked")
_MAX_TEXT = 4096
_TEXT, _OPTIONAL_TEXT, _COUNT = "text", "optional text", "count"
_SCHEMAS = {
    "symbols": {"name": _TEXT, "kind": _TEXT, "line": _COUNT, "end": _COUNT},
    "imports": {"module": _TEXT, "name": _OPTIONAL_TEXT, "alias": _OPTIONAL_TEXT, "level": _COUNT, "line": _COUNT},
    "calls": {"caller": _TEXT, "target": _OPTIONAL_TEXT, "line": _COUNT, "resolution": ("unresolved",)},
    "findings": {"rule": _TEXT, "line": _COUNT, "state": ("candidate",), "explanation": _TEXT},
}


def _field(value, rule):
    if rule == _COUNT:
        return type(value) is int and 0 <= value <= 10 ** 9
    if rule == _OPTIONAL_TEXT and value is None:
        return True
    if rule in (_TEXT, _OPTIONAL_TEXT):
        return isinstance(value, str) and len(value) <= _MAX_TEXT
    return value in rule


def _texts(values):
    return (isinstance(values, list) and len(values) <= _MAX_ITEMS
            and all(isinstance(v, str) and len(v) <= _MAX_TEXT for v in values))


def _valid(value):
    """Element-level schema check of one analysis result produced by an untrusted child."""
    if not (isinstance(value, list) and len(value) == 2 and value[0] in _STATUSES):
        return False
    body = value[1]
    if not isinstance(body, dict) or set(body) != set(_SCHEMAS) | {"facts"}:
        return False
    facts = body["facts"]
    if not (facts == {} or isinstance(facts, dict) and set(facts) == {"scripts", "dependencies"}
            and _texts(facts["scripts"]) and _texts(facts["dependencies"])):
        return False
    for name, schema in _SCHEMAS.items():
        items = body[name]
        if not isinstance(items, list) or len(items) > _MAX_ITEMS:
            return False
        for item in items:
            if not isinstance(item, dict) or set(item) != set(schema):
                return False
            if not all(_field(item[key], rule) for key, rule in schema.items()):
                return False
    return True


def isolated_map(root, module, function, validator, cpu_seconds=10, memory_mib=512, timeout=120,
                 budget_seconds=600, workers=4):
    """Return run(items) -> {key: result or None}: module.function(kind, bytes) applied to each
    (key, kind, bytes) item in its own isolated child; results must pass validator."""
    if not available():
        raise ValueError("isolation unavailable on this host")
    if not (1 <= cpu_seconds <= 600 and 32 <= memory_mib <= 16384 and 1 <= budget_seconds <= 86400
            and 1 <= workers <= 16):
        raise ValueError("analysis limits out of range")
    source = Path(module.__file__).read_bytes()
    name = module.__name__.rsplit(".", 1)[-1]
    entry = (_ENTRY.replace(b"import analysis", b"import " + name.encode() + b" as analysis")
             .replace(b"analysis.analyse(", b"analysis." + function.encode() + b"("))

    def run_one(item, deadline):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        key = item[0]
        with tempfile.TemporaryDirectory() as tmp:
            inputs = {}
            companions = [(Path(m.__file__).name, Path(m.__file__).read_bytes()) for m in getattr(module, "COMPANIONS", ())]
            for filename, data in [("entry.py", entry), (name + ".py", source)] + companions:
                inputs[filename] = os.path.join(tmp, filename)
                with open(inputs[filename], "wb") as handle:
                    handle.write(data)
            payload = json.dumps({"items": [[key, item[1], base64.b64encode(item[2]).decode("ascii")]]}).encode()
            code, out, _ = run_isolated(root, ["python3", "-I", "-B", "/inputs/entry.py"], inputs,
                                        max(1, min(timeout, remaining)), {"PYTHONDONTWRITEBYTECODE": "1"},
                                        payload, limits=(cpu_seconds, memory_mib), max_output=_MAX_RESULT)
        if code != 0:
            return None
        try:
            document = json.loads(out)
        except ValueError:
            return None
        if not isinstance(document, dict) or document.get("version") != module.VERSION:
            raise ValueError("isolated child version differs from the supervisor's module")
        results = document.get("results")
        if not isinstance(results, dict) or set(results) != {key} or not validator(results[key]):
            return None
        value = results[key]
        return tuple(value) if isinstance(value, list) else value

    def run_all(items):
        deadline = time.monotonic() + budget_seconds
        with concurrent.futures.ThreadPoolExecutor(workers) as pool:
            futures = {item[0]: pool.submit(run_one, item, deadline) for item in items}
            return {key: future.result() for key, future in futures.items()}

    return run_all


def isolated_analyser(root, cpu_seconds=10, memory_mib=512, timeout=120, budget_seconds=600, workers=4):
    """Return analyse(items) -> {key: (status, analysis) or None} for (key, kind, bytes) items."""
    return isolated_map(root, analysis, "analyse", _valid, cpu_seconds, memory_mib, timeout, budget_seconds, workers)
