"""Analyse untrusted repository blobs in an isolated, resource-limited child (S03-001).

Blob bytes go to the child on stdin and results come back as JSON on stdout. The
child runs under the S02-010 isolation boundary (read-only checkout, no store, no
network, no writable host path) with prlimit CPU and address-space limits. A failed
batch is retried file by file so one hostile file cannot deny analysis of the rest.
"""
import base64
import json
import os
import tempfile
from pathlib import Path

from . import analysis
from .isolation import available, run_isolated

_ENTRY = b"""import base64, json, sys
sys.path.insert(0, "/inputs")
import analysis
request = json.loads(sys.stdin.buffer.read())
results = {}
for key, kind, data in request["items"]:
    results[key] = analysis.analyse(kind, base64.b64decode(data))
sys.stdout.write(json.dumps({"version": analysis.VERSION, "results": results}))
"""
_MAX_RESULT = 64 * 1024 * 1024


def _valid(value):
    return (isinstance(value, list) and len(value) == 2 and isinstance(value[0], str)
            and isinstance(value[1], dict) and isinstance(value[1].get("findings"), list))


def isolated_analyser(root, cpu_seconds=10, memory_mib=512, timeout=120):
    """Return analyse(items) -> {key: (status, analysis) or None} for (key, kind, bytes) items."""
    if not available():
        raise ValueError("isolation unavailable on this host")
    if not (1 <= cpu_seconds <= 600 and 32 <= memory_mib <= 16384):
        raise ValueError("analysis limits out of range")
    source = Path(analysis.__file__).read_bytes()

    def run(items):
        with tempfile.TemporaryDirectory() as tmp:
            inputs = {}
            for name, data in (("entry.py", _ENTRY), ("analysis.py", source)):
                inputs[name] = os.path.join(tmp, name)
                with open(inputs[name], "wb") as handle:
                    handle.write(data)
            payload = json.dumps({"items": [[k, kind, base64.b64encode(d).decode("ascii")]
                                            for k, kind, d in items]}).encode()
            code, out, _ = run_isolated(root, ["python3", "-I", "-B", "/inputs/entry.py"], inputs, timeout,
                                        {"PYTHONDONTWRITEBYTECODE": "1"}, payload,
                                        limits=(cpu_seconds, memory_mib), max_output=_MAX_RESULT)
        if code != 0:
            return None
        try:
            document = json.loads(out)
        except ValueError:
            return None
        if not isinstance(document, dict) or document.get("version") != analysis.VERSION:
            raise ValueError("isolated analyser version differs from the supervisor's analyser")
        results = document.get("results")
        if not isinstance(results, dict) or set(results) != {k for k, _, _ in items}:
            return None
        if not all(_valid(v) for v in results.values()):
            return None
        return {k: tuple(v) for k, v in results.items()}

    def analyse_batch(items):
        if not items:
            return {}
        results = run(items)
        if results is not None:
            return results
        single = {}
        for item in items:
            outcome = run([item])
            single[item[0]] = outcome[item[0]] if outcome else None
        return single

    return analyse_batch
