"""Runtime verification adapters (S05-005): discover project commands and run them isolated.

Every command runs through isolation.run_isolated (bubblewrap, no network, cleared environment,
CPU/memory limits, bounded output) against the pinned checkout. Nothing here installs
dependencies or reaches the network, so commands that need them are reported blocked.

Receipts record what was observed, never a verdict on the product: a repository's own tests
are repository-controlled, so their success is supporting evidence ("repository_controlled")
unless the operator asserted a trusted target. Only owner-frozen external acceptance (the
kernel's verify) counts as trusted completion authority.
"""
import hashlib
import json
import re
import shutil
import time

from .isolation import available as isolation_available, run_isolated

ADAPTERS = ("build", "unit_tests", "integration_tests", "typecheck", "lint", "api_behaviour", "authorization",
            "persistence", "configuration", "migrations", "supply_chain", "error_handling", "recovery",
            "accessibility", "resources")
# Adapters whose evidence must come from owner-frozen external acceptance, not repository commands.
EXTERNAL_ONLY = {"api_behaviour": "drive the API through osb_accept and assert status codes and bodies",
                 "authorization": "assert anonymous and wrong-user requests are denied and the owner succeeds",
                 "persistence": "write a record, restart the process, read it back",
                 "recovery": "interrupt an operation and assert it resumes or rolls back exactly once",
                 "accessibility": "drive the UI in a browser with keyboard only and an accessibility scanner"}
_MAX_OUTPUT = 256 * 1024
# The checkout is mounted read-only, so compile in memory instead of writing __pycache__.
_COMPILE_ALL = ("import os,sys\nbad=0\nfor d,_,fs in os.walk('.'):\n if '/.git' in d: continue\n for f in fs:\n"
                "  if f.endswith('.py'):\n   p=os.path.join(d,f)\n   try: compile(open(p,'rb').read(),p,'exec')\n"
                "   except (SyntaxError,ValueError) as e: bad+=1; print('FAIL',p,e)\nprint('compiled; failures',bad)\n"
                "sys.exit(1 if bad else 0)")
_TESTS_RAN = re.compile(rb"Ran (\d+) tests?|(\d+) passed|Tests:\s+(\d+) passed|# pass (\d+)")


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _manifest(repo, path):
    blob = next((b for b in repo.inventory() if b.path == path and b.kind == "blob"), None)
    if blob is None or blob.size > 1024 * 1024:
        return None
    try:
        value = json.loads(repo.read(blob))
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


def discover(repo, index):
    """Return {adapter: [command spec]} for commands the repository itself declares or implies."""
    paths = {f["path"] for f in index["files"]}
    languages = {f["language"] for f in index["files"]}
    declared = {d.lower() for f in index["files"] for d in f.get("facts", {}).get("dependencies", [])
                if isinstance(f.get("facts"), dict) and isinstance(f["facts"].get("dependencies"), list)}
    found = {}

    def add(adapter, argv, source, needs=()):
        found.setdefault(adapter, []).append({"argv": argv, "source": source, "needs": list(needs)})
    if "python" in languages:
        add("build", ["python3", "-I", "-c", _COMPILE_ALL], "python sources (in-memory compile)")
        tests = [p for p in paths if p.endswith(".py") and (p.rsplit("/", 1)[-1].startswith("test_") or "/tests/" in "/" + p)]
        if tests:
            if "pytest" in declared:
                add("unit_tests", ["python3", "-m", "pytest", "-q", "-p", "no:cacheprovider"], "pytest declared", ["pytest"])
            else:
                add("unit_tests", ["python3", "-m", "unittest", "discover", "-v"], "unittest discovery")
        if "mypy" in declared:
            add("typecheck", ["python3", "-m", "mypy", "."], "mypy declared", ["mypy"])
        for tool in ("ruff", "flake8"):
            if tool in declared:
                add("lint", ["python3", "-m", tool] + (["check", "."] if tool == "ruff" else ["."]), f"{tool} declared", [tool])
        if "alembic.ini" in paths:
            add("migrations", ["python3", "-m", "alembic", "upgrade", "head", "--sql"], "alembic.ini", ["alembic"])
        if "manage.py" in paths:
            add("migrations", ["python3", "manage.py", "makemigrations", "--check", "--dry-run"], "django manage.py", ["django"])
    for path in sorted(p for p in paths if p.rsplit("/", 1)[-1] == "package.json"):
        package = _manifest(repo, path) or {}
        scripts = package.get("scripts") if isinstance(package.get("scripts"), dict) else {}
        prefix = path.rsplit("/", 1)[0] if "/" in path else "."
        for name, adapter in (("build", "build"), ("test", "unit_tests"), ("test:unit", "unit_tests"),
                              ("test:integration", "integration_tests"), ("test:e2e", "integration_tests"),
                              ("typecheck", "typecheck"), ("lint", "lint")):
            if isinstance(scripts.get(name), str) and scripts[name].strip():
                add(adapter, ["npm", "--prefix", prefix, "run", "--silent", name], f"{path} scripts.{name}",
                    ["node", "node_modules"])
        if "typecheck" not in found and f"{prefix}/tsconfig.json".lstrip("./") in paths | {"tsconfig.json"} \
                and "typescript" in declared:
            add("typecheck", ["npx", "--no-install", "tsc", "--noEmit", "-p", prefix], "tsconfig.json", ["node", "node_modules"])
    lockfiles = sorted(p for p in paths if p.rsplit("/", 1)[-1] in (
        "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "poetry.lock", "uv.lock", "Pipfile.lock", "requirements.txt"))
    return {"commands": found, "lockfiles": lockfiles}


def _blocked_reason(spec, repo):
    needs = set(spec["needs"])
    if "node" in needs and shutil.which("node") is None:
        return "node is not installed on this host"
    if "node" in needs and not str(shutil.which("node") or "").startswith(("/usr/", "/bin/")):
        return "node is outside /usr, so it is not visible inside the isolation sandbox"
    if "node_modules" in needs:
        return "dependencies are not installed (node_modules) and isolated runs have no network"
    python_deps = needs - {"node", "node_modules"}
    if python_deps:
        return f"python packages {sorted(python_deps)} are not installed in the sandbox interpreter"
    return None


def run(repo, index, adapters=None, trusted=False, timeout=300, cpu_seconds=120, memory_mib=1024):
    """Execute discovered commands; return receipts keyed by adapter. Fails closed without isolation."""
    plan = discover(repo, index)
    wanted = set(adapters or ADAPTERS)
    receipts = {}
    for adapter in ADAPTERS:
        if adapter not in wanted:
            continue
        if adapter in EXTERNAL_ONLY:
            receipts[adapter] = [{"adapter": adapter, "state": "not_performed", "trust": "none",
                                  "reason": "requires owner-frozen external acceptance: " + EXTERNAL_ONLY[adapter]}]
            continue
        if adapter == "supply_chain":
            third_party = [m for m, kind in index["graph"].get("external_classified", {}).items() if kind != "stdlib"]
            if not third_party:
                receipts[adapter] = [{"adapter": adapter, "state": "not_applicable", "trust": "static",
                                      "reason": "no third-party imports detected"}]
                continue
            receipts[adapter] = [{"adapter": adapter, "state": "blocked" if plan["lockfiles"] else "fail",
                                  "trust": "static", "lockfiles": plan["lockfiles"],
                                  "reason": "vulnerability databases need network access" if plan["lockfiles"]
                                  else "no lockfile or pinned requirements committed"}]
            continue
        if adapter in ("configuration", "error_handling"):
            receipts[adapter] = [{"adapter": adapter, "state": "not_performed", "trust": "static",
                                  "reason": "evaluated statically from the index; no runtime command"}]
            continue
        specs = plan["commands"].get(adapter if adapter != "resources" else "unit_tests", [])
        if not specs:
            receipts[adapter] = [{"adapter": adapter, "state": "unsupported", "trust": "none",
                                  "reason": "no command discovered for this adapter"}]
            continue
        receipts[adapter] = [_execute(repo, adapter, spec, trusted, timeout, cpu_seconds, memory_mib) for spec in specs]
    return {"revision": repo.revision, "isolation": isolation_available(), "receipts": receipts,
            "discovered": plan}


def _execute(repo, adapter, spec, trusted, timeout, cpu_seconds, memory_mib):
    base = {"adapter": adapter, "argv": spec["argv"], "source": spec["source"], "revision": repo.revision}
    if not isolation_available():
        return {**base, "state": "blocked", "trust": "none",
                "reason": "isolation unavailable: refusing to execute repository code (fail closed)"}
    reason = _blocked_reason(spec, repo)
    if reason:
        return {**base, "state": "blocked", "trust": "none", "reason": reason}
    started = time.monotonic()
    try:
        code, out, err = run_isolated(repo.root, spec["argv"], {}, timeout, {"PYTHONDONTWRITEBYTECODE": "1"},
                                      limits=(cpu_seconds, memory_mib), max_output=_MAX_OUTPUT)
    except (OSError, ValueError) as exc:
        return {**base, "state": "blocked", "trust": "none", "reason": f"sandbox error: {exc}"[:300]}
    elapsed = round(time.monotonic() - started, 3)
    combined = (out or b"") + (err or b"")
    counted = [int(g) for m in _TESTS_RAN.finditer(combined) for g in m.groups() if g]
    executed = max(counted) if counted else None
    if code is None:
        state = "blocked"
    elif code == 0 and adapter in ("unit_tests", "integration_tests", "resources") and not executed:
        state = "unknown"  # exit 0 but no evidence any test ran
    else:
        state = "pass" if code == 0 else "fail"
    return {**base, "state": state, "returncode": code, "seconds": elapsed, "tests_executed": executed,
            "output_sha256": _sha(combined), "output_tail": combined[-2000:].decode("utf-8", "replace"),
            "trust": "trusted_target" if trusted else "repository_controlled",
            "limits": {"cpu_seconds": cpu_seconds, "memory_mib": memory_mib, "timeout": timeout}}
