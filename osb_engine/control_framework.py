"""Executable engineering controls (E01): one framework over the I01 repository index.

Every catalogue control is declared with the same fields. Controls whose family the
index can genuinely check have a static evaluator; all others are reported as
unsupported. Static evaluation can find violations but never establishes a pass:
the best static outcome is no_static_violation.
"""
WRITES = {"POST", "PUT", "PATCH", "DELETE"}
FAMILIES = {"Identity": "security", "Tenancy": "security", "WebDefences": "security", "Secrets": "security",
            "Isolation": "security", "Persistence": "data", "Database": "data", "Cache": "data", "Retention": "data",
            "Removal": "data", "Backend": "backend", "Contracts": "backend", "Integration": "backend",
            "Webhook": "backend", "Frontend": "frontend", "Motion": "frontend", "Accessibility": "frontend",
            "UX": "frontend", "Reliability": "reliability", "Recovery": "reliability", "Concurrency": "reliability",
            "Load": "reliability", "Observability": "operations", "Operations": "operations", "Release": "operations",
            "Canary": "operations", "Infrastructure": "operations", "SupplyChain": "supply-chain", "Build": "build",
            "Quality": "testing", "Architecture": "architecture", "Configuration": "configuration"}
SEVERITY = {"Identity": "high", "WebDefences": "high", "Persistence": "high", "Backend": "high",
            "Reliability": "medium", "SupplyChain": "medium", "Quality": "medium", "Architecture": "low",
            "Secrets": "high", "Configuration": "medium", "Observability": "medium"}
REMEDIATION = {
    "Persistence": "Persist writes through the data layer (or document intentionally ephemeral state) and add an acceptance test that reads the record back after restart.",
    "Identity": "Require authentication and authorisation on write routes and add a denied-access test.",
    "Backend": "Implement the handler or remove the advertised route; add an acceptance test for the real behaviour.",
    "Reliability": "Handle the specific exception, log it and surface failure to the caller instead of swallowing it.",
    "SupplyChain": "Declare the dependency (pyproject or requirements) with a version constraint, or remove the import.",
    "Quality": "Add tests that exercise the route or module through its public entry point.",
    "WebDefences": "Use parameterised queries, argument lists without shell, path normalisation within an allowed root, and never evaluate input.",
    "Architecture": "Break the import cycle by extracting shared code or inverting the dependency.",
    "Secrets": "Remove the credential from source control, rotate it, and load it at runtime from the environment or a secret manager.",
    "Configuration": "Declare the variable in a committed example dotenv file and validate required settings at startup with a clear error that does not print values.",
    "Observability": "Log the exception with context (logger.exception) or re-raise it so failures are traceable.",
}


def _routes(index, writes_only=False):
    return [c for c in index.get("completeness", []) if not writes_only or set(c["methods"]) & WRITES]


def _python_sources(index):
    return [f for f in index["files"] if f["language"] == "python"]


def _persistence(index):
    write = _routes(index, True)
    hits = [{"file": c["file"], "route": f"{'/'.join(c['methods'])} {c['path']}", "detail": flag}
            for c in write for flag in c["flags"] if flag in ("no_persistence", "in_memory_persistence")]
    return bool(write), hits


def _identity(index):
    write = _routes(index, True)
    return bool(write), [{"file": c["file"], "route": f"{'/'.join(c['methods'])} {c['path']}",
                          "detail": "no authentication evidence"} for c in write if c["auth"] == "not_detected"]


def _backend(index):
    hits = [{"file": c["file"], "route": f"{'/'.join(c['methods'])} {c['path']}", "detail": "unimplemented handler"}
            for c in _routes(index) if "unimplemented" in c["flags"]]
    hits += [{"file": i["path"], "line": i["line"], "detail": f"{i['kind']} {i['function']}"}
             for i in index.get("issues", []) if i["kind"] in ("placeholder", "not_implemented")]
    return bool(_python_sources(index)), hits


def _reliability(index):
    return bool(_python_sources(index)), [{"file": i["path"], "line": i["line"], "detail": f"{i['kind']} in {i['function']}"}
                                          for i in index.get("issues", []) if i["kind"] in ("swallowed_exception", "bare_except")]


def _supply_chain(index):
    return bool(index["graph"].get("external")), [{"file": m["files"][0], "detail": f"undeclared dependency {m['module']}"}
                                                  for m in index.get("missing_dependencies", [])]


def _quality(index):
    hits = [{"file": c["file"], "route": f"{'/'.join(c['methods'])} {c['path']}", "detail": "route not tested"}
            for c in _routes(index) if "untested" in c["flags"]]
    hits += [{"file": path, "detail": "module imported by no test"} for path in index.get("untested_sources", [])]
    return bool(_python_sources(index)), hits


def _web_defences(index):
    return bool(_routes(index)), [{"file": t["file"], "line": t["line"], "detail": f"{t['kind']} in {t['function']}"}
                                  for t in index.get("taint", [])]


def _architecture(index):
    return bool(_python_sources(index)), [{"file": cycle[0], "detail": "import cycle: " + " -> ".join(cycle)}
                                          for cycle in index["graph"].get("cycles", [])]


def _secrets(index):
    applicable = any(f["language"] in ("python", "dotenv", "dotenv_example") for f in index["files"])
    return applicable, [{"file": c["file"], "line": c["line"], "name": c["name"],
                         "detail": "hard-coded credential literal" if c["kind"] == "literal" else "credential value committed in dotenv file"}
                        for c in index.get("credentials", [])]


def _configuration(index):
    return bool(index.get("environment")), [
        {"file": r["file"], "line": r["line"], "name": r["name"],
         "detail": "environment variable read without default and not declared in any committed dotenv file"}
        for r in index.get("configuration", {}).get("required_without_default", []) if not r["declared"]]


def _observability(index):
    return bool(_python_sources(index)), [{"file": i["path"], "line": i["line"], "function": i["function"],
                                           "detail": "broad exception handler neither logs nor re-raises"}
                                          for i in index.get("issues", []) if i["kind"] == "unlogged_broad_handler"]


EVALUATORS = {"Persistence": _persistence, "Identity": _identity, "Backend": _backend, "Reliability": _reliability,
              "SupplyChain": _supply_chain, "Quality": _quality, "WebDefences": _web_defences,
              "Architecture": _architecture, "Secrets": _secrets, "Configuration": _configuration,
              "Observability": _observability}


def evaluate_controls(rows, index):
    controls, summary = [], {}
    for row in rows:
        domain = row["domain"]
        evaluator = EVALUATORS.get(domain)
        control = {"id": f"E01-{domain}", "domain": domain, "family": FAMILIES.get(domain, "other"),
                   "applicability": row["activates_when"], "evidence": row["evidence"],
                   "required_outcome": row["required_outcome"],
                   "static_evaluator": f"index.{evaluator.__name__.lstrip('_')}" if evaluator else None,
                   "runtime_evaluator": None, "severity": SEVERITY.get(domain, "unassessed"),
                   "remediation": REMEDIATION.get(domain, "No executable evaluator yet; review manually against the required outcome."),
                   "support": "static" if evaluator else "unsupported", "violations": []}
        if evaluator is None:
            control["status"] = "unsupported"
        else:
            applicable, violations = evaluator(index)
            control["violations"] = violations
            control["status"] = ("violation" if violations else "no_static_violation") if applicable else "not_applicable"
        summary[control["status"]] = summary.get(control["status"], 0) + 1
        controls.append(control)
    return {"revision": index["revision"], "controls": controls, "summary": dict(sorted(summary.items())),
            "note": "Static evaluation never establishes a pass; runtime evaluators are not implemented yet."}
