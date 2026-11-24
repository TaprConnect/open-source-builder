"""Executable assurance engine (S05-003, S05-008) over all catalogue domains.

One engine evaluates every catalogue control with shared applicability rules, the existing
static evaluators (control_framework.EVALUATORS plus the index-backed ones below), runtime
adapter receipts (runtime.py) and owner-frozen external acceptance receipts (kernel verify).

States: pass, fail, blocked, unknown, unsupported, not_applicable, not_performed.
A control passes only when its declared acceptance evidence exists for this exact revision:
security controls require a passing external acceptance receipt; other controls accept
trusted runtime receipts. A clean static scan is never a pass. Every evaluator runs in
isolation from the others (an exception blocks only that control), in dependency order,
under an explicit time budget, and each result carries a content-addressed receipt.
"""
import hashlib
import json
import time

from .control_framework import EVALUATORS, REMEDIATION
from .runtime import EXTERNAL_ONLY

ENGINE_VERSION = "1"
STATES = ("pass", "fail", "blocked", "unknown", "unsupported", "not_applicable", "not_performed")


def _external(index, names):
    roots = {m.split("/")[0].lower() for m in index["graph"].get("external", [])}
    return sorted(roots & names)


def _paths(index, test):
    return sorted(f["path"] for f in index["files"] if test(f["path"]))


def _lang(index, *languages):
    return [f["path"] for f in index["files"] if f["language"] in languages]


# Applicability: index -> (True | False | None, evidence). None means "cannot be determined statically".
def _imports(*names):
    def check(index):
        hits = _external(index, set(names))
        return (True, hits) if hits else (False, [f"none of {', '.join(sorted(names)[:6])} imported"])
    return check


def _files(predicate, label):
    def check(index):
        hits = _paths(index, predicate)
        return (True, hits[:20]) if hits else (False, [f"no {label}"])
    return check


def _any(*checks):
    def check(index):
        results = [c(index) for c in checks]
        if any(r[0] for r in results):
            return True, [e for r in results if r[0] for e in r[1]]
        if any(r[0] is None for r in results):
            return None, ["applicability undetermined"]
        return False, [e for r in results for e in r[1]]
    return check


def _undetermined(note):
    return lambda index: (None, [note])


def _always(index):
    return True, ["repository"]


def _sources(index):
    hits = _lang(index, "python", "typescript", "javascript")
    return (True, hits[:20]) if hits else (False, ["no Python, TypeScript or JavaScript sources"])


def _routes(index):
    hits = sorted({f"{'/'.join(c['methods'])} {c['path']}" for c in index.get("completeness", [])})
    return (True, hits[:20]) if hits else (False, ["no HTTP routes detected"])


def _write_routes(index):
    hits = sorted({f"{'/'.join(c['methods'])} {c['path']}" for c in index.get("completeness", [])
                   if set(c["methods"]) & {"POST", "PUT", "PATCH", "DELETE", "ANY"}})
    return (True, hits[:20]) if hits else (False, ["no write routes detected"])


def _frontend(index):
    hits = _paths(index, lambda p: p.endswith((".tsx", ".jsx", ".vue", ".svelte", ".html")))
    return (True, hits[:20]) if hits else (False, ["no UI sources"])


def _sql(index):
    hits = _paths(index, lambda p: p.endswith(".sql") or "/migrations/" in "/" + p)
    orm = _external(index, {"sqlalchemy", "django", "peewee", "prisma", "@prisma", "sequelize", "typeorm", "knex",
                            "pg", "mysql2", "sqlite3", "better-sqlite3", "psycopg2", "psycopg", "asyncpg", "mongoose",
                            "pymongo", "drizzle-orm"})
    return (True, hits[:20] + orm) if hits or orm else (False, ["no SQL files, migrations or database drivers"])


def _env(index):
    names = sorted(index.get("environment", {}))
    return (True, names[:20]) if names else (False, ["no environment variable reads"])


def _multi_user(index):
    columns = {c.lower() for f in index["files"] for t in (f.get("facts") or {}).get("tables", []) if isinstance(t, dict)
               for c in t.get("columns", [])}
    owners = sorted(columns & {"user_id", "owner_id", "tenant_id", "org_id", "organization_id", "account_id", "workspace_id"})
    if owners:
        return True, owners
    return (None, ["no ownership columns found; tenancy undetermined"]) if _routes(index)[0] else (False, ["no routes"])


_AI = {"openai", "anthropic", "langchain", "llama_index", "transformers", "@anthropic-ai", "@langchain", "ai",
       "cohere", "google", "mistralai", "litellm"}
_ML = {"torch", "tensorflow", "sklearn", "keras", "xgboost", "lightgbm", "jax"}
_PAY = {"stripe", "braintree", "paypalrestsdk", "@paypal", "adyen", "square", "lemonsqueezy"}
APPLIES = {
    "always": _always, "sources": _sources, "routes": _routes, "write_routes": _write_routes, "frontend": _frontend,
    "sql": _sql, "env": _env, "multi_user": _multi_user,
    "python": lambda ix: (bool(_lang(ix, "python")), _lang(ix, "python")[:20] or ["no Python sources"]),
    "ai": _imports(*_AI), "ml": _imports(*_ML), "payments": _imports(*_PAY),
    "jobs": _imports("celery", "rq", "dramatiq", "huey", "bullmq", "bull", "agenda", "apscheduler"),
    "cache": _imports("redis", "ioredis", "memcache", "pymemcache", "aiocache", "cachetools", "lru-cache"),
    "search": _imports("elasticsearch", "@elastic", "meilisearch", "algoliasearch", "whoosh", "typesense", "opensearchpy"),
    "files": _imports("multer", "formidable", "boto3", "@aws-sdk", "werkzeug", "python-multipart", "multipart", "busboy"),
    "email": _imports("smtplib", "nodemailer", "sendgrid", "@sendgrid", "postmark", "resend", "mailgun", "flask_mail"),
    "integration": _imports("requests", "httpx", "aiohttp", "axios", "node-fetch", "got", "urllib3"),
    "webhook": lambda ix: _routes(ix) if any("webhook" in c["path"].lower() for c in ix.get("completeness", []))
    else (False, ["no webhook routes"]),
    "agent": _imports("langchain", "@langchain", "autogen", "crewai", "openai", "anthropic", "@anthropic-ai"),
    "ci": _files(lambda p: p.startswith((".github/workflows/", ".gitlab-ci", ".circleci/")) or p == "Jenkinsfile", "CI configuration"),
    "infra": _files(lambda p: p.rsplit("/", 1)[-1] in ("Dockerfile", "docker-compose.yml", "compose.yaml", "vercel.json",
                                                      "fly.toml", "render.yaml", "Procfile") or p.endswith((".tf", ".bicep")), "deployment configuration"),
    "desktop": _imports("electron", "tauri", "@tauri-apps", "pyqt5", "pyside6", "tkinter", "wx"),
    "mobile": _any(_imports("react-native", "expo", "@capacitor", "kivy"),
                   _files(lambda p: p.endswith(("AndroidManifest.xml", "Info.plist")), "mobile manifests")),
    "cli": _any(_imports("argparse", "click", "typer", "commander", "yargs", "docopt"),
                _files(lambda p: p.endswith("__main__.py") or p.startswith("bin/"), "CLI entry points")),
    "sdk": _files(lambda p: p in ("pyproject.toml", "setup.py", "setup.cfg") or p.endswith("/index.d.ts"), "package metadata"),
    "pipeline": _imports("airflow", "dagster", "prefect", "luigi", "pandas", "pyspark", "dbt"),
    "locale": _imports("gettext", "babel", "i18next", "react-i18next", "next-intl", "flask_babel", "@formatjs"),
    "portability": _sources,
    "concurrency": _any(_write_routes, _imports("threading", "asyncio", "multiprocessing", "worker_threads")),
    "observability": _sources,
    "motion": _imports("framer-motion", "motion", "gsap", "react-spring", "@react-spring", "animejs"),
    "intent": _undetermined("requires the owner's stated product intent"),
    "pricing": _undetermined("requires the owner's commercial model"),
    "jurisdiction": _undetermined("requires the owner's markets and legal entity"),
    "support": _undetermined("requires the owner's support commitments"),
    "discovery": _frontend,
}

# (domain, family, security, applicability, static evaluator, runtime adapters, depends_on, blocker)
# static evaluator keys resolve to control_framework.EVALUATORS or STATIC below.
DOMAINS = [
    ("Identity", "security", True, "write_routes", "Identity", ("authorization",), (), None),
    ("Tenancy", "security", True, "multi_user", "Tenancy", ("authorization",), ("Identity",), None),
    ("Persistence", "data", False, "write_routes", "Persistence", ("persistence",), (), None),
    ("Backend", "backend", False, "sources", "Backend", ("unit_tests", "api_behaviour"), (), None),
    ("Frontend", "frontend", False, "frontend", "Frontend", ("build", "integration_tests"), (), None),
    ("Motion", "frontend", False, "motion", None, ("accessibility",), (), "needs a browser with reduced-motion emulation"),
    ("Accessibility", "frontend", False, "frontend", "Accessibility", ("accessibility",), (), None),
    ("Jobs", "reliability", False, "jobs", None, ("recovery",), (), "needs a queue broker and an interrupted-worker fixture"),
    ("Billing", "business", True, "payments", None, ("api_behaviour",), ("Payments", "Webhook"), "needs a payment-provider test account"),
    ("Database", "data", False, "sql", "Database", ("migrations",), (), None),
    ("AI", "ai", False, "ai", None, (), (), "needs evaluation cases and authorised provider access"),
    ("Agent", "ai", True, "agent", None, ("api_behaviour",), (), "needs an action-approval fixture for external writes"),
    ("Privacy", "privacy", True, "sql", None, ("persistence",), (), "needs the owner's deletion promises and processor list"),
    ("ML", "ai", False, "ml", None, (), (), "needs versioned data splits and a reproducible training run"),
    ("Operations", "operations", False, "infra", None, ("recovery",), (), "needs a backup and restore of a deployed environment"),
    ("Release", "operations", False, "ci", "Release", (), ("Build", "Quality"), "needs deployment receipts from the hosting provider"),
    ("Security", "security", True, "frontend", "ClientBundle", ("build",), (), None),
    ("UX", "frontend", False, "frontend", None, ("accessibility",), (), "needs the approved reference design"),
    ("Pricing", "business", False, "pricing", None, (), (), "needs dated provider prices and the owner's plan definitions"),
    ("Jurisdiction", "business", False, "jurisdiction", None, (), (), "needs legal review of markets and data flows"),
    ("Intent", "business", False, "intent", None, (), (), "needs the owner's confirmed requirements"),
    ("Architecture", "architecture", False, "python", "Architecture", (), (), None),
    ("Build", "build", False, "sources", "Build", ("build",), (), None),
    ("Quality", "testing", False, "sources", "Quality", ("unit_tests",), (), None),
    ("Contracts", "backend", False, "frontend", "Contracts", ("api_behaviour",), (), None),
    ("Configuration", "configuration", False, "env", "Configuration", (), (), None),
    ("Recovery", "reliability", False, "write_routes", None, ("recovery",), ("Persistence",), "needs a crash-injection fixture"),
    ("Isolation", "security", True, "multi_user", None, ("authorization",), ("Tenancy",), "needs a cross-tenant negative test"),
    ("Concurrency", "reliability", False, "concurrency", None, ("integration_tests",), (), "needs a concurrent-writer fixture"),
    ("Cache", "data", False, "cache", None, ("integration_tests",), (), "needs a cache server and an invalidation test"),
    ("Files", "security", True, "files", None, ("api_behaviour",), (), "needs upload fixtures for size, type and path limits"),
    ("Search", "data", False, "search", None, ("integration_tests",), (), "needs a search index and relevance fixtures"),
    ("Webhook", "security", True, "webhook", "Webhook", ("api_behaviour",), (), None),
    ("Integration", "backend", False, "integration", None, ("integration_tests",), (), "needs provider sandboxes or recorded contracts"),
    ("Network", "security", True, "integration", "Network", (), (), None),
    ("WebDefences", "security", True, "routes", "WebDefences", ("api_behaviour",), (), None),
    ("Secrets", "security", True, "always", "Secrets", (), (), None),
    ("SupplyChain", "supply-chain", False, "sources", "SupplyChain", ("supply_chain",), (), None),
    ("Infrastructure", "operations", False, "infra", None, (), (), "needs the deployed environment and its configuration"),
    ("Observability", "operations", False, "observability", "Observability", (), (), None),
    ("Reliability", "reliability", False, "sources", "Reliability", ("unit_tests",), (), None),
    ("Load", "performance", False, "routes", None, ("resources",), (), "needs an agreed latency and throughput budget"),
    ("Cost", "business", False, "ai", None, (), (), "needs metered provider usage"),
    ("Payments", "business", True, "payments", None, ("api_behaviour",), (), "needs a payment-provider test account"),
    ("Locale", "frontend", False, "locale", None, ("integration_tests",), (), "needs locale fixtures"),
    ("Email", "backend", False, "email", None, ("integration_tests",), (), "needs a mail sink"),
    ("Discovery", "frontend", False, "discovery", None, (), (), "needs a rendered page for metadata inspection"),
    ("Portability", "operations", False, "portability", None, ("build",), (), "needs each target platform"),
    ("Canary", "operations", False, "ci", None, (), ("Release",), "needs a staged rollout environment"),
    ("Support", "business", False, "support", None, (), (), "needs the owner's support process"),
    ("Desktop", "frontend", False, "desktop", None, ("build",), (), "needs a desktop packaging run"),
    ("Mobile", "frontend", False, "mobile", None, ("build",), (), "needs a mobile device or emulator"),
    ("CLI", "backend", False, "cli", None, ("unit_tests",), (), None),
    ("SDK", "backend", False, "sdk", None, ("build", "unit_tests"), (), None),
    ("DataPipeline", "data", False, "pipeline", None, ("integration_tests",), (), "needs representative datasets"),
    ("ModelData", "ai", False, "ml", None, (), (), "needs dataset provenance records"),
    ("AIEvals", "ai", False, "ai", None, (), ("AI",), "needs an evaluation dataset and grader"),
    ("AITrials", "ai", False, "ai", None, (), ("AIEvals",), "needs repeated live trials"),
    ("AIOutcome", "ai", False, "ai", None, (), ("AIEvals",), "needs end-state graders"),
    ("Grounding", "ai", True, "ai", None, (), ("AIEvals",), "needs citation-checking evaluation cases"),
    ("AITrust", "ai", True, "ai", None, (), (), "needs prompt-injection and refusal evaluation cases"),
    ("AIRelease", "ai", False, "ai", None, (), ("AIEvals",), "needs documented capability measurements"),
    ("AIResources", "ai", False, "ai", None, ("resources",), (), "needs metered token and tool budgets"),
    ("AIChange", "ai", False, "ai", None, (), ("AIEvals",), "needs before/after evaluation on a model change"),
    ("Retention", "privacy", True, "sql", None, ("persistence",), (), "needs the owner's retention schedule"),
    ("Removal", "privacy", True, "sql", None, ("persistence",), ("Privacy",), "needs deletion propagation fixtures"),
]


def _tenancy(index):
    applicable, _ = _multi_user(index)
    hits = [{"file": c["file"], "route": f"{'/'.join(c['methods'])} {c['path']}",
             "detail": "record addressed by identifier without authentication evidence (cross-user exposure candidate)"}
            for c in index.get("completeness", []) if c["auth"] == "not_detected"
            and any(seg.startswith((":", "{", "<", "[")) for seg in c["path"].split("/"))]
    return applicable is not False, hits


def _frontend_eval(index):
    ui = [f["path"] for f in index["files"] if f["path"].endswith((".tsx", ".jsx"))]
    hits = [{"file": i["path"], "line": i["line"], "detail": f"{i['kind']} {i['function']}"}
            for i in index.get("issues", []) if i["path"] in ui and i["kind"] in ("placeholder", "not_implemented")]
    hits += [{"file": u["file"], "line": u["line"], "detail": f"UI calls {u['method']} {u['path']} but no route serves it"}
             for u in index.get("unmatched_fetches", [])]
    return bool(ui), hits


def _contracts(index):
    links = index.get("frontend_links", []) + index.get("unmatched_fetches", [])
    return bool(links), [{"file": u["file"], "line": u["line"], "detail": f"no backend contract for {u['method']} {u['path']}"}
                         for u in index.get("unmatched_fetches", [])]


def _accessibility(index):
    return _frontend(index)[0], [{"file": a["file"], "line": a["line"], "detail": a["kind"]}
                                 for a in index.get("accessibility", [])]


def _build(index):
    broken = [{"file": f["path"], "detail": f.get("error", "parse failure")} for f in index["files"]
              if f["language"] in ("python", "typescript", "javascript", "json", "package_json", "pyproject")
              and f["state"] == "INDEXED" and f.get("error")]
    return bool(_sources(index)[0]), broken


def _client_bundle(index):
    ui = {f["path"] for f in index["files"] if f["path"].endswith((".tsx", ".jsx")) or "/public/" in "/" + f["path"]}
    hits = [{"file": c["file"], "line": c["line"], "detail": "credential literal in client-side source"}
            for c in index.get("credentials", []) if c["file"] in ui]
    hits += [{"file": p, "detail": f"client code reads server environment variable {name}"}
             for name, paths in index.get("environment", {}).items() for p in paths
             if p in ui and not name.startswith(("NEXT_PUBLIC_", "VITE_", "REACT_APP_", "PUBLIC_", "EXPO_PUBLIC_"))]
    return bool(ui), hits


def _webhook(index):
    hooks = [c for c in index.get("completeness", []) if "webhook" in c["path"].lower()]
    hits = [{"file": c["file"], "route": f"{'/'.join(c['methods'])} {c['path']}",
             "detail": "webhook handler shows no signature verification"}
            for c in hooks if c["auth"] == "not_detected"]
    return bool(hooks), hits


def _database(index):
    sql = [f for f in index["files"] if f["language"] == "sql"]
    hits = [{"file": f["path"], "detail": f["error"]} for f in sql if f["state"] == "INDEXED" and f.get("error")]
    return bool(_sql(index)[0]), hits


def _release(index):
    applicable, evidence = APPLIES["ci"](index)
    return applicable, []  # presence is evidence, not a verdict; deployment receipts decide


def _network(index):
    return bool(_external(index, {"requests", "httpx", "aiohttp", "axios", "urllib3"})), [
        {"file": t["file"], "line": t["line"], "detail": t["kind"]} for t in index.get("taint", []) if t["kind"] == "ssrf"]


_PUBLIC_AUTH = __import__("re").compile(r"/((log_?in|sign_?in|sign_?up|register|log_?out|sign_?out|token|oauth|"
                                        r"verify|callback|health|status)\b|(forgot|reset|recover)[\w-]*|[\w-]*password)",
                                        __import__("re").I)
_PRIVATE_READ = __import__("re").compile(r"/(admin|users?|accounts?|profiles?|me|orders?|billing|invoices?|settings)(/|$|\b)",
                                         __import__("re").I)


def _identity(index):
    applicable, hits = EVALUATORS["Identity"](index)
    hits = [h for h in hits if not _PUBLIC_AUTH.search(h["route"].split(" ", 1)[-1])]
    reads = [{"file": c["file"], "route": f"{'/'.join(c['methods'])} {c['path']}",
              "detail": "read route for admin or personal data without authentication evidence"}
             for c in index.get("completeness", []) if c["auth"] == "not_detected"
             and not set(c["methods"]) & {"POST", "PUT", "PATCH", "DELETE"} and _PRIVATE_READ.search(c["path"])
             and not _PUBLIC_AUTH.search(c["path"])]
    return applicable or bool(reads), hits + reads


_NO_WRITE = __import__("re").compile(r"/(log_?in|sign_?in|log_?out|sign_?out|token|verify|health|status|callback|search)\b",
                                     __import__("re").I)


def _persistence(index):
    applicable, hits = EVALUATORS["Persistence"](index)
    return applicable, [h for h in hits if not _NO_WRITE.search(h["route"].split(" ", 1)[-1])]


STATIC = {**EVALUATORS, "Identity": _identity, "Persistence": _persistence, "Tenancy": _tenancy, "Frontend": _frontend_eval, "Contracts": _contracts,
          "Accessibility": _accessibility, "Build": _build, "ClientBundle": _client_bundle, "Webhook": _webhook,
          "Database": _database, "Release": _release, "Network": _network}
VERIFY = {"security": "owner-frozen external acceptance with positive and negative cases, replayed by the kernel",
          "data": "external acceptance that writes, restarts and reads back on the same store",
          "default": "re-run the declared runtime adapters and the static evaluator on the repaired revision"}


def _order(domains):
    names = {d[0] for d in domains}
    done, order, visiting = set(), [], set()

    def visit(name):
        if name in done or name not in names:
            return
        if name in visiting:
            raise ValueError("control dependency cycle at " + name)
        visiting.add(name)
        for dep in next(d for d in domains if d[0] == name)[6]:
            visit(dep)
        visiting.discard(name)
        done.add(name)
        order.append(name)
    for d in domains:
        visit(d[0])
    return order


def _receipt(record):
    body = json.dumps(record, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(body).hexdigest()


def evaluate(rows, index, runtime=None, acceptance=(), budget_seconds=60.0, clock=time.monotonic):
    """rows: catalogue rows; runtime: runtime.run() output; acceptance: external verification records
    [{"control": "E01-Identity", "passed": bool, "revision": str, "verification": int}]."""
    catalogue = {r["domain"]: r for r in rows}
    table = {d[0]: d for d in DOMAINS}
    missing = sorted(set(catalogue) - set(table))
    domains = [table[name] for name in catalogue if name in table]
    receipts = (runtime or {}).get("receipts", {})
    runtime_ok = runtime is not None and runtime.get("revision") == index["revision"]
    accepted, stale = {}, []
    for a in acceptance:
        if a.get("revision") != index["revision"]:
            stale.append(a.get("control"))
            continue
        accepted.setdefault(a["control"], []).append(a)
    deadline = clock() + budget_seconds
    results = {}
    for name in _order(domains):
        _, family, security, applies_key, static_key, adapters, depends, blocker = table[name]
        row = catalogue[name]
        control_id = f"E01-{name}"
        record = {"id": control_id, "version": f"{ENGINE_VERSION}.1", "domain": name, "family": family,
                  "security": security, "revision": index["revision"], "applicability_rule": row["activates_when"],
                  "required_evidence": row["evidence"], "acceptance_condition": row["required_outcome"],
                  "static_evaluator": static_key, "runtime_adapters": list(adapters), "depends_on": list(depends),
                  "severity": "high" if security else ("medium" if family in ("data", "backend", "reliability") else "low"),
                  "remediation": REMEDIATION.get(name, f"Meet the required outcome: {row['required_outcome']}."),
                  "remediation_verification": VERIFY["security" if security else "data" if family == "data" else "default"],
                  "evidence": [], "violations": []}
        started = clock()
        if started > deadline:
            record.update(state="not_performed", confidence="none", reason="execution budget exhausted")
        else:
            try:
                record.update(_decide(record, index, applies_key, static_key, adapters, blocker, depends, results,
                                      receipts if runtime_ok else {}, runtime is not None and not runtime_ok,
                                      accepted.get(control_id, [])))
            except Exception as exc:  # failure isolation: one broken evaluator blocks only its control
                record.update(state="blocked", confidence="none", reason=f"evaluator error: {type(exc).__name__}: {exc}"[:300])
        record["duration_ms"] = round((clock() - started) * 1000, 3)
        record["receipt_sha256"] = _receipt(record)
        results[name] = record
    controls = [results[d[0]] for d in domains]
    summary = {}
    for c in controls:
        summary[c["state"]] = summary.get(c["state"], 0) + 1
    coverage = {"domains": len(controls), "static_evaluators": sum(1 for c in controls if c["static_evaluator"]),
                "runtime_backed": sum(1 for c in controls if c["runtime_adapters"]),
                "no_evaluator": [c["domain"] for c in controls if not c["static_evaluator"] and not c["runtime_adapters"]],
                "catalogue_domains_without_definition": missing}
    return {"engine": ENGINE_VERSION, "revision": index["revision"], "controls": controls,
            "summary": dict(sorted(summary.items())), "coverage": coverage, "stale_acceptance": stale,
            "note": "pass requires acceptance evidence for this revision; static cleanliness alone is never a pass"}


def _decide(record, index, applies_key, static_key, adapters, blocker, depends, results, receipts, runtime_stale, accepted):
    applies, evidence = APPLIES[applies_key](index)
    record["applicability"] = {"applies": applies, "evidence": evidence}
    if applies is False:
        return {"state": "not_applicable", "confidence": "static", "reason": "; ".join(evidence)[:300]}
    violations = []
    if static_key:
        static_applies, violations = STATIC[static_key](index)
        record["violations"] = violations
    if violations:
        return {"state": "fail", "confidence": "static-candidate",
                "reason": f"{len(violations)} static violation(s); confirm with the acceptance condition"}
    failed_external = [a for a in accepted if not a.get("passed")]
    if failed_external:
        record["evidence"].append({"kind": "external_acceptance", "verifications": [a.get("verification") for a in accepted]})
        return {"state": "fail", "confidence": "external", "reason": "owner-frozen external acceptance failed"}
    dependency_issues = [d for d in depends if d in results and results[d]["state"] in ("fail", "blocked")]
    used = []
    for adapter in adapters:
        for r in receipts.get(adapter, []):
            used.append({"kind": "runtime", "adapter": adapter, "state": r["state"], "trust": r.get("trust"),
                         "output_sha256": r.get("output_sha256"), "reason": r.get("reason")})
    record["evidence"].extend(used)
    if any(u["state"] == "fail" for u in used):
        return {"state": "fail", "confidence": "runtime", "reason": "a runtime adapter failed"}
    passed_external = [a for a in accepted if a.get("passed")]
    if passed_external:
        record["evidence"].append({"kind": "external_acceptance", "verifications": [a.get("verification") for a in passed_external]})
    if dependency_issues:
        return {"state": "blocked", "confidence": "none",
                "reason": "dependency control(s) not satisfied: " + ", ".join(dependency_issues)}
    if passed_external and applies is True:
        return {"state": "pass", "confidence": "external", "reason": "owner-frozen external acceptance passed for this revision"}
    trusted_pass = {u["adapter"] for u in used if u["state"] == "pass" and u["trust"] == "trusted_target"}
    command_only = adapters and not set(adapters) & set(EXTERNAL_ONLY)
    if not record["security"] and applies is True and command_only and set(adapters) <= trusted_pass:
        return {"state": "pass", "confidence": "runtime-trusted", "reason": "all required runtime adapters passed on a trusted target"}
    if not static_key and not adapters:
        return {"state": "unsupported", "confidence": "none", "reason": blocker or "no evaluator"}
    blocked = [u for u in used if u["state"] == "blocked"]
    if blocked and not static_key:
        return {"state": "blocked", "confidence": "none", "reason": blocked[0]["reason"] or "runtime adapter blocked"}
    if applies is None:
        return {"state": "unknown", "confidence": "none", "reason": "; ".join(evidence)[:300]}
    if not static_key and not used:
        reason = "runtime evidence is stale for this revision" if runtime_stale else (blocker or "runtime adapters not executed")
        return {"state": "not_performed", "confidence": "none", "reason": reason}
    missing = blocker or ("security controls need passing external acceptance" if record["security"]
                          else "acceptance evidence absent")
    return {"state": "unknown", "confidence": "static" if static_key else "runtime",
            "reason": "no violation found; " + missing}
