"""Engineering planner (S06-003) and continuous repair loop (S06-006) over the existing kernel.

plan(): one kernel task per owner requirement (plus its frozen external acceptance), with a
stable identity, outcome, evidence, dependencies, modification scope, risk, budget, rollback
and ordered repair strategies. Plans are saved through Store.save(), so an unchanged plan is
recognised rather than rediscovered.

run(): discover -> analyse -> prioritise -> reserve -> implement -> verify -> review ->
complete -> continue. The kernel is the only authority: leases, scope grants, mutation,
frozen acceptance and completion all go through it. A failing attempt is reverted with
release(revert=True); attempts are bounded and persisted, so an interrupted loop resumes
where it stopped; pause, revocation and stale plans stop the loop instead of being retried.
"""
import hashlib
import json
import time
from pathlib import Path

from . import product, providers, repairs
from .completion import complete, depend, freeze, release, verify
from .kernel import _project, _schema, completed, grant, reserve
from .mutation import mutate
from .store import identity

_SECURITY_WORDS = ("owner", "another user", "permission", "auth", "access", "private", "secret", "delete")
_ATTEMPTS = """CREATE TABLE IF NOT EXISTS autopilot_attempts_v1 (project TEXT NOT NULL, run_id TEXT NOT NULL,
    task_id TEXT NOT NULL, attempts INTEGER NOT NULL, state TEXT NOT NULL, detail TEXT NOT NULL,
    PRIMARY KEY (project, run_id, task_id))"""


def _strategies(requirement, understanding):
    text = requirement.get("text", "").lower()
    order = []
    if requirement.get("rules"):
        order.append("validate_required")
    if any(w in text for w in ("restart", "persist", "survive", "durable")) or understanding["inferred"]["in_memory_stores"]:
        order.append("persist_store")
    if understanding["inferred"]["missing_functions"]:
        order.append("complete_crud")
    if any(w in text for w in ("owner", "another user", "other user", "cannot read", "cannot delete")):
        order.append("enforce_ownership")
    return order + [s for s in repairs.REPAIRERS if s not in order]


def plan(store, spec, spec_dir, understanding, facts, budget_attempts=4, budget_seconds=900):
    repo = store.repo
    defined = {name: path for path, f in facts.items() for name in f.get("functions", {})}
    tasks = []
    by_requirement = {}
    for r in spec["requirements"]:
        acceptance = (Path(spec_dir) / r["acceptance"]).read_bytes()
        scope = sorted(set(r.get("scope") or [defined[n] for n in r.get("functions", []) if n in defined]))
        if not scope:
            raise ValueError(f"{r['id']}: no modification scope (declare scope or functions present in the code)")
        if any(not repairs.allowed_path(p, scope) for p in scope):
            raise ValueError(f"{r['id']}: scope includes test, acceptance or CI paths")
        acceptance_sha = hashlib.sha256(acceptance).hexdigest()
        task_id = identity(["autopilot-1", r["id"], acceptance_sha, scope])[:32]
        risk = r.get("risk") or ("high" if any(w in r.get("text", "").lower() for w in _SECURITY_WORDS) else "medium")
        by_requirement[r["id"]] = task_id
        tasks.append({"id": task_id, "fingerprint": task_id, "requirement": r["id"], "outcome": r.get("text", ""),
                      "evidence": {"graph": understanding["inferred"]["missing_functions"] + understanding["inferred"]["in_memory_stores"]},
                      "depends_on": r.get("depends_on", []), "scope": scope, "acceptance_sha256": acceptance_sha,
                      "acceptance_summary": r.get("text", ""), "risk": risk, "rules": r.get("rules", []),
                      "budget": {"attempts": budget_attempts, "seconds": budget_seconds},
                      "rollback": "kernel release --revert restores the worktree from the task's journal",
                      "strategies": _strategies(r, understanding), "kind": "requirement"})
    order = {"high": 0, "medium": 1, "low": 2}
    tasks.sort(key=lambda t: (len(t["depends_on"]), order.get(t["risk"], 1), t["requirement"]))
    report = {"schema": "autopilot-plan-1", "revision": repo.revision, "scope": "committed", "findings": tasks}
    run_id = store.save(report)
    for t in tasks:
        for dep in t["depends_on"]:
            try:
                depend(store, run_id, t["id"], by_requirement[dep])
            except ValueError as exc:
                if "already" not in str(exc):
                    raise
    return run_id, tasks


def _attempts(store, run_id, task_id):
    conn, project = store.conn, _project(store)
    conn.execute(_ATTEMPTS)
    row = conn.execute("SELECT attempts, state, detail FROM autopilot_attempts_v1 WHERE project=? AND run_id=? AND task_id=?",
                       (project, run_id, task_id)).fetchone()
    return row or (0, "pending", "")


def _record(store, run_id, task_id, attempts, state, detail):
    conn, project = store.conn, _project(store)
    conn.execute(_ATTEMPTS)
    with conn:
        conn.execute("INSERT OR REPLACE INTO autopilot_attempts_v1 VALUES (?,?,?,?,?,?)",
                     (project, run_id, task_id, attempts, state, json.dumps(detail, sort_keys=True)[:4000]))


def run(store, run_id, tasks, acceptance, provider, lease_seconds=900, deadline=None, log=None):
    """Execute the plan until no ready work remains. acceptance: {task_id: frozen script bytes}."""
    repo = store.repo
    log = log if log is not None else []
    outcome = {"completed": [], "escalated": [], "blocked": [], "stopped": None, "events": log}
    conn, project = store.conn, _project(store)
    _schema(conn)
    done = {t["id"] for t in tasks if completed(conn, project, run_id, t["id"])}
    progress = True
    while progress:
        progress = False
        if repo.head() != repo.revision:
            outcome["stopped"] = "stale plan: the repository HEAD moved; re-plan before continuing"
            break
        for task in tasks:
            tid = task["id"]
            attempts, state, _ = _attempts(store, run_id, tid)
            if tid in done or state in ("escalated",):
                continue
            deps = [t["id"] for t in tasks if t["requirement"] in task["depends_on"]]
            if any(d not in done for d in deps):
                continue
            if deadline is not None and time.monotonic() > deadline:
                outcome["stopped"] = "resource budget exhausted"
                return _finish(outcome, tasks, done)
            if attempts >= task["budget"]["attempts"]:
                _record(store, run_id, tid, attempts, "escalated", {"reason": "attempt budget exhausted"})
                outcome["escalated"].append({"task": tid, "requirement": task["requirement"], "reason": "attempt budget exhausted"})
                continue
            result = _attempt(store, run_id, task, acceptance[tid], provider, lease_seconds, attempts, log)
            if result == "completed":
                done.add(tid)
                progress = True
            elif result in ("paused", "revoked"):
                outcome["stopped"] = result
                return _finish(outcome, tasks, done)
            elif result == "no_proposal":
                _record(store, run_id, tid, attempts + 1, "escalated", {"reason": "no repair strategy produced a passing change"})
                outcome["escalated"].append({"task": tid, "requirement": task["requirement"],
                                             "reason": "needs a product decision or an authorised model provider"})
            else:
                progress = True  # another attempt (bounded) or another task may now succeed
    return _finish(outcome, tasks, done)


def _finish(outcome, tasks, done):
    outcome["completed"] = sorted(t["requirement"] for t in tasks if t["id"] in done)
    outcome["remaining"] = sorted(t["requirement"] for t in tasks if t["id"] not in done)
    return outcome


def _scope_digest(root, task):
    digest = hashlib.sha256()
    for path in task["scope"]:
        try:
            digest.update(path.encode() + b"\0" + (root / path).read_bytes())
        except OSError:
            digest.update(path.encode() + b"\0missing")
    return digest.hexdigest()[:16]


def _attempt(store, run_id, task, script, provider, lease_seconds, attempts, log):
    tid = task["id"]
    try:
        lease = reserve(store, run_id, tid, lease_seconds)
    except ValueError as exc:
        text = str(exc)
        log.append({"task": task["requirement"], "event": "reserve_refused", "detail": text})
        return "paused" if "paused" in text else "blocked"
    gen, token = lease["generation"], lease["token"]
    try:
        freeze(store, run_id, tid, script, external=True)
        baseline = verify(store, run_id, tid, gen, script)
        log.append({"task": task["requirement"], "event": "baseline", "passed": baseline["passed"]})
        if baseline["passed"]:
            complete(store, run_id, tid, gen, token)
            log.append({"task": task["requirement"], "event": "completed_without_change"})
            return "completed"
        grant(store, run_id, tid, gen, [("edit", task["scope"])])
        proposals = provider.propose(task, providers.context(store.repo.root, task))
        state = _scope_digest(store.repo.root, task)
        _, _, detail = _attempts(store, run_id, tid)
        previous = set(map(tuple, (json.loads(detail) if detail else {}).get("tried", [])))
        tried = 0
        for proposal in proposals:  # skip strategies that already failed on this exact scope content
            if (proposal["strategy"], state) in previous:
                continue
            tried += 1
            patch = proposal["patch"]
            touched = {line[6:].strip() for line in patch.splitlines() if line.startswith("+++ b/")}
            if not touched or any(not repairs.allowed_path(p, task["scope"]) for p in touched):
                log.append({"task": task["requirement"], "event": "proposal_rejected", "strategy": proposal["strategy"],
                            "reason": "patch outside granted scope or touches protected paths"})
                continue
            mutate(store, run_id, tid, gen, token, patch.encode())
            result = verify(store, run_id, tid, gen, script)
            log.append({"task": task["requirement"], "event": "verified", "strategy": proposal["strategy"],
                        "passed": result["passed"], "verification": result.get("verification")})
            if result["passed"]:
                complete(store, run_id, tid, gen, token)
                _record(store, run_id, tid, attempts + tried, "completed", {"strategy": proposal["strategy"]})
                return "completed"
            release(store, run_id, tid, gen, f"{proposal['strategy']} failed acceptance", revert=True)
            _record(store, run_id, tid, attempts + tried, "retry",
                    {"strategy": proposal["strategy"], "tried": sorted(previous | {(proposal["strategy"], state)})})
            log.append({"task": task["requirement"], "event": "reverted", "strategy": proposal["strategy"]})
            return "retry"
        release(store, run_id, tid, gen, "no applicable proposal", revert=True)
        return "no_proposal"
    except ValueError as exc:
        text = str(exc)
        log.append({"task": task["requirement"], "event": "kernel_refused", "detail": text[:300]})
        if "outside the granted" in text or "patch" in text.lower():
            try:
                release(store, run_id, tid, gen, "rejected proposal: " + text[:200], revert=True)
            except ValueError:
                pass
            _record(store, run_id, tid, attempts + 1, "retry", {"error": text[:300]})
            return "retry"
        try:
            release(store, run_id, tid, gen, "loop error: " + text[:200], revert=True)
        except ValueError:
            pass
        if "paused" in text:
            return "paused"
        if "revoked" in text or "lease" in text:
            return "revoked"
        _record(store, run_id, tid, attempts + 1, "retry", {"error": text[:300]})
        return "retry"
