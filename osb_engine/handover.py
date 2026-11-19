"""Portable, digest-sealed plan handover for cross-process and cross-model continuation (F01-PLAN).

A bundle carries the committed report, task states and informational kernel facts.
Importing verifies the seal, the repository identity and the current revision, and
recreates plan and task states. Kernel authority (leases, completions, approvals)
never transfers: the receiving supervisor must re-verify and re-complete work.
"""
import hashlib
import json
import os
import time

from .audit import repository_identity
from .store import canonical

BUNDLE_SCHEMA = 1
_STATES = ("open", "investigating", "blocked", "proposed", "cancelled")


def _seal(body):
    return hashlib.sha256(canonical(body).encode()).hexdigest()


def export_plan(store, run_id, path):
    view = store.view(run_id)
    target = store.repo.private_path(path)
    kernel = {}
    try:
        kernel["completed_tasks"] = sorted(r[0] for r in store.conn.execute(
            "SELECT task_id FROM kernel_completions_v1 WHERE run_id=?", (run_id,)))
    except Exception:  # kernel tables absent: nothing to report
        kernel["completed_tasks"] = []
    body = {"schema": BUNDLE_SCHEMA, "repository_identity": repository_identity(store.repo),
            "revision": view["revision"], "source_run_id": run_id, "report": view["report"],
            "tasks": [{"id": t["id"], "state": t["state"], "reason": t["reason"],
                       "fingerprint": t["fingerprint"]} for t in view["tasks"]],
            "kernel_informational": kernel, "exported_ns": time.time_ns()}
    document = {**body, "seal_sha256": _seal(body)}
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w") as handle:
        json.dump(document, handle, indent=1)
    return {"exported": str(target), "run_id": run_id, "tasks": len(body["tasks"]), "seal_sha256": document["seal_sha256"]}


def import_plan(store, path):
    document = json.loads(store.repo.private_path(path).read_bytes())
    body = {k: v for k, v in document.items() if k != "seal_sha256"}
    if document.get("seal_sha256") != _seal(body):
        raise ValueError("handover bundle seal does not match its contents")
    if body.get("schema") != BUNDLE_SCHEMA:
        raise ValueError("unsupported handover bundle schema")
    if body["repository_identity"] != repository_identity(store.repo):
        raise ValueError("handover bundle belongs to a different repository")
    if body["revision"] != store.repo.head():
        raise ValueError("handover bundle revision differs from the current checkout; re-plan instead")
    states = {t["id"]: t for t in body["tasks"]}
    if any(t["state"] not in _STATES for t in states.values()):
        raise ValueError("handover bundle contains an invalid task state")
    run_id = store.save(body["report"])
    with store.conn:
        store.conn.execute("BEGIN IMMEDIATE")
        for task_id, task in states.items():
            row = store.conn.execute("SELECT state FROM engine_tasks WHERE run_id=? AND id=?", (run_id, task_id)).fetchone()
            if not row:
                raise ValueError("handover task missing from its report")
            if task["state"] != row[0]:
                store.conn.execute("UPDATE engine_tasks SET state=?, version=version+1, reason=? WHERE run_id=? AND id=?",
                                   (task["state"], task["reason"], run_id, task_id))
                store.conn.execute("INSERT INTO engine_events(run_id,task_id,previous,next,reason) VALUES (?,?,?,?,?)",
                                   (run_id, task_id, row[0], task["state"], "handover import: " + task["reason"]))
    return {"imported": True, "run_id": run_id, "source_run_id": body["source_run_id"],
            "tasks": len(states), "kernel_authority_imported": False}
