"""Supervisor-controlled verified completion, dependencies and release.

Completion authority comes only from verification the supervisor ran itself
and recorded in the private store. The worker presents its bearer and nothing
else, so it cannot supply a receipt or choose the acceptance script.
verify() runs repository code as the calling user: run the supervisor inside
an isolation boundary until worker/verifier isolation (S02-005) exists.
"""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time

from .kernel import (_live, _paused, _project, _reason, _schema, completed, digest,
                     integrity)
from .mutation import _apply


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def state_digest(conn, project, revision):
    """Digest of the revision plus every kernel-recorded worktree change."""
    ledger = conn.execute("SELECT path, current FROM kernel_ledger_v1 WHERE project=? ORDER BY path",
                          (project,)).fetchall()
    return _sha(json.dumps([revision, ledger], separators=(",", ":")).encode())


def _task(store, run_id, task_id):
    if not any(t["id"] == task_id for t in store.view(run_id)["tasks"]):
        raise ValueError("unknown plan task")


def depend(store, run_id, task_id, requires):
    """Supervisor declares that task_id cannot be reserved until requires is completed."""
    if task_id == requires:
        raise ValueError("a task cannot depend on itself")
    conn, project = store.conn, _project(store)
    with conn:
        conn.execute("BEGIN IMMEDIATE")
        _schema(conn)
        _task(store, run_id, task_id)
        _task(store, run_id, requires)
        edges = {}
        for t, r in conn.execute("SELECT task_id, requires FROM kernel_dependencies_v1 WHERE project=? AND run_id=?",
                                 (project, run_id)):
            edges.setdefault(t, set()).add(r)
        stack, seen = [requires], set()
        while stack:
            node = stack.pop()
            if node == task_id:
                raise ValueError("dependency cycle")
            if node not in seen:
                seen.add(node)
                stack.extend(edges.get(node, ()))
        conn.execute("INSERT OR IGNORE INTO kernel_dependencies_v1 VALUES (?, ?, ?, ?)",
                     (project, run_id, task_id, requires))
    return {"run_id": run_id, "task_id": task_id, "requires": requires}


def freeze(store, run_id, task_id, acceptance):
    """Supervisor freezes the acceptance script digest for a task. It can never change."""
    if type(acceptance) is not bytes or not acceptance or len(acceptance) > 1024 * 1024:
        raise ValueError("frozen acceptance script required")
    conn, project, value = store.conn, _project(store), _sha(acceptance)
    with conn:
        conn.execute("BEGIN IMMEDIATE")
        _schema(conn)
        _task(store, run_id, task_id)
        row = conn.execute("SELECT digest FROM kernel_acceptance_v1 WHERE project=? AND run_id=? AND task_id=?",
                           (project, run_id, task_id)).fetchone()
        if row and row[0] != value:
            raise ValueError("frozen acceptance cannot change")
        conn.execute("INSERT OR IGNORE INTO kernel_acceptance_v1 VALUES (?, ?, ?, ?)",
                     (project, run_id, task_id, value))
    return {"run_id": run_id, "task_id": task_id, "acceptance_sha256": value}


def _frozen(conn, project, run_id, task_id):
    row = conn.execute("SELECT digest FROM kernel_acceptance_v1 WHERE project=? AND run_id=? AND task_id=?",
                       (project, run_id, task_id)).fetchone()
    if not row:
        raise ValueError("no frozen acceptance for this task")
    return row[0]


def verify(store, run_id, task_id, generation, acceptance, timeout=600):
    """Supervisor runs the frozen acceptance against the current state and records the outcome."""
    conn, project, repo = store.conn, _project(store), store.repo
    with conn:
        conn.execute("BEGIN IMMEDIATE")
        _schema(conn)
        if _paused(conn, project):
            raise ValueError("project dispatch paused")
        if _frozen(conn, project, run_id, task_id) != _sha(acceptance):
            raise ValueError("acceptance differs from the frozen contract")
        plan = _live(store, run_id, task_id, generation)
        if integrity(store, conn):
            raise ValueError("out-of-band worktree changes detected")
        before = state_digest(conn, project, plan["revision"])
        with tempfile.TemporaryDirectory() as tmp:
            script = os.path.join(tmp, "acceptance.py")
            with open(script, "wb") as handle:
                handle.write(acceptance)
            env = {k: os.environ[k] for k in ("PATH", "SYSTEMROOT", "TEMP", "TMP") if k in os.environ}
            env.update(PYTHONDONTWRITEBYTECODE="1", HOME=tmp)
            try:
                result = subprocess.run([sys.executable, "-I", "-B", script], cwd=str(repo.root),
                                        env=env, capture_output=True, timeout=timeout)
                code, output = result.returncode, result.stdout + b"\0" + result.stderr
            except subprocess.TimeoutExpired:
                code, output = -1, b"timeout"
        repo.assert_current()
        unchanged = not integrity(store, conn) and state_digest(conn, project, plan["revision"]) == before
        passed = code == 0 and unchanged
        seq = conn.execute("""
            INSERT INTO kernel_verifications_v1 (project, run_id, task_id, generation, revision,
                acceptance, state, returncode, passed, output_sha256, time_ns)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (project, run_id, task_id, generation, plan["revision"], _sha(acceptance), before,
              code, int(passed), _sha(output), time.time_ns())).lastrowid
    return {"verification": seq, "passed": passed, "returncode": code,
            "worktree_unchanged": unchanged, "revision": plan["revision"], "state": before}


def complete(store, run_id, task_id, generation, token):
    """Holder requests completion; only a current passing supervisor verification grants it."""
    conn, project = store.conn, _project(store)
    with conn:
        conn.execute("BEGIN IMMEDIATE")
        _schema(conn)
        if _paused(conn, project):
            raise ValueError("project dispatch paused")
        plan = _live(store, run_id, task_id, generation, token)
        if completed(conn, project, run_id, task_id):
            raise ValueError("task already completed")
        frozen = _frozen(conn, project, run_id, task_id)
        if integrity(store, conn):
            raise ValueError("out-of-band worktree changes detected")
        state = state_digest(conn, project, plan["revision"])
        row = conn.execute("""
            SELECT seq, revision, acceptance, state, passed FROM kernel_verifications_v1
            WHERE project=? AND run_id=? AND task_id=? ORDER BY seq DESC LIMIT 1
        """, (project, run_id, task_id)).fetchone()
        if not row or (row[1], row[2], row[3], row[4]) != (plan["revision"], frozen, state, 1):
            raise ValueError("no passing supervisor verification of the current state")
        store.repo.assert_current()
        conn.execute("INSERT INTO kernel_completions_v1 VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                     (project, run_id, task_id, generation, plan["revision"], row[0], state, time.time_ns()))
        conn.execute("UPDATE kernel_reservations_v1 SET expires_ns=0 WHERE project=?", (project,))
    return {"completed": True, "run_id": run_id, "task_id": task_id, "generation": generation,
            "revision": plan["revision"], "verification": row[0], "state": state}


def release(store, run_id, task_id, generation, reason, revert=False):
    """Supervisor frees the slot without completion after reverting the task's kernel patches."""
    reason = _reason(reason)
    conn, project, repo = store.conn, _project(store), store.repo
    root = str(repo.root)
    with conn:
        conn.execute("BEGIN IMMEDIATE")
        _schema(conn)
        row = conn.execute("SELECT run_id, task_id, generation FROM kernel_reservations_v1 WHERE project=?",
                           (project,)).fetchone()
        if not row or tuple(row) != (run_id, task_id, generation):
            raise ValueError("release requires the current reservation generation")
        if completed(conn, project, run_id, task_id):
            raise ValueError("completed tasks cannot be released")
        if conn.execute("SELECT 1 FROM kernel_releases_v1 WHERE project=? AND generation=?",
                        (project, generation)).fetchone():
            raise ValueError("generation already released")
        if integrity(store, conn):
            raise ValueError("out-of-band worktree changes detected")
        patches = conn.execute("""SELECT dispatch, patch, paths FROM kernel_patches_v1
            WHERE project=? AND run_id=? AND task_id=? AND reverted=0 ORDER BY dispatch DESC""",
                               (project, run_id, task_id)).fetchall()
        if patches and not revert:
            raise ValueError("revert this task's applied patches before release")
        undone = []
        try:
            for _, patch, _ in patches:
                _apply(repo, patch, reverse=True)
                undone.append(patch)
        except subprocess.CalledProcessError as exc:
            for patch in reversed(undone):
                _apply(repo, patch)
            raise ValueError("revert failed; worktree restored") from exc
        for dispatch, _, paths in patches:
            for path in json.loads(paths):
                conn.execute("UPDATE kernel_ledger_v1 SET current=? WHERE project=? AND path=?",
                             (digest(root, path), project, path))
            conn.execute("UPDATE kernel_patches_v1 SET reverted=1 WHERE dispatch=?", (dispatch,))
        conn.execute("INSERT INTO kernel_releases_v1 VALUES (?, ?, ?, ?, ?)",
                     (project, generation, run_id, task_id, reason))
        conn.execute("UPDATE kernel_reservations_v1 SET expires_ns=0 WHERE project=?", (project,))
    return {"released": True, "run_id": run_id, "task_id": task_id, "generation": generation,
            "reverted_patches": len(patches)}
