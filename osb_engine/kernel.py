"""Operator-managed reservations in one trusted local store per project.

Use a single private database outside worker access. A reservation grants no
permission to run commands or modify a checkout. An expired task retains its
project slot until a supervisor recovers it. Completion is a separate gate.
"""
import hashlib
import hmac
import os
import secrets
import time


def _token_hash(token):
    return hashlib.sha256(token.encode("utf-8")).digest()


def _lease(store, run_id, task_id, seconds, renewal=None):
    if type(seconds) is not int or not 1 <= seconds <= 3600:
        raise ValueError("lease duration must be 1 to 3600 seconds")
    conn = store.conn
    project = os.path.normcase(str(store.repo.common))
    with conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS kernel_reservations_v1 (
                project TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                task_id TEXT NOT NULL,
                generation INTEGER NOT NULL CHECK(generation > 0),
                token_hash BLOB NOT NULL,
                expires_ns INTEGER NOT NULL,
                FOREIGN KEY(run_id, task_id) REFERENCES engine_tasks(run_id, id)
            )
        """)
        plan = store.view(run_id)
        if plan["stale"] or plan["revision"] != store.repo.revision:
            raise ValueError("stale plan revision")
        if not any(task["id"] == task_id for task in plan["tasks"]):
            raise ValueError("unknown plan task")

        row = conn.execute("""
            SELECT run_id, task_id, generation, token_hash, expires_ns
            FROM kernel_reservations_v1 WHERE project = ?
        """, (project,)).fetchone()
        if row and row[:2] != (run_id, task_id):
            raise ValueError("another task retains this project reservation")
        now = time.time_ns()
        expires = now + seconds * 1_000_000_000
        if renewal is None:
            if row and row[4] > now:
                raise ValueError("task already reserved")
            generation = row[2] + 1 if row else 1
            token = secrets.token_urlsafe(32)
            conn.execute("""
                INSERT INTO kernel_reservations_v1
                    (project, run_id, task_id, generation, token_hash, expires_ns)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(project) DO UPDATE SET
                    generation=excluded.generation, token_hash=excluded.token_hash,
                    expires_ns=excluded.expires_ns
            """, (project, run_id, task_id, generation, _token_hash(token), expires))
            result = {"token": token}
        else:
            generation, token = renewal
            if (not row or row[4] <= now or row[2] != generation
                    or not hmac.compare_digest(row[3], _token_hash(token))):
                raise ValueError("invalid or expired reservation")
            conn.execute("""
                UPDATE kernel_reservations_v1 SET expires_ns=? WHERE project=?
            """, (expires, project))
            result = {}
        store.repo.assert_current()
    return {**result, "generation": generation, "expires_ns": expires,
            "run_id": run_id, "task_id": task_id, "revision": plan["revision"]}


def reserve(store, run_id, task_id, seconds):
    return _lease(store, run_id, task_id, seconds)


def renew(store, run_id, task_id, generation, seconds, token):
    return _lease(store, run_id, task_id, seconds, (generation, token))
