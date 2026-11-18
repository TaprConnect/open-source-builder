"""Operator-managed reservations in one trusted local store per project.

Use a single private database outside worker access. A reservation grants no
permission to run commands or modify a checkout. An expired task retains its
project slot until a supervisor recovers it. Completion is a separate gate.

The supervisor grants an explicit operation scope to one lease generation and
calls dispatch immediately before each controlled mutation. Dispatch is an
admission check plus audit record. It does not confine the worker afterwards.
"""
import hashlib
import hmac
import json
import os
import re
import secrets
import time

_KIND = re.compile(r"[a-z][a-z0-9_.-]{0,63}")
_MAX_PATHS = 256


def _token_hash(token):
    return hashlib.sha256(token.encode("utf-8")).digest()


def _project(store):
    return os.path.normcase(str(store.repo.common))


def _schema(conn):
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
    conn.execute("""
        CREATE TABLE IF NOT EXISTS kernel_controls_v1 (
            project TEXT PRIMARY KEY,
            paused INTEGER NOT NULL CHECK(paused IN (0, 1)),
            reason TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS kernel_grants_v1 (
            project TEXT NOT NULL,
            generation INTEGER NOT NULL,
            run_id TEXT NOT NULL,
            task_id TEXT NOT NULL,
            revision TEXT NOT NULL,
            scope TEXT NOT NULL,
            PRIMARY KEY(project, generation)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS kernel_revocations_v1 (
            project TEXT NOT NULL,
            generation INTEGER NOT NULL,
            reason TEXT NOT NULL,
            PRIMARY KEY(project, generation)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS kernel_dispatches_v1 (
            seq INTEGER PRIMARY KEY,
            project TEXT NOT NULL,
            run_id TEXT NOT NULL,
            task_id TEXT NOT NULL,
            generation INTEGER NOT NULL,
            revision TEXT NOT NULL,
            operation TEXT NOT NULL,
            time_ns INTEGER NOT NULL
        )
    """)


def _reason(reason):
    if type(reason) is not str or not reason.strip() or len(reason) > 4000:
        raise ValueError("nonempty bounded reason required")
    return reason


_COMPONENT = re.compile(r"[A-Za-z0-9._-]{1,255}")
_DEVICE = re.compile(r"(con|prn|aux|nul|com[0-9]|lpt[0-9])(\..*)?")


def _path(path):
    """Accept one portable spelling per file so OS aliases cannot widen a grant.

    ASCII letters, digits, '.', '_' and '-' only. Rejects traversal, empty and
    trailing-dot components, Windows device names, and any .git component.
    This excludes 8.3 short names, NTFS streams and Unicode normalisation aliases.
    """
    if type(path) is not str or not path or len(path) > 4096:
        raise ValueError("invalid operation path")
    parts = (path[:-1] if path.endswith("/") else path).split("/")
    for part in parts:
        folded = part.lower()
        if (not _COMPONENT.fullmatch(part) or part in (".", "..") or part.endswith(".")
                or folded == ".git" or _DEVICE.fullmatch(folded)):
            raise ValueError("operation path must be a normalised portable path outside .git")
    return path


def _operation(kind, paths):
    if type(kind) is not str or not _KIND.fullmatch(kind):
        raise ValueError("invalid operation kind")
    paths = list(paths)
    if not 1 <= len(paths) <= _MAX_PATHS:
        raise ValueError("explicit operation paths required")
    return {"kind": kind, "paths": sorted({_path(p) for p in paths})}


def _covered(path, granted):
    return any(path == g or g.endswith("/") and path.startswith(g) for g in granted)


def _revoked(conn, project, generation):
    return conn.execute("SELECT 1 FROM kernel_revocations_v1 WHERE project=? AND generation=?",
                        (project, generation)).fetchone() is not None


def _paused(conn, project):
    row = conn.execute("SELECT paused FROM kernel_controls_v1 WHERE project=?",
                       (project,)).fetchone()
    return bool(row and row[0])


def _live(store, run_id, task_id, generation, token=None):
    """Return the current plan when this exact lease generation is live, else raise."""
    if type(generation) is not int or generation < 1:
        raise ValueError("invalid lease generation")
    conn, project = store.conn, _project(store)
    plan = store.view(run_id)
    if plan["stale"] or plan["revision"] != store.repo.revision:
        raise ValueError("stale plan revision")
    row = conn.execute("""
        SELECT run_id, task_id, generation, token_hash, expires_ns
        FROM kernel_reservations_v1 WHERE project = ?
    """, (project,)).fetchone()
    if (not row or tuple(row[:3]) != (run_id, task_id, generation)
            or row[4] <= time.time_ns() or _revoked(conn, project, generation)
            or token is not None and not hmac.compare_digest(row[3], _token_hash(token))):
        raise ValueError("invalid, expired or revoked reservation")
    return plan


def _lease(store, run_id, task_id, seconds, renewal=None):
    if type(seconds) is not int or not 1 <= seconds <= 3600:
        raise ValueError("lease duration must be 1 to 3600 seconds")
    conn = store.conn
    project = _project(store)
    with conn:
        conn.execute("BEGIN IMMEDIATE")
        _schema(conn)
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
                    or _revoked(conn, project, generation)
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


def grant(store, run_id, task_id, generation, operations):
    """Supervisor binds an explicit operation scope to one live lease generation."""
    scope = [_operation(kind, paths) for kind, paths in operations]
    if not scope:
        raise ValueError("at least one granted operation required")
    conn, project = store.conn, _project(store)
    with conn:
        conn.execute("BEGIN IMMEDIATE")
        _schema(conn)
        if _paused(conn, project):
            raise ValueError("project dispatch paused")
        plan = _live(store, run_id, task_id, generation)
        conn.execute("""
            INSERT INTO kernel_grants_v1 (project, generation, run_id, task_id, revision, scope)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(project, generation) DO UPDATE SET
                revision=excluded.revision, scope=excluded.scope
        """, (project, generation, run_id, task_id, plan["revision"],
              json.dumps(scope, sort_keys=True, separators=(",", ":"))))
        store.repo.assert_current()
    return {"run_id": run_id, "task_id": task_id, "generation": generation,
            "revision": plan["revision"], "scope": scope}


def _control(store, paused, reason):
    conn, project = store.conn, _project(store)
    reason = _reason(reason)
    with conn:
        conn.execute("BEGIN IMMEDIATE")
        _schema(conn)
        conn.execute("""
            INSERT INTO kernel_controls_v1 (project, paused, reason) VALUES (?, ?, ?)
            ON CONFLICT(project) DO UPDATE SET paused=excluded.paused, reason=excluded.reason
        """, (project, int(paused), reason))
    return {"paused": paused, "reason": reason}


def pause(store, reason):
    return _control(store, True, reason)


def resume(store, reason):
    return _control(store, False, reason)


def revoke(store, run_id, task_id, generation, reason):
    """Supervisor invalidates a live generation. Recovery requires a new reservation."""
    reason = _reason(reason)
    conn, project = store.conn, _project(store)
    with conn:
        conn.execute("BEGIN IMMEDIATE")
        _schema(conn)
        _live(store, run_id, task_id, generation)
        conn.execute("INSERT INTO kernel_revocations_v1 (project, generation, reason) VALUES (?, ?, ?)",
                     (project, generation, reason))
        conn.execute("UPDATE kernel_reservations_v1 SET expires_ns=0 WHERE project=?", (project,))
    return {"run_id": run_id, "task_id": task_id, "generation": generation, "revoked": True}


def dispatch(store, run_id, task_id, generation, token, kind, paths):
    """Admit one controlled mutation immediately before it runs, or raise without side effects."""
    operation = _operation(kind, paths)
    conn, project = store.conn, _project(store)
    with conn:
        conn.execute("BEGIN IMMEDIATE")
        _schema(conn)
        if _paused(conn, project):
            raise ValueError("project dispatch paused")
        plan = _live(store, run_id, task_id, generation, token)
        row = conn.execute("""
            SELECT run_id, task_id, revision, scope FROM kernel_grants_v1
            WHERE project=? AND generation=?
        """, (project, generation)).fetchone()
        if not row or tuple(row[:2]) != (run_id, task_id):
            raise ValueError("no operation scope granted to this reservation")
        if row[2] != plan["revision"]:
            raise ValueError("grant bound to a different revision")
        granted = [g["paths"] for g in json.loads(row[3]) if g["kind"] == operation["kind"]]
        if not all(any(_covered(p, g) for g in granted) for p in operation["paths"]):
            raise ValueError("operation outside granted scope")
        store.repo.assert_current()
        now = time.time_ns()
        seq = conn.execute("""
            INSERT INTO kernel_dispatches_v1
                (project, run_id, task_id, generation, revision, operation, time_ns)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (project, run_id, task_id, generation, plan["revision"],
              json.dumps(operation, sort_keys=True, separators=(",", ":")), now)).lastrowid
    return {"authorised": True, "dispatch": seq, "run_id": run_id, "task_id": task_id,
            "generation": generation, "revision": plan["revision"], "operation": operation}
