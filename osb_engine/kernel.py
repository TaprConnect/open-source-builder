"""Operator-managed reservations in one trusted local store per project.

Use a single private database outside worker access. A reservation grants no
permission to run commands or modify a checkout. An expired task retains its
project slot until a supervisor recovers it. Completion is a separate gate.

The supervisor grants an explicit operation scope to one lease generation and
calls dispatch immediately before each controlled mutation. Dispatch is an
admission check plus audit record. It does not confine the worker afterwards.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import subprocess
import tempfile
import time

_KIND = re.compile(r"[a-z][a-z0-9_.-]{0,63}")
_MAX_PATHS = 256


def _token_hash(token):
    return hashlib.sha256(token.encode("utf-8")).digest()


def _project(store):
    return os.path.normcase(str(store.repo.common))


_EXTRA_TABLES = (
    """CREATE TABLE IF NOT EXISTS kernel_settings_v1 (project TEXT PRIMARY KEY, eol TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS kernel_journal_commits_v1 (op TEXT PRIMARY KEY)""",
    """CREATE TABLE IF NOT EXISTS kernel_flags_v1 (project TEXT NOT NULL, name TEXT NOT NULL, value INTEGER NOT NULL, PRIMARY KEY(project, name))""",
    """CREATE TABLE IF NOT EXISTS kernel_approvals_v1 (project TEXT NOT NULL, generation INTEGER NOT NULL, digest TEXT NOT NULL, used INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(project, generation, digest))""",
    """CREATE TABLE IF NOT EXISTS kernel_quotas_v1 (project TEXT NOT NULL, run_id TEXT NOT NULL, task_id TEXT NOT NULL, kind TEXT NOT NULL, quota INTEGER NOT NULL, PRIMARY KEY(project, run_id, task_id, kind))""",
    """CREATE TABLE IF NOT EXISTS kernel_usage_v1 (seq INTEGER PRIMARY KEY, project TEXT NOT NULL, run_id TEXT NOT NULL, task_id TEXT NOT NULL, kind TEXT NOT NULL, time_ns INTEGER NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS kernel_exclusions_v1 (project TEXT NOT NULL, prefix TEXT NOT NULL, PRIMARY KEY(project, prefix))""",
    """CREATE TABLE IF NOT EXISTS kernel_patches_v1 (
            dispatch INTEGER PRIMARY KEY, project TEXT NOT NULL, run_id TEXT NOT NULL,
            task_id TEXT NOT NULL, generation INTEGER NOT NULL, patch BLOB NOT NULL,
            paths TEXT NOT NULL, reverted INTEGER NOT NULL DEFAULT 0)""",
    """CREATE TABLE IF NOT EXISTS kernel_acceptance_v1 (
            project TEXT NOT NULL, run_id TEXT NOT NULL, task_id TEXT NOT NULL,
            digest TEXT NOT NULL, PRIMARY KEY(project, run_id, task_id))""",
    """CREATE TABLE IF NOT EXISTS kernel_verifications_v1 (
            seq INTEGER PRIMARY KEY, project TEXT NOT NULL, run_id TEXT NOT NULL,
            task_id TEXT NOT NULL, generation INTEGER NOT NULL, revision TEXT NOT NULL,
            acceptance TEXT NOT NULL, state TEXT NOT NULL, returncode INTEGER NOT NULL,
            passed INTEGER NOT NULL, output_sha256 TEXT NOT NULL, time_ns INTEGER NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS kernel_completions_v1 (
            project TEXT NOT NULL, run_id TEXT NOT NULL, task_id TEXT NOT NULL,
            generation INTEGER NOT NULL, revision TEXT NOT NULL, verification INTEGER NOT NULL,
            state TEXT NOT NULL, time_ns INTEGER NOT NULL, PRIMARY KEY(project, run_id, task_id))""",
    """CREATE TABLE IF NOT EXISTS kernel_releases_v1 (
            project TEXT NOT NULL, generation INTEGER NOT NULL, run_id TEXT NOT NULL,
            task_id TEXT NOT NULL, reason TEXT NOT NULL, PRIMARY KEY(project, generation))""",
    """CREATE TABLE IF NOT EXISTS kernel_dependencies_v1 (
            project TEXT NOT NULL, run_id TEXT NOT NULL, task_id TEXT NOT NULL,
            requires TEXT NOT NULL, PRIMARY KEY(project, run_id, task_id, requires))""",
)


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
    conn.execute("""
        CREATE TABLE IF NOT EXISTS kernel_ledger_v1 (
            project TEXT NOT NULL,
            path TEXT NOT NULL,
            baseline TEXT,
            current TEXT,
            run_id TEXT NOT NULL,
            task_id TEXT NOT NULL,
            generation INTEGER NOT NULL,
            PRIMARY KEY(project, path)
        )
    """)
    for statement in _EXTRA_TABLES:
        conn.execute(statement)


def completed(conn, project, run_id, task_id):
    return conn.execute("""SELECT 1 FROM kernel_completions_v1
        WHERE project=? AND run_id=? AND task_id=?""", (project, run_id, task_id)).fetchone() is not None


def _finished(conn, project, row):
    """True when the slot holder completed its task or the supervisor released this generation."""
    return completed(conn, project, row[0], row[1]) or conn.execute(
        "SELECT 1 FROM kernel_releases_v1 WHERE project=? AND generation=?",
        (project, row[2])).fetchone() is not None


def digest(root, path):
    """SHA-256 of a worktree file's bytes (plus its POSIX executable bit), or None when absent."""
    full = os.path.join(root, *path.split("/"))
    try:
        with open(full, "rb") as handle:
            value = hashlib.sha256(handle.read()).hexdigest()
    except FileNotFoundError:
        return None
    if os.name == "posix" and os.stat(full).st_mode & 0o111:
        value += ":x"
    return value


def worktree_changes(repo, eol="none", exclude=()):
    """Paths whose worktree content or mode differs from the pinned revision, plus every
    untracked path. Independent of the live index, Git's stat cache and ignore rules."""
    root = str(repo.root)
    with tempfile.TemporaryDirectory() as tmp:
        env = {"GIT_INDEX_FILE": os.path.join(tmp, "index")}
        repo.git("read-tree", repo.revision, extra_env=env)
        others = repo.git("ls-files", "-z", "--others", extra_env=env)
    changed = {path for path in (os.fsdecode(p).rstrip("/") for p in others.split(b"\0") if p)
               if not any((path + "/").startswith(prefix) for prefix in exclude)}
    regular = []
    for entry in repo.git("ls-tree", "-r", "-z", "--full-tree", repo.revision).split(b"\0"):
        if not entry:
            continue
        header, raw = entry.split(b"\t", 1)
        mode, _, oid = header.decode("ascii").split()
        path = os.fsdecode(raw)
        full = os.path.join(root, *path.split("/"))
        if mode in ("100644", "100755"):
            if "\n" in path or os.path.islink(full) or not os.path.isfile(full):
                changed.add(path)
            elif os.name == "posix" and bool(os.stat(full).st_mode & 0o111) != (mode == "100755"):
                changed.add(path)
            else:
                regular.append((path, oid))
        elif mode == "120000":
            target = os.readlink(full).encode() if os.path.islink(full) else None
            if target is None or repo.git("hash-object", "--stdin", data=target).decode().strip() != oid:
                changed.add(path)
        else:
            changed.update(_submodule_changes(full, path, oid, eol))
    if regular:
        # Byte-exact, computed by the kernel: no .gitattributes filter or Git configuration
        # can normalise tampering away. Under the supervisor's crlf policy the only other
        # accepted form is the complete LF->CRLF conversion of an LF-only text blob.
        algorithm = repo.git("rev-parse", "--show-object-format").decode().strip() or "sha1"
        blob_id = lambda data: hashlib.new(algorithm, b"blob %d\0" % len(data) + data).hexdigest()
        for path, oid in regular:
            with open(os.path.join(root, *path.split("/")), "rb") as handle:
                data = handle.read()
            if _matches(data, oid, eol, blob_id):
                continue
            changed.add(path)
    return changed


def _matches(data, oid, eol, blob_id):
    """Accept the raw blob, Git's exact ident expansion of this blob's own id, and under
    the crlf policy the complete LF->CRLF conversion of an LF-only text blob."""
    candidates = [data]
    if eol == "crlf" and b"\0" not in data:
        lf = data.replace(b"\r\n", b"\n")
        if b"\r" not in lf and lf.replace(b"\n", b"\r\n") == data:
            candidates.append(lf)
    expanded = b"$Id: " + oid.encode() + b" $"
    for candidate in candidates:
        if blob_id(candidate) == oid or expanded in candidate and blob_id(
                candidate.replace(expanded, b"$Id$")) == oid:
            return True
    return False


def _submodule_changes(full, path, oid, eol):
    """A gitlink is unchanged only if the nested checkout sits at the recorded commit and
    its own worktree passes the full comparison; anything unverifiable is reported."""
    from .repository import Repository
    try:
        nested = Repository(full)
        if nested.revision != oid:
            return {path}
        return {path + "/" + p for p in worktree_changes(nested, eol)}
    except (ValueError, OSError, subprocess.SubprocessError):
        return {path}


def policy(conn, project):
    """(eol, untracked exclusion prefixes) declared by the supervisor."""
    rows = conn.execute("SELECT prefix FROM kernel_exclusions_v1 WHERE project=? ORDER BY prefix",
                        (project,)).fetchall()
    return _eol(conn, project), tuple(r[0] for r in rows)


def journal_path(store):
    return store.conn.execute("PRAGMA database_list").fetchone()[2] + ".journal"


def begin_journal(store, paths):
    """Durably snapshot paths before a worktree change; returns the operation id."""
    path = journal_path(store)
    if os.path.exists(path):
        raise ValueError("interrupted operation pending; run recover")
    root, snapshot = str(store.repo.root), {}
    for rel in paths:
        full = os.path.join(root, *rel.split("/"))
        try:
            with open(full, "rb") as handle:
                data = handle.read()
            snapshot[rel] = {"data": base64.b64encode(data).decode("ascii"),
                             "mode": os.stat(full).st_mode & 0o777}
        except FileNotFoundError:
            snapshot[rel] = None
    op = secrets.token_hex(16)
    tmp = path + ".new"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        json.dump({"op": op, "project": _project(store), "paths": snapshot}, handle)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)
    if os.name == "posix":
        dirfd = os.open(os.path.dirname(path), os.O_RDONLY)
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
    return op


def commit_journal(conn, op):
    conn.execute("INSERT INTO kernel_journal_commits_v1 VALUES (?)", (op,))


def end_journal(store):
    try:
        os.unlink(journal_path(store))
    except FileNotFoundError:
        pass


def _restore(root, snapshot):
    for rel, entry in sorted(snapshot.items()):
        full = os.path.join(root, *rel.split("/"))
        if entry is None:
            if os.path.lexists(full):
                os.unlink(full)
            continue
        os.makedirs(os.path.dirname(full), exist_ok=True)
        tmp = full + ".osb-restore"
        with open(tmp, "wb") as handle:
            handle.write(base64.b64decode(entry["data"]))
        if os.name == "posix":
            os.chmod(tmp, entry["mode"])
        os.replace(tmp, full)


def recover(store):
    """Supervisor resolves an interrupted operation: adopt it if committed, else restore snapshots."""
    conn, project = store.conn, _project(store)
    with conn:
        conn.execute("BEGIN IMMEDIATE")
        _schema(conn)
        path = journal_path(store)
        if not os.path.exists(path):
            return {"recovered": False}
        with open(path) as handle:
            journal = json.load(handle)
        if journal.get("project") != project:
            raise ValueError("journal belongs to a different project")
        committed = conn.execute("SELECT 1 FROM kernel_journal_commits_v1 WHERE op=?",
                                 (journal["op"],)).fetchone() is not None
        if not committed:
            _restore(str(store.repo.root), journal["paths"])
        os.unlink(path)
    return {"recovered": True, "action": "adopted" if committed else "restored",
            "paths": sorted(journal["paths"])}


def approval_required(conn, project):
    row = conn.execute("SELECT value FROM kernel_flags_v1 WHERE project=? AND name='require_approval'",
                       (project,)).fetchone()
    return bool(row and row[0])


def approve(store, run_id, task_id, generation, patch):
    """Supervisor approves one exact patch for one live lease generation (single use)."""
    if type(patch) is not bytes or not patch:
        raise ValueError("patch required")
    digest_value = hashlib.sha256(patch).hexdigest()
    conn, project = store.conn, _project(store)
    with conn:
        conn.execute("BEGIN IMMEDIATE")
        _schema(conn)
        _live(store, run_id, task_id, generation)
        conn.execute("INSERT OR IGNORE INTO kernel_approvals_v1 (project, generation, digest) VALUES (?, ?, ?)",
                     (project, generation, digest_value))
    return {"run_id": run_id, "task_id": task_id, "generation": generation, "patch_sha256": digest_value}


def use_approval(conn, project, generation, patch):
    """Inside the admitting transaction: consume the approval for this exact patch or refuse."""
    if not approval_required(conn, project):
        return
    digest_value = hashlib.sha256(patch).hexdigest()
    updated = conn.execute("""UPDATE kernel_approvals_v1 SET used=1
        WHERE project=? AND generation=? AND digest=? AND used=0""",
                           (project, generation, digest_value)).rowcount
    if updated != 1:
        raise ValueError("patch not approved for this reservation (approvals bind the exact patch once)")


QUOTA_KINDS = ("mutate", "verify", "worker")


def set_quota(store, run_id, task_id, kind, limit):
    """Supervisor caps how many times a task may mutate, verify or run a worker."""
    if kind not in QUOTA_KINDS:
        raise ValueError("quota kind must be mutate, verify or worker")
    if type(limit) is not int or not 0 <= limit <= 100000:
        raise ValueError("quota limit must be 0 to 100000")
    conn, project = store.conn, _project(store)
    with conn:
        conn.execute("BEGIN IMMEDIATE")
        _schema(conn)
        if not any(t["id"] == task_id for t in store.view(run_id)["tasks"]):
            raise ValueError("unknown plan task")
        conn.execute("""INSERT INTO kernel_quotas_v1 VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(project, run_id, task_id, kind) DO UPDATE SET quota=excluded.quota""",
                     (project, run_id, task_id, kind, limit))
    return {"run_id": run_id, "task_id": task_id, "kind": kind, "limit": limit}


def consume(conn, project, run_id, task_id, kind):
    """Record one use inside the caller's write transaction, refusing beyond the quota."""
    row = conn.execute("SELECT quota FROM kernel_quotas_v1 WHERE project=? AND run_id=? AND task_id=? AND kind=?",
                       (project, run_id, task_id, kind)).fetchone()
    if row is not None:
        used = conn.execute("SELECT COUNT(*) FROM kernel_usage_v1 WHERE project=? AND run_id=? AND task_id=? AND kind=?",
                            (project, run_id, task_id, kind)).fetchone()[0]
        if used >= row[0]:
            raise ValueError(f"{kind} quota exhausted")
    conn.execute("INSERT INTO kernel_usage_v1 (project, run_id, task_id, kind, time_ns) VALUES (?, ?, ?, ?, ?)",
                 (project, run_id, task_id, kind, time.time_ns()))


_EOL = ("none", "crlf")


def _eol(conn, project):
    row = conn.execute("SELECT eol FROM kernel_settings_v1 WHERE project=?", (project,)).fetchone()
    return row[0] if row else "none"


def configure(store, eol=None, exclude=(), clear_excludes=False, require_approval=None):
    """Supervisor declares line-ending policy and untracked directories that are not evidence."""
    if eol is not None and eol not in _EOL:
        raise ValueError("eol policy must be none or crlf")
    for prefix in exclude:
        if not prefix.endswith("/"):
            raise ValueError("exclusions are directory prefixes ending in /")
        _path(prefix)
    conn, project = store.conn, _project(store)
    with conn:
        conn.execute("BEGIN IMMEDIATE")
        _schema(conn)
        if eol is not None:
            conn.execute("""INSERT INTO kernel_settings_v1 (project, eol) VALUES (?, ?)
                ON CONFLICT(project) DO UPDATE SET eol=excluded.eol""", (project, eol))
        if clear_excludes:
            conn.execute("DELETE FROM kernel_exclusions_v1 WHERE project=?", (project,))
        conn.executemany("INSERT OR IGNORE INTO kernel_exclusions_v1 VALUES (?, ?)",
                         [(project, prefix) for prefix in exclude])
        if require_approval is not None:
            conn.execute("""INSERT INTO kernel_flags_v1 VALUES (?, 'require_approval', ?)
                ON CONFLICT(project, name) DO UPDATE SET value=excluded.value""", (project, int(bool(require_approval))))
        current = policy(conn, project)
        required = approval_required(conn, project)
    return {"eol": current[0], "exclude": list(current[1]), "require_approval": required}


def integrity(store, conn):
    """Return out-of-band changes: unrecorded changed paths or ledger hash mismatches."""
    if os.path.exists(journal_path(store)):
        raise ValueError("interrupted operation pending; run recover")
    ledger = dict(conn.execute("SELECT path, current FROM kernel_ledger_v1 WHERE project=?",
                               (_project(store),)).fetchall())
    root = str(store.repo.root)
    problems = sorted(p for p in worktree_changes(store.repo, *policy(conn, _project(store))) if p not in ledger)
    problems += sorted(p for p, h in ledger.items() if digest(root, p) != h)
    return problems


def granted_scope(conn, project, run_id, task_id, generation, revision):
    row = conn.execute("""
        SELECT run_id, task_id, revision, scope FROM kernel_grants_v1
        WHERE project=? AND generation=?
    """, (project, generation)).fetchone()
    if not row or tuple(row[:2]) != (run_id, task_id):
        raise ValueError("no operation scope granted to this reservation")
    if row[2] != revision:
        raise ValueError("grant bound to a different revision")
    return json.loads(row[3])


def covered(kind, paths, scope):
    granted = [g["paths"] for g in scope if g["kind"] == kind]
    return all(any(_covered(p, g) for g in granted) for p in paths)


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


_GIT_CONTROL = {".gitignore", ".gitattributes", ".gitmodules"}


def _covered(path, granted):
    """Exact grants cover a path; directory grants never cover Git control files."""
    control = path.rstrip("/").rsplit("/", 1)[-1].lower() in _GIT_CONTROL
    return any(path == g or not control and g.endswith("/") and path.startswith(g) for g in granted)


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
        if row and row[:2] != (run_id, task_id) and not _finished(conn, project, row):
            raise ValueError("another task retains this project reservation")
        now = time.time_ns()
        expires = now + seconds * 1_000_000_000
        if renewal is None:
            if row and row[:2] == (run_id, task_id) and row[4] > now:
                raise ValueError("task already reserved")
            if _paused(conn, project):
                raise ValueError("project dispatch paused")
            if completed(conn, project, run_id, task_id):
                raise ValueError("task already completed")
            missing = [r for (r,) in conn.execute("""SELECT requires FROM kernel_dependencies_v1
                WHERE project=? AND run_id=? AND task_id=?""", (project, run_id, task_id))
                if not completed(conn, project, run_id, r)]
            if missing:
                raise ValueError("prerequisite tasks are not completed")
            if integrity(store, conn):
                raise ValueError("out-of-band worktree changes detected")
            generation = row[2] + 1 if row else 1
            token = secrets.token_urlsafe(32)
            conn.execute("""
                INSERT INTO kernel_reservations_v1
                    (project, run_id, task_id, generation, token_hash, expires_ns)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(project) DO UPDATE SET
                    run_id=excluded.run_id, task_id=excluded.task_id,
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
        scope = granted_scope(conn, project, run_id, task_id, generation, plan["revision"])
        if not covered(operation["kind"], operation["paths"], scope):
            raise ValueError("operation outside granted scope")
        if integrity(store, conn):
            raise ValueError("out-of-band worktree changes detected")
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
