"""Supervisor-mediated application of worker patches.

The supervisor is the only writer. Admission, filesystem checks, application,
post-checks and the audit/ledger record share one write transaction, so a
pause, revocation or grant change cannot commit between check and apply.
This detects, but cannot prevent, writes by a worker that can reach the
checkout; isolate workers at the OS level for prevention.
"""
import hashlib
import json
import os
import stat
import subprocess
import time

from .kernel import (_eol, _live, _path, _paused, _project, _schema, covered, digest,
                     granted_scope, integrity, worktree_changes)

MAX_PATCH = 8 * 1024 * 1024
_MODES = ("100644", "100755")
_REPARSE = 0x400


def _changes(repo, patch):
    """Return {path: kind} for a plain text patch, rejecting renames, copies and special modes."""
    kinds = {}
    for line in repo.git("apply", "--summary", "-", data=patch).decode("utf-8", "strict").splitlines():
        words = line.split()
        if not words:
            continue
        if words[0] in ("rename", "copy"):
            raise ValueError("renames and copies must be explicit delete and create")
        if words[0] in ("create", "delete"):
            if words[1] == "mode":
                if len(words) < 4 or words[2] not in _MODES:
                    raise ValueError("only regular file modes are allowed")
                path = " ".join(words[3:])
            else:
                path = " ".join(words[1:])
            if words[0] == "delete":
                kinds[_path(path)] = "delete"
        elif words[:2] == ["mode", "change"]:
            if words[4] not in _MODES:
                raise ValueError("only regular file modes are allowed")
        else:
            raise ValueError("unrecognised patch summary")
    records = repo.git("apply", "--numstat", "-z", "-", data=patch).split(b"\0")
    paths = []
    for record in records:
        if not record:
            continue
        fields = record.split(b"\t", 2)
        if len(fields) != 3 or not fields[2] or fields[0] == b"-":
            raise ValueError("binary, renamed or malformed patch entry")
        paths.append(_path(fields[2].decode("utf-8", "strict")))
    if len(paths) != len(set(paths)):
        raise ValueError("a path may appear only once per patch")
    if not paths or set(kinds) - set(paths):
        raise ValueError("patch changes no files")
    return {p: kinds.get(p, "edit") for p in paths}


def _safe_target(root, rel):
    """Refuse links, reparse points, nested repositories, case aliases and multi-link files."""
    current = root
    parts = rel.split("/")
    for index, part in enumerate(parts):
        names = os.listdir(current)
        if part not in names:
            if any(name.lower() == part.lower() for name in names):
                raise ValueError("path differs only in case from an existing entry")
            return
        current = os.path.join(current, part)
        info = os.lstat(current)
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & _REPARSE:
            raise ValueError("path crosses a symbolic link or reparse point")
        if index < len(parts) - 1:
            if not stat.S_ISDIR(info.st_mode):
                raise ValueError("path component is not a directory")
            if ".git" in (n.lower() for n in os.listdir(current)):
                raise ValueError("path enters a nested repository")
        elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("target must be a regular single-link file")


def _apply(repo, patch, reverse=False):
    repo.git("apply", *(["-R"] if reverse else []), "--whitespace=nowarn", "-", data=patch)


def mutate(store, run_id, task_id, generation, token, patch):
    """Admit and apply one worker patch, or raise leaving the worktree and store unchanged."""
    if type(patch) is not bytes or not patch or len(patch) > MAX_PATCH or b"\0" in patch:
        raise ValueError("invalid patch size or encoding")
    repo, conn, project = store.repo, store.conn, _project(store)
    root = str(repo.root)
    with conn:
        conn.execute("BEGIN IMMEDIATE")
        _schema(conn)
        if _paused(conn, project):
            raise ValueError("project dispatch paused")
        plan = _live(store, run_id, task_id, generation, token)
        scope = granted_scope(conn, project, run_id, task_id, generation, plan["revision"])
        try:
            changes = _changes(repo, patch)
        except subprocess.CalledProcessError as exc:
            raise ValueError("patch rejected by git apply") from exc
        for kind in ("edit", "delete"):
            if not covered(kind, [p for p, k in changes.items() if k == kind], scope):
                raise ValueError("patch outside granted scope")
        if integrity(store, conn):
            raise ValueError("out-of-band worktree changes detected")
        for path in changes:
            _safe_target(root, path)
        before = {p: digest(root, p) for p in changes}
        try:
            repo.git("apply", "--check", "--whitespace=nowarn", "-", data=patch)
        except subprocess.CalledProcessError as exc:
            raise ValueError("patch does not apply cleanly") from exc
        _apply(repo, patch)
        try:
            repo.assert_current()
            for path in changes:
                _safe_target(root, path)
            ledger = dict(conn.execute("SELECT path, current FROM kernel_ledger_v1 WHERE project=?",
                                       (project,)).fetchall())
            stray = [p for p in worktree_changes(repo, _eol(conn, project)) if p not in changes and p not in ledger]
            stray += [p for p, h in ledger.items() if p not in changes and digest(root, p) != h]
            if stray:
                raise ValueError("changes outside the patch appeared during apply")
        except Exception as exc:
            try:
                _apply(repo, patch, reverse=True)
            except subprocess.CalledProcessError:
                raise ValueError("post-apply check failed and revert failed; supervisor recovery required") from exc
            raise ValueError(f"post-apply check failed; patch reverted: {exc}") from exc
        after = {p: digest(root, p) for p in changes}
        for path in changes:
            conn.execute("""
                INSERT INTO kernel_ledger_v1 (project, path, baseline, current, run_id, task_id, generation)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(project, path) DO UPDATE SET current=excluded.current,
                    run_id=excluded.run_id, task_id=excluded.task_id, generation=excluded.generation
            """, (project, path, before[path], after[path], run_id, task_id, generation))
        operation = {"kind": "mutate", "changes": sorted([k, p] for p, k in changes.items()),
                     "patch_sha256": hashlib.sha256(patch).hexdigest()}
        seq = conn.execute("""
            INSERT INTO kernel_dispatches_v1
                (project, run_id, task_id, generation, revision, operation, time_ns)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (project, run_id, task_id, generation, plan["revision"],
              json.dumps(operation, sort_keys=True, separators=(",", ":")), time.time_ns())).lastrowid
        conn.execute("""
            INSERT INTO kernel_patches_v1 (dispatch, project, run_id, task_id, generation, patch, paths)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (seq, project, run_id, task_id, generation, patch, json.dumps(sorted(changes))))
    return {"applied": True, "dispatch": seq, "run_id": run_id, "task_id": task_id,
            "generation": generation, "revision": plan["revision"], "operation": operation}
