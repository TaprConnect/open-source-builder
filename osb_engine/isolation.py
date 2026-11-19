"""Run a worker under OS isolation; the kernel is its only route to change the checkout.

Linux bubblewrap only. The worker sees the checkout (and its .git) read-only at
/work, supervisor inputs read-only at /inputs, a private writable outbox at
/outbox and an ephemeral /tmp. It gets no network, no store, no bearer token
and a cleared environment. After a successful exit the supervisor applies the
outbox patches through mutate() with the bearer it holds. Other hosts refuse.
"""
import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path

from .kernel import _live, _paused, _project, _schema, consume
from .mutation import MAX_PATCH, mutate

_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_MAX_OUTPUT = 1024 * 1024


def available():
    return sys.platform.startswith("linux") and shutil.which("bwrap") is not None


def _inside(path, parent):
    return path == parent or path.is_relative_to(parent)


def _command(root, outbox, inputs, argv, env=None):
    cmd = ["bwrap", "--unshare-all", "--die-with-parent", "--new-session", "--clearenv",
           "--cap-drop", "ALL", "--ro-bind", "/usr", "/usr"]
    for name in ("bin", "lib", "lib64", "sbin"):
        host = Path("/" + name)
        if host.is_symlink():
            cmd += ["--symlink", os.readlink(host), "/" + name]
        elif host.is_dir():
            cmd += ["--ro-bind", str(host), "/" + name]
    cmd += ["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
            "--ro-bind", str(root), "/work"]
    if outbox is not None:
        cmd += ["--bind", str(outbox), "/outbox"]
    for name, path in sorted(inputs.items()):
        cmd += ["--ro-bind", str(path), "/inputs/" + name]
    for key, value in sorted((env or {}).items()):
        cmd += ["--setenv", key, value]
    return cmd + ["--chdir", "/work", "--setenv", "HOME", "/tmp", "--setenv", "PATH",
                  "/usr/bin:/bin", "--", *argv]


def run_isolated(root, argv, inputs, timeout, env=None):
    """Run argv with the checkout read-only and no writable host path; return (code, stdout, stderr)."""
    if not available():
        raise ValueError("isolation unavailable on this host")
    try:
        result = subprocess.run(_command(root, None, inputs, list(argv), env), capture_output=True,
                                timeout=timeout, env={"PATH": "/usr/bin:/bin"}, stdin=subprocess.DEVNULL)
        return result.returncode, result.stdout[-_MAX_OUTPUT:], result.stderr[-_MAX_OUTPUT:]
    except subprocess.TimeoutExpired:
        return -1, b"", b"timeout"


def _patches(outbox):
    """Regular single-link *.patch files only; links and special files are refused."""
    found = []
    for entry in sorted(os.listdir(outbox)):
        if not entry.endswith(".patch"):
            continue
        path = outbox / entry
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_PATCH:
            found.append((entry, None, "outbox entry must be a regular single-link file within size"))
            continue
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as handle:
            found.append((entry, handle.read(MAX_PATCH + 1), None))
    return found


def run_worker(store, run_id, task_id, generation, token, outbox, argv, inputs=None, timeout=600):
    if not available():
        raise ValueError("worker isolation unavailable on this host")
    if not argv:
        raise ValueError("worker command required")
    if type(timeout) is not int or not 1 <= timeout <= 3600:
        raise ValueError("worker timeout must be 1 to 3600 seconds")
    repo = store.repo
    root, common = repo.root, repo.common
    database = Path(store.conn.execute("PRAGMA database_list").fetchone()[2]).resolve()
    outbox = Path(outbox)
    if outbox.is_symlink() or not outbox.is_dir() or os.listdir(outbox):
        raise ValueError("outbox must be an existing empty directory")
    outbox = outbox.resolve()
    protected = (root, common, database.parent)
    if any(_inside(outbox, p) or _inside(p, outbox) for p in protected):
        raise ValueError("outbox must be separate from the checkout, Git metadata and store")
    checked = {}
    for name, path in (inputs or {}).items():
        path = Path(path)
        if not _NAME.fullmatch(name) or path.is_symlink() or not path.is_file():
            raise ValueError("inputs must be named regular files")
        path = path.resolve()
        if any(_inside(path, p) for p in (database.parent, outbox)):
            raise ValueError("inputs must not expose the store or outbox")
        checked[name] = path
    if _inside(database, root) or _inside(database, common):
        raise ValueError("store must be outside the checkout")
    repo.assert_current()
    conn, project = store.conn, _project(store)
    with conn:
        conn.execute("BEGIN IMMEDIATE")
        _schema(conn)
        if _paused(conn, project):
            raise ValueError("project dispatch paused")
        _live(store, run_id, task_id, generation, token)
        consume(conn, project, run_id, task_id, "worker")
    try:
        result = subprocess.run(_command(root, outbox, checked, list(argv)), capture_output=True,
                                timeout=timeout, env={"PATH": "/usr/bin:/bin"}, stdin=subprocess.DEVNULL)
        code, out, err = result.returncode, result.stdout[-_MAX_OUTPUT:], result.stderr[-_MAX_OUTPUT:]
    except subprocess.TimeoutExpired:
        code, out, err = -1, b"", b"timeout"
    applied = []
    if code == 0:
        for name, data, problem in _patches(outbox):
            if problem is None:
                try:
                    record = mutate(store, run_id, task_id, generation, token, data)
                    applied.append({"patch": name, "applied": True, "dispatch": record["dispatch"]})
                    continue
                except ValueError as exc:
                    problem = str(exc)
            applied.append({"patch": name, "applied": False, "error": problem})
    return {"returncode": code, "stdout": out.decode("utf-8", "replace"),
            "stderr": err.decode("utf-8", "replace"), "patches": applied}
