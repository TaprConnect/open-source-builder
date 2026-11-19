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


_PROBE = None


def available():
    """True only if bubblewrap can actually create the sandbox here (probed once per process).

    A present but unusable binary (for example inside another sandbox that forbids user
    namespaces) must count as unavailable, or callers would silently degrade."""
    global _PROBE
    if _PROBE is None:
        _PROBE = False
        if sys.platform.startswith("linux") and shutil.which("bwrap") is not None:
            try:
                import tempfile
                with tempfile.TemporaryDirectory() as probe_root:
                    # Same command builder as real runs, so a pass proves the real configuration.
                    _PROBE = subprocess.run(_command(probe_root, None, {}, ["prlimit", "--cpu=5", "--",
                                                                           "python3", "-I", "-c", "pass"]),
                                            capture_output=True, timeout=20, stdin=subprocess.DEVNULL,
                                            env={"PATH": "/usr/bin:/bin"}).returncode == 0
            except subprocess.TimeoutExpired:
                _PROBE = None  # transient: do not pin a negative result
                return False
            except (OSError, subprocess.SubprocessError):
                _PROBE = False
    return _PROBE


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
            ] + ([] if root is None else ["--ro-bind", str(root), "/work"])
    if outbox is not None:
        cmd += ["--bind", str(outbox), "/outbox"]
    for name, path in sorted(inputs.items()):
        cmd += ["--ro-bind", str(path), "/inputs/" + name]
    for key, value in sorted((env or {}).items()):
        cmd += ["--setenv", key, value]
    return cmd + ["--chdir", "/tmp" if root is None else "/work", "--setenv", "HOME", "/tmp", "--setenv", "PATH",
                  "/usr/bin:/bin", "--", *argv]


_HARD_CAP = 16 * 1024 * 1024


def _bounded_run(cmd, timeout, stdin_data=b"", cap=_HARD_CAP, pass_fds=(), on_start=None, register=None):
    """Run cmd streaming its output; kill it if stdout or stderr exceeds cap or time runs out.

    Returns (code, stdout, stderr) with code -1 on timeout and -2 on output overflow. The
    supervisor never buffers more than cap + one read per stream."""
    import threading
    try:
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env={"PATH": "/usr/bin:/bin"}, start_new_session=True, pass_fds=pass_fds)
    finally:
        if on_start:
            on_start()
    if register:
        register(proc)
    overflow = threading.Event()
    buffers = {"out": [], "err": []}

    def drain(stream, key):
        total = 0
        while True:
            chunk = stream.read(65536)
            if not chunk:
                return
            total += len(chunk)
            if total > cap:
                overflow.set()
                proc.kill()
                return
            buffers[key].append(chunk)

    def feed():
        try:
            if stdin_data:
                proc.stdin.write(stdin_data)
        except (BrokenPipeError, OSError):
            pass
        finally:
            try:
                proc.stdin.close()
            except OSError:
                pass

    threads = [threading.Thread(target=drain, args=(proc.stdout, "out"), daemon=True),
               threading.Thread(target=drain, args=(proc.stderr, "err"), daemon=True),
               threading.Thread(target=feed, daemon=True)]
    for thread in threads:
        thread.start()
    timed_out = False
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        proc.kill()
        proc.wait()
    for thread in threads:
        thread.join(timeout=5)
    out, err = b"".join(buffers["out"]), b"".join(buffers["err"])
    if overflow.is_set():
        return -2, b"", b"output limit exceeded"
    if timed_out:
        return -1, b"", b"timeout"
    return proc.returncode, out, err


def run_external(root, inputs, argv, stdin_data, timeout, max_requests=256, command_timeout=300,
                 limits=(120, 2048)):
    """Run a trusted acceptance with NO checkout access; it reaches repository code only by
    asking this broker to run commands, each in a separate isolated sandbox (own PID
    namespace, checkout read-only). Command results return to the acceptance as data."""
    import base64
    import json
    import threading
    import time
    if not available():
        raise ValueError("isolation unavailable on this host")
    req_r, req_w = os.pipe()
    resp_r, resp_w = os.pipe()
    deadline = time.monotonic() + timeout
    stop = threading.Event()
    current = {}

    def track(proc):
        current["proc"] = proc
        if stop.is_set():
            proc.kill()

    def broker():
        count = 0
        with os.fdopen(req_r, "rb") as requests, os.fdopen(resp_w, "wb", buffering=0) as replies:
            while True:
                line = requests.readline(8 * 1024 * 1024 + 1)
                if not line or stop.is_set():
                    return
                if len(line) > 8 * 1024 * 1024:
                    replies.write(b'{"error": "request too large; broker stopped"}\n')
                    return
                count += 1
                try:
                    if count > max_requests:
                        raise ValueError("broker request limit reached")
                    left = deadline - time.monotonic()
                    if left <= 1 or len(line) > 8 * 1024 * 1024:
                        raise ValueError("broker time or size limit reached")
                    message = json.loads(line)
                    command = [str(a) for a in message["argv"]]
                    if not command:
                        raise ValueError("empty command")
                    data = base64.b64decode(message.get("stdin", ""))
                    code, out, err = run_isolated(root, command, {}, max(1, min(int(message.get("timeout", 60)),
                                                                              command_timeout, left - 1)),
                                                  {"PYTHONDONTWRITEBYTECODE": "1"}, data, limits=limits,
                                                  max_output=8 * 1024 * 1024, register=track)
                    reply = {"code": code, "stdout": base64.b64encode(out).decode("ascii"),
                             "stderr": base64.b64encode(err[-65536:]).decode("ascii")}
                except Exception as exc:  # reported to the acceptance, never trusted
                    reply = {"error": str(exc)[:200]}
                try:
                    replies.write(json.dumps(reply).encode() + b"\n")
                except OSError:
                    return

    thread = threading.Thread(target=broker, daemon=True)
    thread.start()

    def started():
        os.close(req_w)
        os.close(resp_r)

    cmd = _command(None, None, inputs, list(argv) + [str(req_w), str(resp_r)], {"PYTHONDONTWRITEBYTECODE": "1"})
    code, out, err = _bounded_run(cmd, timeout, stdin_data, pass_fds=(req_w, resp_r), on_start=started)
    stop.set()
    proc = current.get("proc")
    if proc is not None and proc.poll() is None:
        proc.kill()
    thread.join()
    return code, out[-_MAX_OUTPUT:], err[-_MAX_OUTPUT:]


def run_isolated(root, argv, inputs, timeout, env=None, stdin_data=b"", limits=None, max_output=None, register=None):
    """Run argv with the checkout read-only and no writable host path; return (code, stdout, stderr)."""
    if not available():
        raise ValueError("isolation unavailable on this host")
    argv = list(argv)
    if limits:
        cpu, memory_mib = limits
        argv = ["prlimit", f"--cpu={int(cpu)}", f"--as={int(memory_mib) * 1024 * 1024}",
                "--nofile=64", "--nproc=64", "--"] + argv
    code, out, err = _bounded_run(_command(root, None, inputs, argv, env), timeout, stdin_data,
                                  _HARD_CAP if max_output is None else max_output, register=register)
    if max_output is None:
        out = out[-_MAX_OUTPUT:]
    return code, out, err[-_MAX_OUTPUT:]


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
    code, out, err = _bounded_run(_command(root, outbox, checked, list(argv)), timeout)
    out, err = out[-_MAX_OUTPUT:], err[-_MAX_OUTPUT:]
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
