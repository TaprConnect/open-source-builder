"""Local deterministic audit and persistent planning; never executes target code."""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess

MAX_BLOB = 2 * 1024 * 1024
MAX_TOTAL = 32 * 1024 * 1024


def git(root, *args):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
               GIT_NO_REPLACE_OBJECTS="1", GIT_OPTIONAL_LOCKS="0")
    return subprocess.check_output(["git", "-C", str(root), *args], env=env, timeout=30)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True).encode()).hexdigest()


def python_findings(source):
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError) as exc:
        return [("python.parse_error", getattr(exc, "lineno", None) or 1, "candidate")]
    findings = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        body = node.body[:]
        if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
            body.pop(0)
        if len(body) != 1:
            continue
        stmt = body[0]
        error = stmt.exc if isinstance(stmt, ast.Raise) else None
        if isinstance(error, ast.Call):
            error = error.func
        if (isinstance(stmt, ast.Pass) or
                isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant) and stmt.value.value is Ellipsis or
                isinstance(error, ast.Name) and error.id == "NotImplementedError"):
            findings.append(("python.placeholder_body", stmt.lineno, "candidate"))
    return findings


def audit(repository):
    root = Path(repository).resolve(strict=True)
    if git(root, "rev-parse", "--show-prefix").strip():
        raise ValueError("use repository root")
    revision = git(root, "rev-parse", "--verify", "HEAD^{commit}").decode().strip()
    rows, findings, cache = [], [], {}
    remaining = MAX_TOTAL
    for entry in git(root, "ls-tree", "-rlz", revision).split(b"\0"):
        if not entry:
            continue
        header, path_bytes = entry.split(b"\t", 1)
        mode, kind, oid, size = header.split()
        path, blob = os.fsdecode(path_bytes), oid.decode()
        row = {"path": path, "blob": blob, "status": "unsupported_language"}
        rows.append(row)
        if kind != b"blob" or mode == b"120000":
            row["status"] = "special_file"
        elif not path.endswith(".py"):
            continue
        elif int(size) > MAX_BLOB:
            row["status"] = "oversized"
        else:
            if blob not in cache:
                if int(size) > remaining:
                    row["status"] = "budget_blocked"
                    continue
                remaining -= int(size)
                try:
                    cache[blob] = ("analysed", python_findings(git(root, "cat-file", "blob", blob)))
                except (subprocess.SubprocessError, OSError):
                    cache[blob] = ("read_blocked", [])
            row["status"], candidates = cache[blob]
            for rule, line, status in candidates:
                key = digest([revision, path, blob, rule, line])
                findings.append(dict(id=key, path=path, blob=blob, rule=rule, line=line, status=status))
    return dict(schema=1, revision=revision, files=rows, findings=findings,
                runtime_verification="not_performed", semantic_review="not_performed")


def open_store(repository, db):
    root = Path(repository).resolve(strict=True)
    path = Path(db).resolve()
    common = (root / os.fsdecode(git(root, "rev-parse", "--git-common-dir").rstrip(b"\n"))).resolve()
    if path.is_relative_to(root) or path.is_relative_to(common):
        raise ValueError("store must be outside repository and Git metadata")
    if not path.parent.is_dir():
        raise ValueError("create a private store directory first")
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    os.close(fd)
    conn = sqlite3.connect(path, timeout=10)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("CREATE TABLE IF NOT EXISTS audits (id TEXT PRIMARY KEY, report TEXT NOT NULL)")
    conn.execute("CREATE TABLE IF NOT EXISTS tasks (audit_id TEXT NOT NULL REFERENCES audits(id), id TEXT NOT NULL, finding TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('open','blocked')), PRIMARY KEY(audit_id,id))")
    return conn, str(root)


def plan(repository, db):
    report = audit(repository)
    conn, root = open_store(repository, db)
    identifier = digest([root, report])
    try:
        with conn:
            conn.execute("INSERT OR IGNORE INTO audits VALUES (?,?)", (identifier, json.dumps(report)))
            conn.executemany("INSERT OR IGNORE INTO tasks VALUES (?,?,?,'open')",
                             [(identifier, f["id"], json.dumps(f)) for f in report["findings"]])
        return status(repository, db, identifier)
    finally:
        conn.close()


def status(repository, db, identifier):
    conn, root = open_store(repository, db)
    try:
        record = conn.execute("SELECT report FROM audits WHERE id=?", (identifier,)).fetchone()
        if record is None:
            raise ValueError("unknown audit")
        report = json.loads(record[0])
        if digest([root, report]) != identifier:
            raise ValueError("audit identity mismatch")
        current = git(root, "rev-parse", "--verify", "HEAD^{commit}").decode().strip()
        tasks = [dict(finding=json.loads(f), state=s) for f, s in conn.execute("SELECT finding,state FROM tasks WHERE audit_id=? ORDER BY id", (identifier,))]
        return dict(audit_id=identifier, revision=report["revision"], stale=current != report["revision"], tasks=tasks,
                    coverage=report["files"], release_ready=False, runtime_verification="not_performed")
    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("audit", "plan", "status"):
        cmd = sub.add_parser(name)
        cmd.add_argument("repository")
        if name != "audit":
            cmd.add_argument("database")
        if name == "status":
            cmd.add_argument("audit_id")
    args = parser.parse_args()
    try:
        if args.command == "audit":
            result = audit(args.repository)
        elif args.command == "plan":
            result = plan(args.repository, args.database)
        else:
            result = status(args.repository, args.database, args.audit_id)
    except (ValueError, OSError, sqlite3.Error, subprocess.SubprocessError) as exc:
        parser.exit(2, f"Audit blocked: {exc}\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
