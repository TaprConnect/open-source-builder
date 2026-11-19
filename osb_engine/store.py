"""Private local transaction store. Not a multi-tenant trust boundary."""
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)


def identity(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


class Store:
    def __init__(self, repository, path):
        self.repo = repository
        path = repository.private_path(path)
        if not path.parent.is_dir():
            raise ValueError('create an external private directory first')
        if os.name == 'posix' and path.parent.stat().st_mode & 0o077:
            raise ValueError('private directory must not grant group or other access (chmod 700)')
        if os.name == 'nt':
            from .winacl import unexpected_principals
            if unexpected_principals(path.parent):
                raise ValueError('private directory ACL grants access beyond the owner, SYSTEM and Administrators')
            if path.exists() and unexpected_principals(path):
                raise ValueError('private database ACL grants access beyond the owner, SYSTEM and Administrators')
        flags = os.O_CREAT | os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0)
        fd = os.open(path, flags, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or os.name == 'posix' and info.st_mode & 0o077:
                raise ValueError('private single-link database with owner-only permissions required')
        finally:
            os.close(fd)
        self.conn = sqlite3.connect(path, timeout=10)
        self.conn.execute('PRAGMA foreign_keys=ON')
        self.conn.executescript('''
        CREATE TABLE IF NOT EXISTS engine_cache (
            repository TEXT NOT NULL, oid TEXT NOT NULL, language TEXT NOT NULL,
            version TEXT NOT NULL, payload TEXT NOT NULL,
            PRIMARY KEY(repository, oid, language, version));
        CREATE TABLE IF NOT EXISTS engine_runs (
            id TEXT PRIMARY KEY, repository TEXT NOT NULL, revision TEXT NOT NULL, report TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS engine_tasks (
            run_id TEXT NOT NULL REFERENCES engine_runs(id), id TEXT NOT NULL,
            payload TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('open','investigating','blocked','proposed')),
            version INTEGER NOT NULL DEFAULT 0, reason TEXT NOT NULL DEFAULT '', PRIMARY KEY(run_id,id));
        CREATE TABLE IF NOT EXISTS engine_events (
            seq INTEGER PRIMARY KEY, run_id TEXT NOT NULL, task_id TEXT NOT NULL,
            previous TEXT NOT NULL, next TEXT NOT NULL, reason TEXT NOT NULL,
            FOREIGN KEY(run_id, task_id) REFERENCES engine_tasks(run_id,id));
        ''')

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.conn.close()

    def cached(self, oid, language, version):
        row = self.conn.execute('SELECT payload FROM engine_cache WHERE repository=? AND oid=? AND language=? AND version=?',
                                (str(self.repo.root), oid, language, version)).fetchone()
        return json.loads(row[0]) if row else None

    def cache(self, oid, language, version, payload):
        with self.conn:
            self.conn.execute('INSERT OR REPLACE INTO engine_cache VALUES (?,?,?,?,?)',
                              (str(self.repo.root), oid, language, version, canonical(payload)))

    def save(self, report):
        key = identity([str(self.repo.root), report])
        with self.conn:
            self.conn.execute('INSERT OR IGNORE INTO engine_runs VALUES (?,?,?,?)',
                              (key, str(self.repo.root), report['revision'], canonical(report)))
            self.conn.executemany('INSERT OR IGNORE INTO engine_tasks(run_id,id,payload,state) VALUES (?,?,?,\'open\')',
                                  [(key, f['id'], canonical(f)) for f in report['findings']])
        return key

    def view(self, key):
        row = self.conn.execute('SELECT revision,report FROM engine_runs WHERE id=? AND repository=?', (key, str(self.repo.root))).fetchone()
        if not row:
            raise ValueError('unknown audit for this repository')
        report = json.loads(row[1])
        if identity([str(self.repo.root), report]) != key or report['revision'] != row[0]:
            raise ValueError('stored report integrity mismatch')
        tasks = [dict(id=i, finding=json.loads(p), state=s, version=v, reason=r) for i,p,s,v,r in self.conn.execute(
            'SELECT id,payload,state,version,reason FROM engine_tasks WHERE run_id=? ORDER BY id', (key,))]
        return dict(run_id=key, revision=row[0], stale=self.repo.head()!=row[0], tasks=tasks,
                    report=report, release_ready=False)

    def transition(self, key, task, version, state, reason):
        allowed = {'open': {'investigating','blocked'}, 'investigating': {'blocked','proposed','open'},
                   'blocked': {'open','investigating'}, 'proposed': {'open','blocked'}}
        if not reason.strip() or len(reason) > 4000:
            raise ValueError('nonempty bounded reason required')
        with self.conn:
            self.conn.execute('BEGIN IMMEDIATE')
            view = self.view(key)
            if view['stale']:
                raise ValueError('stale audit')
            row = self.conn.execute('SELECT state,version FROM engine_tasks WHERE run_id=? AND id=?', (key, task)).fetchone()
            if not row or row[1] != version or state not in allowed[row[0]]:
                raise ValueError('invalid or conflicting transition')
            from .kernel import transition_guard
            transition_guard(self, key, task, row[0], state)
            self.conn.execute('UPDATE engine_tasks SET state=?,version=version+1,reason=? WHERE run_id=? AND id=?', (state,reason,key,task))
            self.conn.execute('INSERT INTO engine_events(run_id,task_id,previous,next,reason) VALUES (?,?,?,?,?)', (key,task,row[0],state,reason))
        return self.view(key)
