"""Private local transaction store. Not a multi-tenant trust boundary."""
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import time

SCHEMA_VERSION = 2


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
        CREATE TABLE IF NOT EXISTS engine_cache_v2 (
            key TEXT PRIMARY KEY, payload TEXT NOT NULL, payload_sha256 TEXT NOT NULL,
            size INTEGER NOT NULL, created_ns INTEGER NOT NULL, last_used_ns INTEGER NOT NULL);
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
        self._migrate()

    def _migrate(self):
        """Ordered, transactional schema migrations (F01-PLAN). Newer stores are refused."""
        version = self.conn.execute('PRAGMA user_version').fetchone()[0]
        if version > SCHEMA_VERSION:
            raise ValueError(f'store schema {version} is newer than this runtime supports ({SCHEMA_VERSION})')
        if version < 2:
            self.conn.execute('PRAGMA foreign_keys=OFF')
            try:
                with self.conn:
                    self.conn.execute('BEGIN IMMEDIATE')
                    self.conn.execute('''CREATE TABLE engine_tasks_v2 (
                        run_id TEXT NOT NULL REFERENCES engine_runs(id), id TEXT NOT NULL, payload TEXT NOT NULL,
                        state TEXT NOT NULL CHECK(state IN ('open','investigating','blocked','proposed','cancelled')),
                        version INTEGER NOT NULL DEFAULT 0, reason TEXT NOT NULL DEFAULT '',
                        fingerprint TEXT NOT NULL DEFAULT '', PRIMARY KEY(run_id,id))''')
                    rows = self.conn.execute('SELECT run_id,id,payload,state,version,reason FROM engine_tasks').fetchall()
                    self.conn.executemany('INSERT INTO engine_tasks_v2 VALUES (?,?,?,?,?,?,?)',
                                          [(*r, json.loads(r[2]).get('fingerprint', '')) for r in rows])
                    self.conn.execute('DROP TABLE engine_tasks')
                    self.conn.execute('ALTER TABLE engine_tasks_v2 RENAME TO engine_tasks')
                    self.conn.execute('CREATE TABLE IF NOT EXISTS engine_supersessions (run_id TEXT PRIMARY KEY, superseded_by TEXT NOT NULL)')
                    self.conn.execute('PRAGMA user_version=2')
            finally:
                self.conn.execute('PRAGMA foreign_keys=ON')

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

    # F01-CACHE: bounded, keyed, integrity-checked analysis cache (S03-004).
    def cache_key(self, oid, language, version, context):
        return identity([str(self.repo.root), oid, language, version, context])

    def cached_v2(self, key, validate):
        """Return a cached payload, or None. Digest or schema failures delete the entry."""
        row = self.conn.execute('SELECT payload, payload_sha256 FROM engine_cache_v2 WHERE key=?', (key,)).fetchone()
        if not row:
            return None
        try:
            value = json.loads(row[0]) if hashlib.sha256(row[0].encode()).hexdigest() == row[1] else None
        except ValueError:
            value = None
        if value is None or not validate(value):
            with self.conn:
                self.conn.execute('DELETE FROM engine_cache_v2 WHERE key=?', (key,))
            self.cache_corrupt = getattr(self, 'cache_corrupt', 0) + 1
            return None
        with self.conn:
            self.conn.execute('UPDATE engine_cache_v2 SET last_used_ns=? WHERE key=?', (time.time_ns(), key))
        return value

    def cache_v2(self, key, payload):
        text = canonical(payload)
        now = time.time_ns()
        with self.conn:
            self.conn.execute('INSERT OR REPLACE INTO engine_cache_v2 VALUES (?,?,?,?,?,?)',
                              (key, text, hashlib.sha256(text.encode()).hexdigest(), len(text), now, now))

    def evict(self, max_entries, max_bytes, retention_days):
        """Deterministic eviction: expired first, then least recently used (ties by key)."""
        if not (1 <= max_entries <= 10**7 and 1 <= max_bytes <= 2**40 and 0 <= retention_days <= 3650):
            raise ValueError('cache limits out of range')
        with self.conn:
            self.conn.execute('BEGIN IMMEDIATE')
            cutoff = time.time_ns() - retention_days * 86400 * 10**9
            self.conn.execute('DELETE FROM engine_cache_v2 WHERE last_used_ns < ?', (cutoff,))
            count, size = self.conn.execute('SELECT COUNT(*), COALESCE(SUM(size), 0) FROM engine_cache_v2').fetchone()
            for key, item in self.conn.execute('SELECT key, size FROM engine_cache_v2 ORDER BY last_used_ns, key').fetchall():
                if count <= max_entries and size <= max_bytes:
                    break
                self.conn.execute('DELETE FROM engine_cache_v2 WHERE key=?', (key,))
                count, size = count - 1, size - item

    def cache_clear(self):
        with self.conn:
            self.conn.execute('DELETE FROM engine_cache_v2')
        return {'cleared': True}

    def save(self, report):
        if report.get('scope', 'committed') != 'committed':
            raise ValueError('only committed-revision reports can become plans')
        key = identity([str(self.repo.root), report])
        with self.conn:
            self.conn.execute('BEGIN IMMEDIATE')
            self.conn.execute('INSERT OR IGNORE INTO engine_runs VALUES (?,?,?,?)',
                              (key, str(self.repo.root), report['revision'], canonical(report)))
            self.conn.executemany('INSERT OR IGNORE INTO engine_tasks(run_id,id,payload,state,fingerprint) VALUES (?,?,?,\'open\',?)',
                                  [(key, f['id'], canonical(f), f.get('fingerprint', '')) for f in report['findings']])
            if report['revision'] == self.repo.head():
                self.conn.execute('''INSERT OR IGNORE INTO engine_supersessions
                    SELECT id, ? FROM engine_runs WHERE repository=? AND id!=? AND revision!=?''',
                                  (key, str(self.repo.root), key, report['revision']))
        return key

    def cancel(self, key, task, reason):
        """Supervisor cancels a task: terminal, refused while a live kernel lease holds it."""
        if not reason.strip() or len(reason) > 4000:
            raise ValueError('nonempty bounded reason required')
        with self.conn:
            self.conn.execute('BEGIN IMMEDIATE')
            self.view(key)
            row = self.conn.execute('SELECT state FROM engine_tasks WHERE run_id=? AND id=?', (key, task)).fetchone()
            if not row or row[0] not in ('open', 'investigating', 'blocked'):
                raise ValueError('only open, investigating or blocked tasks can be cancelled')
            from .kernel import holds_live_lease
            if holds_live_lease(self, key, task):
                raise ValueError('task is held by a live reservation; release it first')
            self.conn.execute("UPDATE engine_tasks SET state='cancelled',version=version+1,reason=? WHERE run_id=? AND id=?", (reason, key, task))
            self.conn.execute('INSERT INTO engine_events(run_id,task_id,previous,next,reason) VALUES (?,?,?,?,?)', (key, task, row[0], 'cancelled', reason))
        return self.view(key)

    def view(self, key):
        row = self.conn.execute('SELECT revision,report FROM engine_runs WHERE id=? AND repository=?', (key, str(self.repo.root))).fetchone()
        if not row:
            raise ValueError('unknown audit for this repository')
        report = json.loads(row[1])
        if identity([str(self.repo.root), report]) != key or report['revision'] != row[0]:
            raise ValueError('stored report integrity mismatch')
        tasks = [dict(id=i, finding=json.loads(p), state=s, version=v, reason=r, fingerprint=f) for i,p,s,v,r,f in self.conn.execute(
            'SELECT id,payload,state,version,reason,fingerprint FROM engine_tasks WHERE run_id=? ORDER BY id', (key,))]
        later = self.conn.execute('SELECT superseded_by FROM engine_supersessions WHERE run_id=?', (key,)).fetchone()
        return dict(run_id=key, revision=row[0], stale=self.repo.head()!=row[0], superseded_by=later[0] if later else None,
                    tasks=tasks, report=report, release_ready=False)

    def transition(self, key, task, version, state, reason):
        allowed = {'open': {'investigating','blocked'}, 'investigating': {'blocked','proposed','open'},
                   'blocked': {'open','investigating'}, 'proposed': {'open','blocked'}, 'cancelled': set()}
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
