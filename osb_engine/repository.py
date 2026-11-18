"""Pinned Git snapshots. Trusted repository configuration is required."""
from dataclasses import dataclass
import os
from pathlib import Path
import re
import subprocess


@dataclass(frozen=True)
class Blob:
    path: str
    oid: str
    mode: str
    kind: str
    size: int


class Repository:
    def __init__(self, root):
        self.root = Path(root).resolve(strict=True)
        if self.git('rev-parse', '--show-prefix').strip():
            raise ValueError('repository root required')
        self.revision = self.head()
        self.common = (self.root / os.fsdecode(self.git('rev-parse', '--git-common-dir').rstrip(b'\n'))).resolve()

    def git(self, *args, data=None, extra_env=None):
        env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
        env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
                   GIT_NO_REPLACE_OBJECTS='1', GIT_OPTIONAL_LOCKS='0', GIT_TERMINAL_PROMPT='0',
                   GIT_NO_LAZY_FETCH='1')
        if extra_env:
            env.update(extra_env)
        return subprocess.run(['git', '-C', str(self.root), '-c', 'core.hooksPath='+os.devnull,
                               '-c', 'core.fsmonitor=false', *args], input=data,
                              capture_output=True, check=True, timeout=60, env=env).stdout

    def head(self):
        revision = self.git('rev-parse', '--verify', 'HEAD^{commit}').decode().strip()
        if not re.fullmatch('[0-9a-f]{40}|[0-9a-f]{64}', revision):
            raise ValueError('invalid revision')
        return revision

    def assert_current(self):
        if self.head() != self.revision:
            raise ValueError('repository revision changed; rescan')

    def inventory(self):
        for entry in self.git('ls-tree', '-rlz', self.revision).split(b'\0'):
            if entry:
                header, path = entry.split(b'\t', 1)
                mode, kind, oid, size = header.decode('ascii').split()
                yield Blob(os.fsdecode(path), oid, mode, kind, int(size) if size != '-' else 0)

    def read(self, blob):
        if blob.kind != 'blob' or blob.mode not in ('100644', '100755'):
            raise ValueError('regular committed file required')
        return self.git('cat-file', 'blob', blob.oid)

    def dirty(self):
        return bool(self.git('status', '--porcelain=v1', '--untracked-files=all'))

    def private_path(self, path):
        raw = Path(path).absolute()
        actual = raw.resolve()
        if actual.is_relative_to(self.root) or actual.is_relative_to(self.common):
            raise ValueError('private state must be outside target and Git metadata')
        if raw.is_symlink() or actual.exists() and not actual.is_file():
            raise ValueError('regular private file required')
        return actual
