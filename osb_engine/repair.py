"""Guarded patch preparation: immutable receipt of scope, not execution or assurance."""
import hashlib
import os
from pathlib import Path
import tempfile
from .store import identity

MAX_PATCH = 8*1024*1024
MAX_TEST = 1024*1024


def check_patch(repo, patch, declarations, acceptance):
    """Validate a textual Git patch in a temporary index outside the target.

    Git may write unreferenced blob objects to its object database. No working
    tree or live index modification. Use a dedicated disposable clone.
    """
    if not patch or len(patch)>MAX_PATCH or b'\0' in patch:
        raise ValueError('invalid patch size or binary encoding')
    if b'GIT binary patch' in patch or b'Binary files ' in patch:
        raise ValueError('binary patches require manual review')
    if not acceptance or len(acceptance)>MAX_TEST:
        raise ValueError('frozen acceptance script required')
    repo.assert_current()
    if repo.dirty():
        raise ValueError('clean checkout required')
    with tempfile.TemporaryDirectory() as tmp:
        env = {'GIT_INDEX_FILE':str(Path(tmp)/'index')}
        repo.git('read-tree',repo.revision,extra_env=env)
        repo.git('apply','--cached','--whitespace=error','-',data=patch,extra_env=env)
        raw=repo.git('diff','--cached','--no-renames','--raw','-z',repo.revision,extra_env=env)
    parts=raw.rstrip(b'\0').split(b'\0') if raw else []
    if len(parts)%2:
        raise ValueError('invalid diff record')
    changes={}
    for header,p in zip(parts[::2],parts[1::2]):
        old,new,_,_,status=header.lstrip(b':').split()
        path=os.fsdecode(p)
        if {old,new}-{b'100644',b'100755',b'000000'}:
            raise ValueError('special file change rejected')
        action={b'A':'add',b'M':'modify',b'D':'remove'}.get(status)
        if action is None or path in changes:
            raise ValueError('invalid change classification')
        # Sensitive paths require a separate review workflow, not this pilot.
        parts_path=path.lower().split('/')
        name=parts_path[-1]
        if any(x in ('.github','.git','tests','test','__tests__') for x in parts_path) or name.startswith(('test_','test.','.env')) or '.test.' in name or '.spec.' in name or name.endswith(('_test.py','.spec.ts')) or name in ('agents.md','security.md','conftest.py','pytest.ini','pyproject.toml','package.json','requirements.txt'):
            raise ValueError('test, workflow, manifest or policy change requires separate review: '+path)
        changes[path]=action
    if not changes or set(changes)!=set(declarations):
        raise ValueError('exact changed-path declarations required')
    for path,action in changes.items():
        d=declarations[path]
        if d.get('action')!=action or any(not isinstance(d.get(k),str) or not d[k].strip() for k in ('justification','acceptance','rollback')):
            raise ValueError('incomplete change declaration: '+path)
    repo.assert_current()
    if repo.dirty():
        raise ValueError('checkout changed during preview')
    payload={'schema':1,'repository':str(repo.root),'revision':repo.revision,
             'patch_sha256':hashlib.sha256(patch).hexdigest(),'acceptance_sha256':hashlib.sha256(acceptance).hexdigest(),
             'changes':changes,'declarations':declarations,'requires_removal_approval':'remove' in changes.values(),
             'verification':'not_performed','release_ready':False}
    return {**payload,'approval_id':identity(payload)}


def apply_prepared(repo, patch, declarations, acceptance, approval_id, allow_remove=False):
    receipt=check_patch(repo,patch,declarations,acceptance)
    if receipt['approval_id']!=approval_id:
        raise ValueError('approval does not bind this patch and test')
    if receipt['requires_removal_approval'] and not allow_remove:
        raise ValueError('explicit removal approval required')
    # Require an isolated single-owner linked worktree; not a process sandbox.
    git_dir=Path(os.fsdecode(repo.git('rev-parse','--absolute-git-dir').rstrip(b'\n'))).resolve()
    if git_dir==repo.common:
        raise ValueError('apply requires a dedicated linked worktree')
    repo.assert_current()
    if repo.dirty():
        raise ValueError('checkout changed before apply')
    repo.git('apply','--index','--whitespace=error','-',data=patch)
    return {**receipt,'applied':True,'verification':'not_performed',
            'rollback':'Review staged changes, then discard only this dedicated worktree after owner authorisation.'}
