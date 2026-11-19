"""Command line entry point for the local audit and guarded repair pilot."""
import argparse
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
from .kernel import approve, configure, dispatch, recover, set_quota, grant, pause, renew, reserve, resume, revoke
from .completion import complete, depend, freeze, release, verify
from .isolation import available as isolation_available, run_worker
from .sandboxed import isolated_analyser
from .mutation import mutate
from .repository import Repository
from .store import Store
from .audit import scan
from .controls import catalogue
from .repair import check_patch, apply_prepared


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    worker_argv = []
    if argv[:1] == ['run-worker'] and '--' in argv:
        split = argv.index('--')
        argv, worker_argv = argv[:split], argv[split + 1:]
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest='command',required=True)
    for name in ('audit','plan','status','transition','preview','apply'):
        p=sub.add_parser(name)
        p.add_argument('repository')
        if name in ('audit','plan','status','transition'):
            p.add_argument('database')
        if name in ('audit','plan'):
            p.add_argument('--catalogue',default=str(Path(__file__).resolve().parent.parent/'profiles'/'checks.tsv'))
            p.add_argument('--max-blob',type=int,default=2*1024*1024)
            p.add_argument('--max-total',type=int,default=32*1024*1024)
            p.add_argument('--analysis-cpu',type=int,default=10)
            p.add_argument('--analysis-memory',type=int,default=512,help='MiB')
            p.add_argument('--trusted-target',action='store_true',help='analyse in-process when isolation is unavailable')
        if name in ('status','transition'):
            p.add_argument('run_id')
        if name=='transition':
            p.add_argument('task_id'); p.add_argument('version',type=int)
            p.add_argument('state',choices=('open','investigating','blocked','proposed'))
            p.add_argument('--reason',required=True)
        if name in ('preview','apply'):
            p.add_argument('patch'); p.add_argument('declarations'); p.add_argument('acceptance')
        if name=='apply':
            p.add_argument('--approval-id',required=True)
            p.add_argument('--allow-remove',action='store_true')
    for command in ('reserve', 'renew'):
        lease = sub.add_parser(command, description=(
            "Trusted supervisor only. Share one private database across the project's "
            "workers. Reserve returns a private bearer. Renew reads it from stdin."
        ))
        for field in ('repository', 'database', 'run_id', 'task_id'):
            lease.add_argument(field)
        if command == 'renew':
            lease.add_argument('generation', type=int)
        lease.add_argument('seconds', type=int)
    for command in ('grant', 'revoke', 'dispatch'):
        gate = sub.add_parser(command, description=(
            "Trusted supervisor only. Dispatch reads the private bearer from stdin and "
            "admits one controlled mutation immediately before it runs."
        ))
        for field in ('repository', 'database', 'run_id', 'task_id'):
            gate.add_argument(field)
        gate.add_argument('generation', type=int)
        if command == 'grant':
            gate.add_argument('--operation', action='append', nargs='+', required=True,
                              metavar=('KIND', 'PATH'))
        elif command == 'revoke':
            gate.add_argument('--reason', required=True)
        else:
            gate.add_argument('kind')
            gate.add_argument('paths', nargs='*')
    mutate_parser = sub.add_parser('mutate', description=(
        "Trusted supervisor only. Reads the worker bearer from stdin and applies one "
        "private patch file after checking lease, revision, scope and worktree integrity."
    ))
    for field in ('repository', 'database', 'run_id', 'task_id'):
        mutate_parser.add_argument(field)
    mutate_parser.add_argument('generation', type=int)
    mutate_parser.add_argument('patch')
    completion_help = "Trusted supervisor only, except complete, which reads the holder's bearer from stdin."
    for command in ('freeze', 'verify', 'complete', 'release', 'depend'):
        c = sub.add_parser(command, description=completion_help)
        for field in ('repository', 'database', 'run_id', 'task_id'):
            c.add_argument(field)
        if command in ('verify', 'complete', 'release'):
            c.add_argument('generation', type=int)
        if command in ('freeze', 'verify'):
            c.add_argument('acceptance')
        if command == 'verify':
            c.add_argument('--timeout', type=int, default=600)
        if command == 'release':
            c.add_argument('--reason', required=True)
            c.add_argument('--revert', action='store_true')
        if command == 'depend':
            c.add_argument('requires')
    worker = sub.add_parser('run-worker', description=(
        "Trusted supervisor only. Runs the worker command isolated (Linux bubblewrap), then applies "
        "outbox *.patch files through mutate with the bearer read from stdin."
    ))
    for field in ('repository', 'database', 'run_id', 'task_id'):
        worker.add_argument(field)
    worker.add_argument('generation', type=int)
    worker.add_argument('outbox')
    worker.add_argument('--input', action='append', default=[], metavar='NAME=PATH')
    worker.add_argument('--timeout', type=int, default=600)
    worker.epilog = "Place the worker command after a literal --."
    configure_parser = sub.add_parser('configure', description='Trusted supervisor only. Declares the checkout line-ending policy.')
    configure_parser.add_argument('repository')
    configure_parser.add_argument('database')
    configure_parser.add_argument('--eol', choices=('none', 'crlf'))
    configure_parser.add_argument('--exclude', action='append', default=[], metavar='DIR/')
    configure_parser.add_argument('--clear-excludes', action='store_true')
    configure_parser.add_argument('--require-approval', choices=('on', 'off'))
    approve_parser = sub.add_parser('approve', description='Trusted supervisor only. Approves one exact patch for one lease generation.')
    for field in ('repository', 'database', 'run_id', 'task_id'):
        approve_parser.add_argument(field)
    approve_parser.add_argument('generation', type=int)
    approve_parser.add_argument('patch')
    quota_parser = sub.add_parser('quota', description='Trusted supervisor only. Caps mutate, verify or worker uses for a task.')
    for field in ('repository', 'database', 'run_id', 'task_id'):
        quota_parser.add_argument(field)
    quota_parser.add_argument('--kind', required=True)
    quota_parser.add_argument('--limit', type=int, required=True)
    recover_parser = sub.add_parser('recover', description='Trusted supervisor only. Resolves an interrupted kernel operation.')
    recover_parser.add_argument('repository')
    recover_parser.add_argument('database')
    for command in ('pause', 'resume'):
        control = sub.add_parser(command, description="Trusted supervisor only.")
        control.add_argument('repository')
        control.add_argument('database')
        control.add_argument('--reason', required=True)
    a=parser.parse_args(argv)
    try:
        repo=Repository(a.repository)
        if a.command in ('preview','apply'):
            patch, declarations, test=[repo.private_path(p) for p in (a.patch,a.declarations,a.acceptance)]
            args=(repo,patch.read_bytes(),json.loads(declarations.read_bytes()),test.read_bytes())
            output=check_patch(*args) if a.command=='preview' else apply_prepared(*args,a.approval_id,a.allow_remove)
        else:
            with Store(repo,a.database) as store:
                if a.command in ('audit','plan'):
                    if isolation_available():
                        analyser=isolated_analyser(repo.root,a.analysis_cpu,a.analysis_memory)
                    elif a.trusted_target or os.environ.get('OSB_TRUSTED_TARGETS')=='1':
                        analyser=None
                    else:
                        raise ValueError('analysis isolation unavailable; use --trusted-target only for trusted repositories')
                    report,metrics=scan(repo,store,catalogue(a.catalogue),a.max_blob,a.max_total,analyser)
                    output={'report':report,'metrics':metrics}
                    if a.command=='plan':
                        output['run_id']=store.save(report)
                elif a.command == 'reserve':
                    output = reserve(store, a.run_id, a.task_id, a.seconds)
                elif a.command == 'renew':
                    token = sys.stdin.readline(128).rstrip('\r\n')
                    output = renew(store, a.run_id, a.task_id, a.generation, a.seconds, token)
                elif a.command == 'grant':
                    output = grant(store, a.run_id, a.task_id, a.generation,
                                   [(op[0], op[1:]) for op in a.operation])
                elif a.command == 'revoke':
                    output = revoke(store, a.run_id, a.task_id, a.generation, a.reason)
                elif a.command == 'dispatch':
                    token = sys.stdin.readline(128).rstrip('\r\n')
                    output = dispatch(store, a.run_id, a.task_id, a.generation, token,
                                      a.kind, a.paths)
                elif a.command == 'mutate':
                    token = sys.stdin.readline(128).rstrip('\r\n')
                    output = mutate(store, a.run_id, a.task_id, a.generation, token,
                                    repo.private_path(a.patch).read_bytes())
                elif a.command == 'freeze':
                    output = freeze(store, a.run_id, a.task_id, repo.private_path(a.acceptance).read_bytes())
                elif a.command == 'verify':
                    if not 1 <= a.timeout <= 3600:
                        raise ValueError('verification timeout must be 1 to 3600 seconds')
                    output = verify(store, a.run_id, a.task_id, a.generation,
                                    repo.private_path(a.acceptance).read_bytes(), a.timeout)
                elif a.command == 'complete':
                    token = sys.stdin.readline(128).rstrip('\r\n')
                    output = complete(store, a.run_id, a.task_id, a.generation, token)
                elif a.command == 'release':
                    output = release(store, a.run_id, a.task_id, a.generation, a.reason, a.revert)
                elif a.command == 'depend':
                    output = depend(store, a.run_id, a.task_id, a.requires)
                elif a.command == 'run-worker':
                    token = sys.stdin.readline(128).rstrip('\r\n')
                    inputs = dict(item.split('=', 1) for item in a.input if '=' in item)
                    if len(inputs) != len(a.input):
                        raise ValueError('inputs must be NAME=PATH')
                    output = run_worker(store, a.run_id, a.task_id, a.generation, token,
                                        a.outbox, worker_argv, inputs, a.timeout)
                elif a.command == 'recover':
                    output = recover(store)
                elif a.command == 'quota':
                    output = set_quota(store, a.run_id, a.task_id, a.kind, a.limit)
                elif a.command == 'configure':
                    output = configure(store, a.eol, a.exclude, a.clear_excludes,
                                       None if a.require_approval is None else a.require_approval == 'on')
                elif a.command == 'approve':
                    output = approve(store, a.run_id, a.task_id, a.generation, repo.private_path(a.patch).read_bytes())
                elif a.command in ('pause', 'resume'):
                    output = (pause if a.command == 'pause' else resume)(store, a.reason)
                elif a.command=='status':
                    output=store.view(a.run_id)
                else:
                    output=store.transition(a.run_id,a.task_id,a.version,a.state,a.reason)
        print(json.dumps(output,indent=2,ensure_ascii=True))
        return 0
    except (ValueError, OSError, KeyError, TypeError, sqlite3.Error, subprocess.SubprocessError) as exc:
        parser.exit(2,f'Command blocked: {exc}\n')


if __name__=='__main__':
    raise SystemExit(main())
