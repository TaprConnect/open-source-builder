"""Command line entry point for the local audit and guarded repair pilot."""
import argparse
import json
import time
from datetime import datetime, timezone
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
from .config import load as load_config, resolve
from .doctor import doctor, text_report
from .handover import export_plan, import_plan
from . import plugins as plugins_module
from .intelligence import build_index, valid_facts
from .control_framework import evaluate_controls
from .sandboxed import isolated_map
from .repository import Repository
from .store import identity
from .store import Store
from .audit import scan
from .controls import catalogue
from .repair import check_patch, apply_prepared


_EVENT = {}


def main(argv=None):
    """CLI entry point; with --log FILE appends one JSON line per command (F01-OPS)."""
    argv = list(sys.argv[1:] if argv is None else argv)
    log = None
    if '--log' in argv[:argv.index('run-worker') if 'run-worker' in argv else len(argv)]:
        at = argv.index('--log')
        log = argv[at + 1] if at + 1 < len(argv) else None
    started, code = time.monotonic(), 0
    _EVENT.clear()
    try:
        code = _main(argv)
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 2
        raise
    finally:
        if log:
            _append_log(log, {'time': datetime.now(timezone.utc).isoformat(), 'command': _EVENT.get('command'),
                              'exit': code, 'duration_ms': int((time.monotonic() - started) * 1000),
                              **{k: v for k, v in _EVENT.items() if k != 'command'}})
    return code


def _append_log(path, event):
    """Log only metadata; the directory must be owner-only (and outside any target, checked in _main)."""
    target = Path(path).absolute()
    if os.name == 'posix' and target.parent.stat().st_mode & 0o077:
        raise SystemExit('log directory must be owner-only (chmod 700)')
    if os.name == 'nt':
        from .winacl import unexpected_principals
        if unexpected_principals(target.parent):
            raise SystemExit('log directory ACL grants access beyond the owner')
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    with os.fdopen(fd, 'a') as handle:
        handle.write(json.dumps(event, sort_keys=True) + '\n')


def _main(argv):
    argv = list(sys.argv[1:] if argv is None else argv)
    worker_argv = []
    if 'run-worker' in argv and '--' in argv[argv.index('run-worker'):]:
        split = argv.index('--', argv.index('run-worker'))
        argv, worker_argv = argv[:split], argv[split + 1:]
    parser=argparse.ArgumentParser(prog='osb',description=__doc__)
    parser.add_argument('--error-format',choices=('text','json'),default='text')
    parser.add_argument('--log',help='append one JSON metadata line per command to this private file')
    sub=parser.add_subparsers(dest='command',required=True)
    sub.add_parser('doctor',description='Report host capabilities and support classification.')
    discover_parser=sub.add_parser('discover',description='Resolve a path inside a repository to its root, revision and identity.')
    discover_parser.add_argument('path')
    for name in ('audit','plan','status','transition','preview','apply'):
        p=sub.add_parser(name)
        p.add_argument('repository')
        if name in ('audit','plan','status','transition'):
            p.add_argument('database')
        if name in ('audit','plan'):
            p.add_argument('--catalogue',default=str(Path(__file__).resolve().parent/'profiles'/'checks.tsv'))
            p.add_argument('--config',help='private versioned JSON configuration outside the target')
            p.add_argument('--working-tree',action='store_true',help='analyse uncommitted files (audit only; never cached or planned)')
            p.add_argument('--max-blob',type=int)
            p.add_argument('--max-total',type=int)
            p.add_argument('--analysis-cpu',type=int)
            p.add_argument('--analysis-memory',type=int,help='MiB')
            p.add_argument('--trusted-target',action='store_true',help='analyse in-process when isolation is unavailable')
            p.add_argument('--analysis-budget',type=int,help='seconds for all isolated analysis')
            p.add_argument('--cache-max-entries',type=int)
            p.add_argument('--cache-max-bytes',type=int)
            p.add_argument('--cache-retention-days',type=int)
        if name in ('audit','plan','status'):
            p.add_argument('--format',choices=('json','text'),default='json')
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
        if command == 'freeze':
            c.add_argument('--external', action='store_true', help='acceptance drives repository code only through the isolated broker')
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
    configure_parser.add_argument('--require-external-acceptance', choices=('on', 'off'))
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
    cache_parser = sub.add_parser('cache-clear', description='Trusted supervisor only. Empties the analysis cache.')
    cache_parser.add_argument('repository')
    cache_parser.add_argument('database')
    index_parser = sub.add_parser('index', description='Build a repository intelligence index of the pinned revision.')
    index_parser.add_argument('repository')
    index_parser.add_argument('database')
    index_parser.add_argument('--trusted-target', action='store_true')
    index_parser.add_argument('--analysis-cpu', type=int, default=10)
    index_parser.add_argument('--analysis-memory', type=int, default=512)
    index_parser.add_argument('--analysis-budget', type=int, default=1800)
    controls_parser = sub.add_parser('controls', description='Evaluate the engineering control catalogue against the repository index.')
    controls_parser.add_argument('repository')
    controls_parser.add_argument('database')
    controls_parser.add_argument('--catalogue', default=str(Path(__file__).resolve().parent/'profiles'/'checks.tsv'))
    controls_parser.add_argument('--trusted-target', action='store_true')
    controls_parser.add_argument('--analysis-cpu', type=int, default=10)
    controls_parser.add_argument('--analysis-memory', type=int, default=512)
    controls_parser.add_argument('--analysis-budget', type=int, default=1800)
    assure_parser = sub.add_parser('assure', description='Evaluate every catalogue control with static, runtime and external evidence (S05).')
    assure_parser.add_argument('repository')
    assure_parser.add_argument('database')
    assure_parser.add_argument('--catalogue', default=str(Path(__file__).resolve().parent/'profiles'/'checks.tsv'))
    assure_parser.add_argument('--trusted-target', action='store_true')
    assure_parser.add_argument('--runtime', action='store_true', help='run discovered project commands in isolation')
    assure_parser.add_argument('--acceptance', help='private JSON list of external verification records')
    assure_parser.add_argument('--budget', type=float, default=60.0)
    assure_parser.add_argument('--analysis-cpu', type=int, default=10)
    assure_parser.add_argument('--analysis-memory', type=int, default=512)
    assure_parser.add_argument('--analysis-budget', type=int, default=1800)
    cancel_parser = sub.add_parser('cancel', description='Trusted supervisor only. Cancels a task (terminal).')
    for field in ('repository', 'database', 'run_id', 'task_id'):
        cancel_parser.add_argument(field)
    cancel_parser.add_argument('--reason', required=True)
    export_parser = sub.add_parser('export-plan', description='Write a sealed handover bundle for a plan.')
    for field in ('repository', 'database', 'run_id', 'bundle'):
        export_parser.add_argument(field)
    import_parser = sub.add_parser('import-plan', description='Recreate a plan from a sealed handover bundle.')
    for field in ('repository', 'database', 'bundle'):
        import_parser.add_argument(field)
    for command in ('pause', 'resume'):
        control = sub.add_parser(command, description="Trusted supervisor only.")
        control.add_argument('repository')
        control.add_argument('database')
        control.add_argument('--reason', required=True)
    a=parser.parse_args(argv)
    _EVENT['command']=a.command
    try:
        if a.command=='doctor':
            print(json.dumps(doctor(),indent=2,ensure_ascii=True))
            return 0
        if a.command=='discover':
            print(json.dumps(discover(a.path),indent=2,ensure_ascii=True))
            return 0
        repo=Repository(a.repository)
        if a.log:
            repo.private_path(a.log)
        if a.command in ('preview','apply'):
            patch, declarations, test=[repo.private_path(p) for p in (a.patch,a.declarations,a.acceptance)]
            args=(repo,patch.read_bytes(),json.loads(declarations.read_bytes()),test.read_bytes())
            output=check_patch(*args) if a.command=='preview' else apply_prepared(*args,a.approval_id,a.allow_remove)
        else:
            with Store(repo,a.database) as store:
                if a.command in ('audit','plan'):
                    cfg=load_config(repo,a.config)
                    a.analysis_cpu=resolve(cfg,'analysis','cpu',a.analysis_cpu)
                    a.analysis_memory=resolve(cfg,'analysis','memory',a.analysis_memory)
                    a.analysis_budget=resolve(cfg,'analysis','budget',a.analysis_budget)
                    a.max_blob=resolve(cfg,'budget','max_blob',a.max_blob)
                    a.max_total=resolve(cfg,'budget','max_total',a.max_total)
                    a.cache_max_entries=resolve(cfg,'cache','max_entries',a.cache_max_entries)
                    a.cache_max_bytes=resolve(cfg,'cache','max_bytes',a.cache_max_bytes)
                    a.cache_retention_days=resolve(cfg,'cache','retention_days',a.cache_retention_days)
                    if isolation_available():
                        analyser=isolated_analyser(repo.root,a.analysis_cpu,a.analysis_memory,budget_seconds=a.analysis_budget)
                        mode='isolated'
                    elif a.trusted_target or os.environ.get('OSB_TRUSTED_TARGETS')=='1':
                        analyser=None
                        mode='in_process_trusted'
                        print('warning: analysing repository content in-process without isolation (trusted target asserted)', file=sys.stderr)
                    else:
                        raise ValueError('analysis isolation unavailable; use --trusted-target only for trusted repositories')
                    context={'trust':mode}
                    if mode=='isolated':
                        context.update(cpu=a.analysis_cpu,memory=a.analysis_memory)
                    if a.working_tree and a.command=='plan':
                        raise ValueError('plans bind to a committed revision; commit first or use audit --working-tree')
                    report,metrics=scan(repo,store,catalogue(a.catalogue),a.max_blob,a.max_total,analyser,context,
                                        (a.cache_max_entries,a.cache_max_bytes,a.cache_retention_days),a.working_tree)
                    output={'report':report,'metrics':{**metrics,'analysis':mode}}
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
                    output = freeze(store, a.run_id, a.task_id, repo.private_path(a.acceptance).read_bytes(), a.external)
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
                elif a.command in ('index', 'controls', 'assure'):
                    if isolation_available():
                        extractor = isolated_map(repo.root, plugins_module, 'extract', valid_facts, a.analysis_cpu,
                                                 a.analysis_memory, budget_seconds=a.analysis_budget)
                    elif a.trusted_target or os.environ.get('OSB_TRUSTED_TARGETS') == '1':
                        extractor = None
                        print('warning: indexing repository content in-process without isolation (trusted target asserted)', file=sys.stderr)
                    else:
                        raise ValueError('analysis isolation unavailable; use --trusted-target only for trusted repositories')
                    output = build_index(repo, extractor)
                    if a.command == 'controls':
                        output = evaluate_controls(catalogue(a.catalogue), output)
                    elif a.command == 'assure':
                        from . import assurance, runtime as runtime_adapters
                        trusted = a.trusted_target or os.environ.get('OSB_TRUSTED_TARGETS') == '1'
                        observed = runtime_adapters.run(repo, output, trusted=trusted) if a.runtime else None
                        records = json.loads(Path(a.acceptance).read_bytes()) if a.acceptance else []
                        if not isinstance(records, list):
                            raise ValueError('acceptance records must be a JSON list')
                        output = {'assurance': assurance.evaluate(catalogue(a.catalogue), output, observed, records, a.budget),
                                  'runtime': observed}
                elif a.command == 'cancel':
                    output = store.cancel(a.run_id, a.task_id, a.reason)
                elif a.command == 'export-plan':
                    output = export_plan(store, a.run_id, a.bundle)
                elif a.command == 'import-plan':
                    output = import_plan(store, a.bundle)
                elif a.command == 'cache-clear':
                    output = store.cache_clear()
                elif a.command == 'recover':
                    output = recover(store)
                elif a.command == 'quota':
                    output = set_quota(store, a.run_id, a.task_id, a.kind, a.limit)
                elif a.command == 'configure':
                    output = configure(store, a.eol, a.exclude, a.clear_excludes,
                                       None if a.require_approval is None else a.require_approval == 'on',
                                       None if a.require_external_acceptance is None else a.require_external_acceptance == 'on')
                elif a.command == 'approve':
                    output = approve(store, a.run_id, a.task_id, a.generation, repo.private_path(a.patch).read_bytes())
                elif a.command in ('pause', 'resume'):
                    output = (pause if a.command == 'pause' else resume)(store, a.reason)
                elif a.command=='status':
                    output=store.view(a.run_id)
                else:
                    output=store.transition(a.run_id,a.task_id,a.version,a.state,a.reason)
        if isinstance(output,dict):
            if output.get('run_id'):
                _EVENT['run_id']=output['run_id']
            report=output.get('report') if isinstance(output.get('report'),dict) else {}
            size=lambda v: len(v) if isinstance(v,list) else (v if isinstance(v,int) else 0)
            _EVENT['counts']={'files_count':size(report.get('files')),'finding_count':size(report.get('findings')),
                              'task_count':size(output.get('tasks'))}
        if getattr(a,'format','json')=='text':
            sys.stdout.write(text_report(a.command,output))
        else:
            print(json.dumps(output,indent=2,ensure_ascii=True))
        return 0
    except (ValueError, OSError, KeyError, TypeError, sqlite3.Error, subprocess.SubprocessError) as exc:
        _fail(parser,a,'blocked',f'Command blocked: {exc}',str(exc),2)
    except Exception as exc:  # unexpected: exit 3 without leaking a traceback
        if os.environ.get('OSB_DEBUG')=='1':
            raise
        _fail(parser,a,'internal',f'Internal error: {type(exc).__name__}: {exc}',f'{type(exc).__name__}: {exc}',3)


def _fail(parser, a, kind, text, message, code):
    if a.error_format=='json':
        sys.stderr.write(json.dumps({'error':kind,'message':message,'exit':code})+'\n')
        raise SystemExit(code)
    parser.exit(code,text+'\n')


def discover(path):
    top=subprocess.run(['git','-C',str(path),'rev-parse','--show-toplevel'],capture_output=True,text=True,timeout=60)
    if top.returncode!=0:
        raise ValueError('not inside a Git repository')
    repo=Repository(top.stdout.strip())
    roots=sorted(repo.git('rev-list','--max-parents=0',repo.revision).decode().split())
    return {'root':str(repo.root),'revision':repo.revision,'common_dir':str(repo.common),
            'project_identity':identity(roots),'root_commits':roots}


if __name__=='__main__':
    raise SystemExit(main())
