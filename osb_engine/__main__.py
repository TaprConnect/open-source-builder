"""Command line entry point for the local audit and guarded repair pilot."""
import argparse
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
from .kernel import reserve, renew
from .repository import Repository
from .store import Store
from .audit import scan
from .controls import catalogue
from .repair import check_patch, apply_prepared


def main(argv=None):
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
                    report,metrics=scan(repo,store,catalogue(a.catalogue),a.max_blob,a.max_total)
                    output={'report':report,'metrics':metrics}
                    if a.command=='plan':
                        output['run_id']=store.save(report)
                elif a.command == 'reserve':
                    output = reserve(store, a.run_id, a.task_id, a.seconds)
                elif a.command == 'renew':
                    token = sys.stdin.readline(128).rstrip('\r\n')
                    output = renew(store, a.run_id, a.task_id, a.generation, a.seconds, token)
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
