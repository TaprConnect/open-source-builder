import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from osb_engine.repository import Repository
from osb_engine.store import Store
from osb_engine.audit import scan
from osb_engine.analysis import python_source, manifest
from osb_engine.controls import catalogue
from osb_engine.repair import check_patch, apply_prepared


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name); self.root=self.base/'target'; self.root.mkdir()
        self.private=self.base/'private'; self.private.mkdir(mode=0o700)
        self.db=self.private/'db.sqlite'
        self.git('init','-q'); self.git('config','user.name','Test'); self.git('config','user.email','test@example.invalid')
        (self.root/'app.py').write_text('from helper import run\nraise RuntimeError("do not execute")\ndef todo():\n    pass\ndef go():\n    run()\n')
        (self.root/'helper.py').write_text('def run():\n    return 1\n')
        (self.root/'package.json').write_text('{"scripts":{"build":"secret command"},"dependencies":{"private":"https://secret@example.invalid"}}')
        (self.root/'app.ts').write_text('export const x=1;')
        self.commit()
        self.rows=[dict(domain=d,activates_when='fixture',evidence='runtime proof',required_outcome='test passes') for d in ('Backend','Build','Security','Identity','Release','Quality')]

    def git(self,*args):
        return subprocess.check_output(['git','-C',str(self.root),*args],stderr=subprocess.PIPE)

    def commit(self):
        self.git('add','.'); self.git('commit','-qm','fixture')

    def report(self, **kwargs):
        repo=Repository(self.root)
        with Store(repo,self.db) as store:
            return scan(repo,store,self.rows,**kwargs)

    def test_symbols_imports_calls(self):
        report,_=self.report()
        app=next(f for f in report['files'] if f['path']=='app.py')['analysis']
        self.assertEqual({n['name'] for n in app['symbols']},{'go','todo'})
        self.assertTrue(any(c['caller']=='go' and c['target']=='run' for c in app['calls']))
        self.assertEqual(report['dependencies'][0]['to'],'helper.py')
        self.assertFalse(report['release_ready'])

    def test_cache_and_incremental_change(self):
        first,m=self.report(); second,n=self.report()
        self.assertEqual(first,second); self.assertEqual(m['cache_misses'],3); self.assertEqual(n['cache_hits'],3)
        (self.root/'helper.py').write_text('def run():\n    return 2\n'); self.commit()
        third,n=self.report(); self.assertEqual(n['cache_hits'],2); self.assertEqual(n['cache_misses'],1)
        self.assertNotEqual(first['revision'],third['revision'])

    def test_cache_separates_manifest_and_python(self):
        (self.root/'same.py').write_bytes((self.root/'package.json').read_bytes()); self.commit()
        report,_=self.report(); self.assertEqual(next(f['language'] for f in report['files'] if f['path']=='same.py'),'python')

    def test_candidates_no_secret_values(self):
        report,_=self.report(); raw=json.dumps(report)
        self.assertNotIn('secret command',raw); self.assertNotIn('https://secret',raw)
        self.assertTrue(all(c['status'] in ('unknown','not_performed') for c in report['controls']))
        self.assertEqual(next(c['status'] for c in report['controls'] if c['domain']=='Identity'),'not_performed')

    def test_unsupported_and_budget(self):
        report,_=self.report(max_blob=1,max_total=1)
        self.assertTrue(any(f['status']=='oversized' for f in report['files']))
        self.assertTrue(any(f['status']=='unsupported_language' for f in report['files']))
        with self.assertRaises(ValueError): self.report(max_blob=2,max_total=1)

    def test_worktree_edits_not_scanned(self):
        (self.root/'app.py').write_text('def fixed():\n    return 1\n')
        report,_=self.report(); self.assertTrue(any(f['rule']=='python.placeholder_body' for f in report['findings']))

    def test_transaction_and_conflict(self):
        repo=Repository(self.root)
        with Store(repo,self.db) as s:
            report,_=scan(repo,s,self.rows); key=s.save(report); self.assertEqual(key,s.save(report))
            task=s.view(key)['tasks'][0]
            s.transition(key,task['id'],0,'investigating','review')
            with self.assertRaises(ValueError): s.transition(key,task['id'],0,'blocked','stale writer')
            with self.assertRaises(ValueError): s.transition(key,task['id'],1,'pass','invented')
            s.transition(key,task['id'],1,'proposed','patch ready for review')
            self.assertEqual(s.conn.execute('SELECT count(*) FROM engine_events').fetchone()[0],2)
        with Store(repo,self.db) as s:
            self.assertEqual(next(t['state'] for t in s.view(key)['tasks'] if t['id']==task['id']),'proposed')
            (self.root/'helper.py').write_text('x=2'); self.commit()
            self.assertTrue(s.view(key)['stale'])
            with self.assertRaises(ValueError): s.transition(key,task['id'],2,'open','retry')

    def test_store_path_and_hardlink(self):
        repo=Repository(self.root)
        with self.assertRaises(ValueError): Store(repo,self.root/'db')
        with Store(repo,self.db): pass
        if hasattr(os,'link'):
            os.link(self.db,self.private/'hardlink')
            with self.assertRaises(ValueError): Store(repo,self.db)

    def test_parse_blocked_and_security_leads(self):
        self.assertEqual(python_source(b'def a(:')[0],'parse_blocked')
        _,out=python_source(b'def f(x):\n    eval(x)\n    call(x, shell=True)\n    try: pass\n    except: pass\n')
        self.assertEqual({f['rule'] for f in out['findings']},{'python.unsafe_operation','python.shell_execution','python.swallowed_exception'})
        self.assertEqual(manifest(b'{"scripts":null}')[0],'parse_blocked')

    def test_catalogue_validation(self):
        p=self.private/'checks.tsv'; p.write_text('domain\tactivates_when\tevidence\trequired_outcome\nA\tx\ty\tz\nA\tx\ty\tz\n')
        with self.assertRaises(ValueError): catalogue(p)

    def make_patch(self,filename='helper.py',content='def run():\n    return 2\n'):
        p=self.root/filename; original=p.read_bytes() if p.exists() else None
        if content is None: p.unlink()
        else: p.write_text(content)
        self.git('add','-A'); diff=self.git('diff','--cached','--no-renames'); self.git('reset','--hard','HEAD')
        action='remove' if content is None else 'add' if original is None else 'modify'
        return diff,{filename:dict(action=action,justification='fixture',acceptance='test',rollback='restore')}

    def test_preview_bound_and_no_real_changes(self):
        diff,d=self.make_patch(); repo=Repository(self.root); receipt=check_patch(repo,diff,d,b'test')
        self.assertFalse(repo.dirty()); self.assertFalse(receipt['release_ready'])
        with self.assertRaises(ValueError): apply_prepared(repo,diff,d,b'changed',receipt['approval_id'])
        with self.assertRaisesRegex(ValueError,'linked worktree'): apply_prepared(repo,diff,d,b'test',receipt['approval_id'])
        with self.assertRaises(ValueError): check_patch(repo,diff,{},b'test')

    def test_apply_linked_worktree(self):
        diff,d=self.make_patch(); linked=self.base/'linked'; self.git('worktree','add','--detach',str(linked),'HEAD')
        repo=Repository(linked); receipt=check_patch(repo,diff,d,b'test')
        result=apply_prepared(repo,diff,d,b'test',receipt['approval_id'])
        self.assertTrue(result['applied']); self.assertEqual(result['verification'],'not_performed')
        self.assertIn('return 2',(linked/'helper.py').read_text()); self.assertIn('return 1',(self.root/'helper.py').read_text())

    def test_sensitive_paths_and_removal(self):
        diff,d=self.make_patch('test_new.py','pass\n'); repo=Repository(self.root)
        with self.assertRaises(ValueError): check_patch(repo,diff,d,b'test')
        diff,d=self.make_patch('helper.py',None); receipt=check_patch(repo,diff,d,b'test')
        self.assertTrue(receipt['requires_removal_approval'])
        with self.assertRaisesRegex(ValueError,'removal'): apply_prepared(repo,diff,d,b'test',receipt['approval_id'])

    def test_dirty_checkout_rejected(self):
        diff,d=self.make_patch(); (self.root/'untracked').write_text('work')
        with self.assertRaisesRegex(ValueError,'clean'): check_patch(Repository(self.root),diff,d,b'test')

    def test_cli_plan_and_status(self):
        import sys
        catalogue_path=self.private/'checks.tsv'
        catalogue_path.write_text('domain\tactivates_when\tevidence\trequired_outcome\nBackend\tx\ty\tz\nIdentity\tx\ty\tz\n')
        command=[sys.executable,'-m','osb_engine']
        result=json.loads(subprocess.check_output(command+['plan',str(self.root),str(self.db),'--catalogue',str(catalogue_path)]))
        current=json.loads(subprocess.check_output(command+['status',str(self.root),str(self.db),result['run_id']]))
        self.assertFalse(current['stale']); self.assertFalse(current['release_ready']); self.assertTrue(current['tasks'])
        self.assertEqual(len(current['report']['controls']),2)

    def test_relative_imports(self):
        pkg=self.root/'pkg'; pkg.mkdir()
        (pkg/'__init__.py').write_text('from . import service\n')
        (pkg/'service.py').write_text('from . import utility\n')
        (pkg/'utility.py').write_text('x=1\n')
        self.commit()
        report,_=self.report()
        self.assertIn(('pkg/__init__.py','pkg/service.py'),{(e['from'],e['to']) for e in report['dependencies']})
        self.assertIn(('pkg/service.py','pkg/utility.py'),{(e['from'],e['to']) for e in report['dependencies']})

    def test_controls_cover_all_named_domains(self):
        names='Identity Tenancy Persistence Backend Frontend Motion Accessibility Jobs Billing Database AI Agent Privacy ML Operations Release Security UX Pricing Jurisdiction Intent Architecture Build Quality Contracts Configuration Recovery Isolation Concurrency Cache Files Search Webhook Integration Network WebDefences Secrets SupplyChain Infrastructure Observability Reliability Load Cost Payments Locale Email Discovery Portability Canary Support Desktop Mobile CLI SDK DataPipeline ModelData AIEvals AITrials AIOutcome Grounding AITrust AIRelease AIResources AIChange Retention Removal'.split()
        self.rows=[dict(domain=d,activates_when='fixture',evidence='fixture',required_outcome='fixture') for d in names]
        report,_=self.report()
        self.assertEqual(len(report['controls']),66)
        self.assertEqual({r['domain'] for r in report['controls']},set(names))
        self.assertEqual(sum(r['static_check']=='executed' for r in report['controls']),11)
        self.assertTrue(all(r['status'] in ('unknown','not_performed') for r in report['controls']))
