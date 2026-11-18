import pathlib
import subprocess
import tempfile
import unittest
from osb import audit, plan, status


class AuditTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = pathlib.Path(tmp.name) / 'repo'
        self.root.mkdir()
        self.db = self.root.parent / 'review.sqlite'
        self.git('init', '-q')
        (self.root / 'app.py').write_text('raise RuntimeError("never execute")\ndef unfinished():\n    pass\n')
        (self.root / 'valid.py').write_text('def real():\n    return 42\n')
        (self.root / 'invalid.py').write_text('def x(:\n')
        (self.root / 'app.ts').write_text('export const x = 1;')
        self.commit()

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.root), *args])

    def commit(self):
        self.git('add', '.')
        self.git('-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit', '-qm', 'fixture')

    def test_static_candidates_and_unsupported_file(self):
        report = audit(self.root)
        self.assertEqual({f['rule'] for f in report['findings']}, {'python.parse_error', 'python.placeholder_body'})
        self.assertEqual({f['path'] for f in report['findings']}, {'app.py', 'invalid.py'})
        self.assertEqual(next(f['status'] for f in report['files'] if f['path'] == 'app.ts'), 'unsupported_language')
        self.assertEqual(report['runtime_verification'], 'not_performed')

    def test_committed_snapshot_only(self):
        (self.root / 'app.py').write_text('def fixed():\n    return 1\n')
        self.assertIn('app.py', {f['path'] for f in audit(self.root)['findings']})

    def test_idempotent_plan_and_stale_revision(self):
        first = plan(self.root, self.db)
        self.assertEqual(first, plan(self.root, self.db))
        self.assertEqual(len(first['tasks']), 2)
        self.assertFalse(first['release_ready'])
        (self.root / 'app.py').write_text('def fixed():\n    return 1\n')
        self.commit()
        self.assertTrue(status(self.root, self.db, first['audit_id'])['stale'])
        self.assertEqual(len(plan(self.root, self.db)['tasks']), 1)

    def test_store_outside_target(self):
        with self.assertRaises(ValueError):
            plan(self.root, self.root / 'review.sqlite')
        self.assertFalse((self.root / 'review.sqlite').exists())

    def test_unknown_id(self):
        with self.assertRaises(ValueError):
            status(self.root, self.db, 'unknown')

    def test_duplicate_blob_paths_remain_distinct(self):
        (self.root / 'copy.py').write_bytes((self.root / 'app.py').read_bytes())
        self.commit()
        results = [f for f in audit(self.root)['findings'] if f['rule'] == 'python.placeholder_body']
        self.assertEqual(len(results), 2)
        self.assertEqual(len({f['blob'] for f in results}), 1)
        self.assertEqual(len({f['id'] for f in results}), 2)

    def test_budget_blocked_explicit(self):
        from unittest.mock import patch
        with patch('osb.MAX_TOTAL', 0):
            report = audit(self.root)
        self.assertFalse(report['findings'])
        self.assertTrue(all(f['status'] == 'budget_blocked' for f in report['files'] if f['path'].endswith('.py')))

    def test_symlink_unanalysed(self):
        try:
            (self.root / 'link.py').symlink_to('app.py')
        except (OSError, NotImplementedError):
            self.skipTest('symlinks unavailable')
        self.commit()
        report = audit(self.root)
        self.assertEqual(next(f['status'] for f in report['files'] if f['path'] == 'link.py'), 'special_file')

    def test_placeholder_forms_and_comment_false_positive(self):
        from osb import python_findings
        source = b'def a():\n    "doc"\n    ...\nasync def b():\n    raise NotImplementedError()\ndef c():\n    # TODO pass\n    return 1\n'
        hits = python_findings(source)
        self.assertEqual({line for _, line, _ in hits}, {3, 5})
        self.assertTrue(all(state == 'candidate' for _, _, state in hits))
