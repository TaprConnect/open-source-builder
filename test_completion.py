"""Completion authority: verification side effects, release rollback, transaction integrity."""
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from osb_engine import completion, isolation, mutation
from osb_engine.audit import scan
from osb_engine.kernel import _schema, grant, reserve
from osb_engine.repository import Repository
from osb_engine.store import Store

P1 = b"--- a/a.py\n+++ b/a.py\n@@ -1,2 +1,2 @@\n-def a(): pass\n+def a(): return 1\n def b(): pass\n"
P2 = b"--- /dev/null\n+++ b/n.py\n@@ -0,0 +1 @@\n+n = 1\n"


class CompletionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        parent = Path(self.tmp.name)
        self.target = parent / "target"
        self.target.mkdir()
        run = lambda *a: subprocess.run(["git", "-C", str(self.target), "-c", "user.name=F",
                                         "-c", "user.email=f@example.invalid", "-c", "core.autocrlf=false", *a],
                                        check=True, capture_output=True)
        run("init")
        (self.target / "a.py").write_bytes(b"def a(): pass\ndef b(): pass\n")
        run("add", ".")
        run("commit", "-m", "fixture")
        self.store = Store(Repository(self.target), parent / "private.sqlite")
        report, _ = scan(self.store.repo, self.store, [])
        self.run_id = self.store.save(report)
        self.task = report["findings"][0]["id"]
        lease = reserve(self.store, self.run_id, self.task, 300)
        self.gen, self.token = lease["generation"], lease["token"]
        grant(self.store, self.run_id, self.task, self.gen, [("edit", ["a.py", "n.py"])])

    def tearDown(self):
        self.store.conn.close()
        self.tmp.cleanup()

    def count(self, table):
        return self.store.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]

    def test_schema_does_not_end_the_write_transaction(self):
        conn = self.store.conn
        with conn:
            conn.execute("BEGIN IMMEDIATE")
            _schema(conn)
            self.assertTrue(conn.in_transaction)

    @unittest.skipUnless(isolation.available(), "verification requires OS isolation")
    def test_verification_cannot_write_the_worktree(self):
        script = b"open('stray.txt', 'w').write('x')\n"
        completion.freeze(self.store, self.run_id, self.task, script)
        result = completion.verify(self.store, self.run_id, self.task, self.gen, script)
        self.assertFalse(result["passed"])
        self.assertFalse((self.target / "stray.txt").exists())
        with self.assertRaises(ValueError):
            completion.complete(self.store, self.run_id, self.task, self.gen, self.token)

    @unittest.skipUnless(isolation.available(), "verification requires OS isolation")
    def test_early_interpreter_exit_is_not_a_pass(self):
        script = b"import os\nos._exit(0)\n"
        completion.freeze(self.store, self.run_id, self.task, script)
        result = completion.verify(self.store, self.run_id, self.task, self.gen, script)
        self.assertEqual(result["returncode"], 0)
        self.assertFalse(result["passed"])

    def test_verification_refuses_without_isolation(self):
        script = b"pass\n"
        completion.freeze(self.store, self.run_id, self.task, script)
        with patch.object(isolation, "available", return_value=False), \
                patch.object(isolation, "_command", side_effect=AssertionError("must not run")):
            with self.assertRaisesRegex(ValueError, "unavailable"):
                completion.verify(self.store, self.run_id, self.task, self.gen, script)
        self.assertEqual(self.count("kernel_verifications_v1"), 0)

    def test_failed_revert_restores_worktree_and_records_no_release(self):
        mutation.mutate(self.store, self.run_id, self.task, self.gen, self.token, P1)
        mutation.mutate(self.store, self.run_id, self.task, self.gen, self.token, P2)
        real, calls = mutation._apply, []

        def flaky(repo, data, reverse=False):
            calls.append(reverse)
            if reverse and len(calls) == 2:
                raise subprocess.CalledProcessError(1, "git apply")
            real(repo, data, reverse)

        with patch.object(completion, "_apply", flaky):
            with self.assertRaisesRegex(ValueError, "restored"):
                completion.release(self.store, self.run_id, self.task, self.gen, "abandon", revert=True)
        self.assertEqual((self.target / "a.py").read_bytes(), b"def a(): return 1\ndef b(): pass\n")
        self.assertTrue((self.target / "n.py").exists())
        self.assertEqual(self.count("kernel_releases_v1"), 0)
        released = completion.release(self.store, self.run_id, self.task, self.gen, "abandon", revert=True)
        self.assertEqual(released["reverted_patches"], 2)
        self.assertEqual((self.target / "a.py").read_bytes(), b"def a(): pass\ndef b(): pass\n")
        self.assertFalse((self.target / "n.py").exists())
        again = reserve(self.store, self.run_id, self.task, 60)
        self.assertEqual(again["generation"], self.gen + 1)
