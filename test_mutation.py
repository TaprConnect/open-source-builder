"""Mediated mutation: filesystem refusals, transaction serialisation and revert."""
import os
import sqlite3
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from osb_engine import mutation
from osb_engine.audit import scan
from osb_engine.kernel import grant, reserve
from osb_engine.repository import Repository
from osb_engine.store import Store

EDIT = b"--- a/a.py\n+++ b/a.py\n@@ -1 +1 @@\n-def a(): pass\n+def a(): return 1\n"


class MutationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.parent = Path(self.tmp.name)
        self.target = self.parent / "target"
        self.target.mkdir()
        self.git("init")
        (self.target / "a.py").write_text("def a(): pass\n", newline="\n")
        (self.target / "h.py").write_text("h = 1\n", newline="\n")
        self.git("add", ".")
        self.git("commit", "-m", "fixture")
        self.database = self.parent / "private.sqlite"
        self.store = Store(Repository(self.target), self.database)
        report, _ = scan(self.store.repo, self.store, [])
        self.run_id = self.store.save(report)
        self.task = report["findings"][0]["id"]
        lease = reserve(self.store, self.run_id, self.task, 300)
        self.gen, self.token = lease["generation"], lease["token"]
        grant(self.store, self.run_id, self.task, self.gen, [("edit", ["a.py", "h.py", "A.py"])])

    def tearDown(self):
        self.store.conn.close()
        self.tmp.cleanup()

    def git(self, *args):
        subprocess.run(["git", "-C", str(self.target), "-c", "user.name=F",
                        "-c", "user.email=f@example.invalid", "-c", "core.autocrlf=false", *args],
                       check=True, capture_output=True)

    def mutate(self, data):
        return mutation.mutate(self.store, self.run_id, self.task, self.gen, self.token, data)

    def rows(self):
        return self.store.conn.execute("SELECT COUNT(*) FROM kernel_dispatches_v1").fetchone()[0]

    def test_hard_linked_target_is_refused(self):
        outside = self.parent / "outside.py"
        outside.write_bytes((self.target / "h.py").read_bytes())
        (self.target / "h.py").unlink()
        os.link(outside, self.target / "h.py")
        with self.assertRaisesRegex(ValueError, "single-link"):
            self.mutate(b"--- a/h.py\n+++ b/h.py\n@@ -1 +1 @@\n-h = 1\n+h = 2\n")
        self.assertEqual(outside.read_text(), "h = 1\n")

    def test_case_alias_of_existing_file_is_refused(self):
        with self.assertRaisesRegex(ValueError, "case"):
            self.mutate(b"--- /dev/null\n+++ b/A.py\n@@ -0,0 +1 @@\n+x = 1\n")
        self.assertEqual(self.rows(), 0)

    def test_revocation_cannot_commit_between_check_and_apply(self):
        seen = []
        real = mutation._apply

        def racing_apply(repo, data, reverse=False):
            other = sqlite3.connect(self.database, timeout=0.2)
            try:
                other.execute("BEGIN IMMEDIATE")
                seen.append("acquired")
            except sqlite3.OperationalError as exc:
                seen.append(str(exc))
            finally:
                other.close()
            real(repo, data, reverse)

        with patch.object(mutation, "_apply", racing_apply):
            self.mutate(EDIT)
        self.assertEqual(seen, ["database is locked"])
        self.assertEqual(self.rows(), 1)

    def test_revision_change_during_apply_reverts(self):
        real = mutation._apply

        def moving_apply(repo, data, reverse=False):
            real(repo, data, reverse)
            if not reverse:
                self.git("commit", "--allow-empty", "-m", "moved")

        with patch.object(mutation, "_apply", moving_apply):
            with self.assertRaisesRegex(ValueError, "reverted"):
                self.mutate(EDIT)
        self.assertEqual((self.target / "a.py").read_text(), "def a(): pass\n")
        self.assertEqual(self.rows(), 0)
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM kernel_ledger_v1").fetchone()[0], 0)

    def test_applied_patch_is_recorded_and_tamper_blocks_next(self):
        result = self.mutate(EDIT)
        self.assertEqual(result["operation"]["changes"], [["edit", "a.py"]])
        (self.target / "a.py").write_text("tampered\n")
        with self.assertRaisesRegex(ValueError, "out-of-band"):
            self.mutate(b"--- a/h.py\n+++ b/h.py\n@@ -1 +1 @@\n-h = 1\n+h = 2\n")
        self.assertEqual(self.rows(), 1)


class LegacyApplyTests(unittest.TestCase):
    """S02-009: the pre-kernel apply command cannot silently feed kernel-governed work."""

    def test_legacy_apply_is_detected_as_out_of_band(self):
        from osb_engine.repair import apply_prepared, check_patch
        from osb_engine.kernel import dispatch
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            main, linked = parent / "main", parent / "linked"
            main.mkdir()
            git = lambda cwd, *a: subprocess.run(["git", "-C", str(cwd), "-c", "user.name=F",
                                                  "-c", "user.email=f@example.invalid",
                                                  "-c", "core.autocrlf=false", *a],
                                                 check=True, capture_output=True)
            git(main, "init")
            (main / "a.py").write_bytes(b"def a(): pass\n")
            git(main, "add", ".")
            git(main, "commit", "-m", "fixture")
            git(main, "worktree", "add", "--detach", str(linked))
            store = Store(Repository(linked), parent / "private.sqlite")
            try:
                report, _ = scan(store.repo, store, [])
                run = store.save(report)
                task = report["findings"][0]["id"]
                lease = reserve(store, run, task, 300)
                grant(store, run, task, lease["generation"], [("edit", ["a.py"])])
                declarations = {"a.py": {"action": "modify", "justification": "j",
                                         "acceptance": "a", "rollback": "r"}}
                receipt = check_patch(store.repo, EDIT, declarations, b"assert True\n")
                apply_prepared(store.repo, EDIT, declarations, b"assert True\n", receipt["approval_id"])
                self.assertEqual((linked / "a.py").read_bytes(), b"def a(): return 1\n")
                with self.assertRaisesRegex(ValueError, "out-of-band"):
                    mutation.mutate(store, run, task, lease["generation"], lease["token"],
                                    b"--- a/a.py\n+++ b/a.py\n@@ -1 +1 @@\n-def a(): return 1\n+def a(): return 2\n")
                with self.assertRaisesRegex(ValueError, "out-of-band"):
                    dispatch(store, run, task, lease["generation"], lease["token"], "edit", ["a.py"])
                self.assertEqual(store.conn.execute("SELECT COUNT(*) FROM kernel_dispatches_v1").fetchone()[0], 0)
            finally:
                store.conn.close()