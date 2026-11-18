"""Exercise durable reservation semantics against the real planning store."""
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from osb_engine.audit import scan
from osb_engine.kernel import dispatch, grant, pause, renew, reserve, resume, revoke
from osb_engine.repository import Repository
from osb_engine.store import Store


class ReservationTests(unittest.TestCase):
    def test_expiry_recovery_and_conflict_preserve_slot(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            target = parent / "target"
            target.mkdir()
            def git(*args):
                subprocess.run(["git", "-C", str(target), "-c", "user.name=Fixture",
                                "-c", "user.email=test@example.invalid", *args],
                               check=True, capture_output=True)
            git("init")
            (target / "module.py").write_text("def first(): pass\ndef second(): pass\n")
            git("add", "module.py")
            git("commit", "-m", "fixture")
            repo = Repository(target)
            database = parent / "private.sqlite"
            with Store(repo, database) as store:
                report, _ = scan(repo, store, [])
                run = store.save(report)
                first, second = [f["id"] for f in report["findings"]]
                with patch("osb_engine.kernel.time.time_ns", return_value=1_000_000_000):
                    initial = reserve(store, run, first, 1)
            with Store(repo, database) as store:
                with patch("osb_engine.kernel.time.time_ns", return_value=initial["expires_ns"]):
                    with self.assertRaises(ValueError):
                        reserve(store, run, second, 10)
                    with self.assertRaises(ValueError):
                        renew(store, run, first, initial["generation"], 10, initial["token"])
                    current = reserve(store, run, first, 10)
                    self.assertEqual(current["generation"], initial["generation"] + 1)
                    with self.assertRaises(ValueError):
                        renew(store, run, first, current["generation"], 1, initial["token"])
                    renewed = renew(store, run, first, current["generation"], 20, current["token"])
                    self.assertGreater(renewed["expires_ns"], current["expires_ns"])
                    self.assertNotIn("token", renewed)


class DispatchGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        parent = Path(self.tmp.name)
        self.target = parent / "target"
        self.target.mkdir()
        self.git("init")
        (self.target / "module.py").write_bytes(b"def first(): pass\ndef second(): pass\n")
        self.git("add", "module.py")
        self.git("commit", "-m", "fixture")
        self.database = parent / "private.sqlite"
        repo = Repository(self.target)
        with Store(repo, self.database) as store:
            report, _ = scan(repo, store, [])
            self.run_id = store.save(report)
            self.first, self.second = [f["id"] for f in report["findings"]]

    def tearDown(self):
        self.tmp.cleanup()

    def git(self, *args):
        subprocess.run(["git", "-C", str(self.target), "-c", "user.name=Fixture",
                        "-c", "user.email=test@example.invalid", "-c", "core.autocrlf=false", *args],
                       check=True, capture_output=True)

    def store(self):
        return Store(Repository(self.target), self.database)

    def dispatched(self, store):
        return store.conn.execute("SELECT COUNT(*) FROM kernel_dispatches_v1").fetchone()[0]

    def test_scope_pause_revocation_and_denials_leave_no_record(self):
        with self.store() as store:
            lease = reserve(store, self.run_id, self.first, 60)
            gen, token = lease["generation"], lease["token"]
            with self.assertRaises(ValueError):
                dispatch(store, self.run_id, self.first, gen, token, "edit", ["module.py"])
            for bad in ("/abs", "../x", "a/../b", ".git/config", ".GIT/x", "", "./a", "a\\b",
                        "GIT~1/config", ".git./config", "a.py::$DATA", "CON", "nul.txt",
                        "a.py.", "a.py ", "x/.Git/HEAD", "café.py"):
                with self.assertRaises(ValueError):
                    grant(store, self.run_id, self.first, gen, [("edit", [bad])])
            with self.assertRaises(ValueError):
                grant(store, self.run_id, self.second, gen, [("edit", ["module.py"])])
            grant(store, self.run_id, self.first, gen, [("edit", ["module.py", "pkg/"])])
            record = dispatch(store, self.run_id, self.first, gen, token, "edit",
                              ["pkg/a.py", "module.py"])
            self.assertEqual(record["operation"]["paths"], ["module.py", "pkg/a.py"])
            denials = [(self.first, gen, token, "edit", ["other.py"]),
                       (self.first, gen, token, "edit", ["pkg"]),
                       (self.first, gen, token, "delete", ["module.py"]),
                       (self.first, gen, token, "edit", []),
                       (self.first, gen, "wrong", "edit", ["module.py"]),
                       (self.first, gen + 1, token, "edit", ["module.py"]),
                       (self.second, gen, token, "edit", ["module.py"])]
            for task, g, t, kind, paths in denials:
                with self.assertRaises(ValueError):
                    dispatch(store, self.run_id, task, g, t, kind, paths)
            self.assertEqual(self.dispatched(store), 1)

            pause(store, "investigation")
            with self.assertRaises(ValueError):
                dispatch(store, self.run_id, self.first, gen, token, "edit", ["module.py"])
            renew(store, self.run_id, self.first, gen, 60, token)
            resume(store, "cleared")
            dispatch(store, self.run_id, self.first, gen, token, "edit", ["module.py"])

            revoke(store, self.run_id, self.first, gen, "compromised")
            for call in (lambda: dispatch(store, self.run_id, self.first, gen, token, "edit", ["module.py"]),
                         lambda: renew(store, self.run_id, self.first, gen, 60, token),
                         lambda: revoke(store, self.run_id, self.first, gen, "again"),
                         lambda: reserve(store, self.run_id, self.second, 60)):
                with self.assertRaises(ValueError):
                    call()
            recovered = reserve(store, self.run_id, self.first, 60)
            self.assertEqual(recovered["generation"], gen + 1)
            with self.assertRaises(ValueError):
                dispatch(store, self.run_id, self.first, gen + 1, recovered["token"], "edit", ["module.py"])
            self.assertEqual(self.dispatched(store), 2)

    def test_expiry_and_revision_change_deny_dispatch(self):
        with self.store() as store:
            with patch("osb_engine.kernel.time.time_ns", return_value=1_000_000_000):
                lease = reserve(store, self.run_id, self.first, 5)
                grant(store, self.run_id, self.first, lease["generation"], [("edit", ["module.py"])])
                dispatch(store, self.run_id, self.first, lease["generation"], lease["token"],
                         "edit", ["module.py"])
            with patch("osb_engine.kernel.time.time_ns", return_value=lease["expires_ns"]):
                with self.assertRaises(ValueError):
                    dispatch(store, self.run_id, self.first, lease["generation"], lease["token"],
                             "edit", ["module.py"])
        with self.store() as store:
            lease = reserve(store, self.run_id, self.first, 60)
            grant(store, self.run_id, self.first, lease["generation"], [("edit", ["module.py"])])
        self.git("commit", "--allow-empty", "-m", "moved")
        with self.store() as store:
            with self.assertRaises(ValueError):
                dispatch(store, self.run_id, self.first, lease["generation"], lease["token"],
                         "edit", ["module.py"])
            self.assertEqual(self.dispatched(store), 1)