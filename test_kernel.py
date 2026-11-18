"""Exercise durable reservation semantics against the real planning store."""
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from osb_engine.audit import scan
from osb_engine.kernel import renew, reserve
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
