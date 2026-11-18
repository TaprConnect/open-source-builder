"""Isolation runner refusals that must hold before any worker code runs."""
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from osb_engine import isolation
from osb_engine.audit import scan
from osb_engine.kernel import reserve
from osb_engine.repository import Repository
from osb_engine.store import Store


class IsolationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.parent = Path(self.tmp.name)
        target = self.parent / "target"
        target.mkdir()
        run = lambda *a: subprocess.run(["git", "-C", str(target), "-c", "user.name=F",
                                         "-c", "user.email=f@example.invalid", "-c", "core.autocrlf=false", *a],
                                        check=True, capture_output=True)
        run("init")
        (target / "a.py").write_bytes(b"def a(): pass\n")
        run("add", ".")
        run("commit", "-m", "fixture")
        private = self.parent / "private"
        private.mkdir(mode=0o700)
        self.store = Store(Repository(target), private / "s.sqlite")
        report, _ = scan(self.store.repo, self.store, [])
        self.run_id = self.store.save(report)
        self.task = report["findings"][0]["id"]
        lease = reserve(self.store, self.run_id, self.task, 300)
        self.gen, self.token = lease["generation"], lease["token"]
        self.outbox = self.parent / "outbox"
        self.outbox.mkdir()

    def tearDown(self):
        self.store.conn.close()
        self.tmp.cleanup()

    def call(self, outbox=None, inputs=None):
        return isolation.run_worker(self.store, self.run_id, self.task, self.gen, self.token,
                                    outbox or self.outbox, ["true"], inputs)

    def never_run(self, *args, **kwargs):
        raise AssertionError("worker must not start")

    def test_refuses_without_isolation_mechanism(self):
        with patch.object(isolation, "available", return_value=False), \
                patch.object(isolation.subprocess, "run", self.never_run):
            with self.assertRaisesRegex(ValueError, "unavailable"):
                self.call()

    def test_refuses_unsafe_outbox_and_inputs_before_running(self):
        (self.parent / "busy").mkdir()
        (self.parent / "busy" / "x").write_text("x")
        cases = [dict(outbox=self.parent / "busy"),
                 dict(outbox=self.store.repo.root),
                 dict(outbox=self.parent / "private"),
                 dict(inputs={"db": self.parent / "private" / "s.sqlite"}),
                 dict(inputs={"../x": self.parent / "busy" / "x"})]
        with patch.object(isolation, "available", return_value=True), \
                patch.object(isolation.subprocess, "run", self.never_run):
            for case in cases:
                with self.assertRaises(ValueError, msg=str(case)):
                    self.call(**case)

    def test_outbox_links_are_not_read(self):
        secret = self.parent / "secret.txt"
        secret.write_text("host secret")
        try:
            os.symlink(secret, self.outbox / "1.patch")
        except OSError:
            self.skipTest("symlinks not permitted on this host")
        os.link(secret, self.outbox / "2.patch")
        found = isolation._patches(self.outbox)
        self.assertEqual([(n, d) for n, d, _ in found], [("1.patch", None), ("2.patch", None)])
