"""Isolated analysis: fail-closed version binding and per-file failure attribution."""
import json
import unittest
from unittest.mock import patch

from osb_engine import analysis, sandboxed


def fake_child(version, fail_keys=(), crash_batch=False):
    def run(root, argv, inputs, timeout, env=None, stdin_data=b"", limits=None, max_output=None):
        items = json.loads(stdin_data)["items"]
        keys = [k for k, _, _ in items]
        if crash_batch and len(items) > 1 or any(k in fail_keys for k in keys):
            return -9, b"", b"killed"
        results = {k: ["analysed", {"findings": []}] for k in keys}
        return 0, json.dumps({"version": version, "results": results}).encode(), b""
    return run


class SandboxedAnalysisTests(unittest.TestCase):
    def analyser(self, run):
        with patch.object(sandboxed, "available", return_value=True):
            analyse = sandboxed.isolated_analyser("/nonexistent", 2, 64)
        return lambda items: self._call(analyse, run, items)

    @staticmethod
    def _call(analyse, run, items):
        with patch.object(sandboxed, "run_isolated", run):
            return analyse(items)

    def test_version_mismatch_fails_closed(self):
        analyse = self.analyser(fake_child("other-version"))
        with self.assertRaisesRegex(ValueError, "version"):
            analyse([("python:a", "python", b"x = 1\n")])

    def test_failed_batch_is_attributed_per_file(self):
        analyse = self.analyser(fake_child(analysis.VERSION, fail_keys={"python:bomb"}, crash_batch=True))
        results = analyse([("python:ok", "python", b"x = 1\n"), ("python:bomb", "python", b"y = 2\n")])
        self.assertIsNone(results["python:bomb"])
        self.assertEqual(results["python:ok"][0], "analysed")

    def test_refuses_without_isolation(self):
        with patch.object(sandboxed, "available", return_value=False):
            with self.assertRaisesRegex(ValueError, "unavailable"):
                sandboxed.isolated_analyser("/nonexistent")
