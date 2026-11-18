import pathlib
import tempfile
import unittest

from verifier import compare, git


class VerificationTests(unittest.TestCase):
    def test_observed_repair_requires_explicit_assertion(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = pathlib.Path(tmp)
            git(repo, "init", "-q")
            git(repo, "config", "user.email", "test@example.invalid")
            git(repo, "config", "user.name", "Test")
            for value in ("broken", "fixed"):
                (repo / "value").write_text(value)
                git(repo, "add", "value")
                git(repo, "commit", "-qm", value)
            script = repo / "acceptance.py"
            script.write_text("from pathlib import Path\n"
                              "raise SystemExit(0 if Path('value').read_text() == 'fixed' else 42)")
            receipt = compare(repo, "HEAD~1", "HEAD", script, 5)
            self.assertTrue(receipt["observed_repair"])
            script.write_text("raise ValueError('broken harness')")
            self.assertFalse(compare(repo, "HEAD~1", "HEAD", script, 5)["observed_repair"])
            with self.assertRaises(ValueError):
                compare(repo, "HEAD", "HEAD", script, 5)
