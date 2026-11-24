import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from changes import validate_and_apply
from research import next_range
from launch import plan, evaluate


class ProductReviewTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name) / "product"
        self.root.mkdir()
        self.evidence = Path(tmp.name) / "evidence"
        self.evidence.mkdir()
        self.git("init")
        for filename in ("old.txt", "app.txt"):
            (self.root / filename).write_text("initial\n")
        self.git("add", ".")
        self.git("-c", "user.name=Local", "-c", "user.email=local@localhost",
                 "commit", "-m", "baseline")
        self.dossier = plan(self.root)
        self.ledger = {"revision": self.dossier["revision"],
                       "files": {"app.txt": [[1, 1]], "old.txt": [[1, 1]]}}

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.root), *args], stderr=subprocess.PIPE)

    def verdict(self):
        return evaluate(self.root, self.dossier, self.ledger, self.evidence)

    def test_research_resumes_without_silently_advancing(self):
        partial = {"revision": self.dossier["revision"], "files": {"app.txt": [[1, 1]]}}
        chunk = next_range(self.root, partial)["range"]
        self.assertEqual((chunk["path"], chunk["lines"]), ("old.txt", ["initial"]))
        tiny = next_range(self.root, partial, max_chars=1)
        self.assertEqual(tiny["oversized_line"]["line"], 1)
        self.assertFalse(tiny["attested_coverage_complete"])
        self.assertTrue(next_range(self.root, self.ledger)["attested_coverage_complete"])

    def test_empty_review_cannot_pass(self):
        result = self.verdict()
        self.assertFalse(result["dossier_complete"])
        self.assertEqual(len(result["open_controls"]), len(self.dossier["controls"]))

    def test_missing_control_and_stale_revision_rejected(self):
        self.dossier["controls"].pop("Canary")
        with self.assertRaises(ValueError):
            self.verdict()
        self.dossier["revision"] = "stale"
        with self.assertRaisesRegex(ValueError, "stale"):
            self.verdict()

    def test_attestations_tampering_and_coverage(self):
        for name, row in self.dossier["controls"].items():
            status = "pass" if name == "Quality" else "not_applicable"
            raw = json.dumps({"revision": self.dossier["revision"], "control": name,
                              "reviewer": "tester", "status": status, "environment": "fixture",
                              "observation": "synthetic acceptance fixture"}).encode()
            (self.evidence / name).write_bytes(raw)
            row.update(status=status, reason="synthetic test case",
                       receipt={"path": name, "sha256": hashlib.sha256(raw).hexdigest()})
        self.assertTrue(self.verdict()["dossier_complete"])
        self.ledger["files"] = {}
        self.assertFalse(self.verdict()["dossier_complete"])
        (self.evidence / "Quality").write_text("changed")
        with self.assertRaisesRegex(ValueError, "hash"):
            self.verdict()

    def test_judged_patch_and_explicit_removal(self):
        (self.root / "old.txt").unlink()
        (self.root / "new.txt").write_text("new\n")
        (self.root / "app.txt").write_text("updated\n")
        self.git("add", "-A")
        patch = self.git("diff", "--cached", "--no-renames")
        self.git("reset", "--hard", "HEAD")
        actions = {"old.txt": "remove", "app.txt": "modify", "new.txt": "add"}
        manifest = {"revision": self.dossier["revision"], "patch_sha256": hashlib.sha256(patch).hexdigest(),
                    "changes": {p: dict(action=a, justification="fixture requirement",
                                        acceptance="exercise public caller", rollback="restore baseline")
                                for p, a in actions.items()}}
        self.assertEqual(validate_and_apply(self.root, patch, manifest)["changes"], actions)
        with self.assertRaisesRegex(ValueError, "approval"):
            validate_and_apply(self.root, patch, manifest, apply=True)
        self.assertFalse(self.git("status", "--porcelain"))
        with self.assertRaisesRegex(ValueError, "digest"):
            validate_and_apply(self.root, patch + b"\n", manifest)
        manifest["changes"]["new.txt"]["justification"] = ""
        with self.assertRaisesRegex(ValueError, "justification"):
            validate_and_apply(self.root, patch, manifest)
        manifest["changes"]["new.txt"]["justification"] = "new public requirement"
        validate_and_apply(self.root, patch, manifest, apply=True, allow_remove=True)
        self.assertFalse((self.root / "old.txt").exists())
        self.assertEqual((self.root / "app.txt").read_text(), "updated\n")
        self.assertEqual((self.root / "new.txt").read_text(), "new\n")
