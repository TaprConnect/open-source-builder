"""S05-010: coverage states and resource bounds stay explicit under hostile inputs."""
import unittest

from osb_engine import intelligence, plugins
from osb_engine.intelligence import build_index
from test_ts_plugin import repo_with


class ResourceIntegrity(unittest.TestCase):
    def test_oversized_file_has_an_explicit_reason(self):
        repo = repo_with({"big.py": b"x = 1\n" * (intelligence.MAX_FILE_BYTES // 6 + 10), "ok.py": b"y = 2\n"})
        files = {f["path"]: f for f in build_index(repo)["files"]}
        self.assertEqual(files["big.py"]["state"], "INDEXED")
        self.assertIn("per-file analysis limit", files["big.py"]["reason"])
        self.assertNotEqual(files["ok.py"]["state"], "INDEXED")

    def test_aggregate_file_and_byte_budgets(self):
        repo = repo_with({f"m{i}.py": b"def f():\n    return 1\n" for i in range(30)})
        index = build_index(repo, max_files=10)
        limited = [f for f in index["files"] if "aggregate analysis budget" in f.get("reason", "")]
        self.assertEqual(len(limited), 20)
        index = build_index(repo, max_total_bytes=100)
        self.assertTrue(all(f["state"] == "INDEXED" for f in index["files"][5:]))

    def test_every_file_has_a_state_and_unparsed_files_say_why(self):
        repo = repo_with({"bad.py": b"def (:\n", "bad.json": b"{", "x.bin": b"\x00\x01", "deep.py": b"(" * 5000 + b")" * 5000,
                          "bad.ts": b"\xff\xfe"})
        for f in build_index(repo)["files"]:
            self.assertIn(f["state"], intelligence.STATES)
            if f["state"] == "INDEXED" and f["language"] is not None:
                self.assertTrue(f.get("error") or f.get("reason"), f)

    def test_plugin_output_is_bounded(self):
        source = "".join(f"def f{i}():\n    pass\n" for i in range(plugins._LIMIT + 500)).encode()
        facts = plugins.extract("python", source, "many.py")["facts"]
        self.assertEqual(len(facts["definitions"]), plugins._LIMIT)
        self.assertLessEqual(len(facts["issues"]), plugins._LIMIT)
