import unittest
from coverage import assess


class CoverageTests(unittest.TestCase):
    snapshot = {"revision": "abc", "files": [{"path": "app", "status": "indexed", "lines": 8}]}

    def run_ranges(self, ranges):
        return assess(self.snapshot, {"revision": "abc", "files": {"app": ranges}})

    def test_hidden_gap(self):
        self.assertEqual(self.run_ranges([[1, 3], [5, 8]])["unreviewed"], [["app", 4, 4]])

    def test_overlaps(self):
        self.assertTrue(self.run_ranges([[3, 8], [1, 4]])["attested_coverage_complete"])

    def test_bad_bounds(self):
        with self.assertRaises(ValueError):
            self.run_ranges([[0, 8]])

    def test_wrong_revision(self):
        with self.assertRaises(ValueError):
            assess(self.snapshot, {"revision": "old", "files": {}})
