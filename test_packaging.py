"""The packaged control catalogue must stay identical to the repository copy."""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent


class PackagingTests(unittest.TestCase):
    def test_packaged_catalogue_matches_repository_catalogue(self):
        self.assertEqual((ROOT / "osb_engine" / "profiles" / "checks.tsv").read_bytes(),
                         (ROOT / "profiles" / "checks.tsv").read_bytes())
