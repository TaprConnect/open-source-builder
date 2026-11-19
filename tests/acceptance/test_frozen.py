"""Frozen acceptance scripts as unittest cases (opt-in: OSB_ACCEPTANCE=1; several minutes)."""
import os
import unittest

from tests.acceptance import harness


class FrozenAcceptance(unittest.TestCase):
    def test_manifest_hashes(self):
        for name in harness.MANIFEST:
            harness.script(name)


def _case(name):
    def test(self):
        if os.environ.get("OSB_ACCEPTANCE") != "1":
            self.skipTest("set OSB_ACCEPTANCE=1 to run frozen acceptance scripts")
        reason = harness.supported(name)
        if reason:
            self.skipTest(reason)
        code, out, err = harness.run(name)
        self.assertEqual(code, 0, (out[-2000:], err[-4000:]))
    return test


for _name in harness.MANIFEST:
    setattr(FrozenAcceptance, f"test_{_name}", _case(_name))
