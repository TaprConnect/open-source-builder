"""S05-003/S05-005/S05-008: executable assurance over all catalogue domains."""
import unittest
from pathlib import Path
from unittest import mock

from osb_engine import assurance, runtime
from osb_engine.controls import catalogue
from osb_engine.intelligence import build_index
from test_ts_plugin import SERVER, repo_with

ROWS = catalogue(Path(__file__).with_name("profiles") / "checks.tsv")
CLEAN_PY = {"app.py": b"def add(a, b):\n    return a + b\n",
            "tests/__init__.py": b"", "tests/test_app.py": b"import unittest\nfrom app import add\n"
            b"class T(unittest.TestCase):\n    def test_add(self):\n        self.assertEqual(add(1, 2), 3)\n"}


def by_domain(result):
    return {c["domain"]: c for c in result["controls"]}


class AssuranceEngine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo = repo_with({"package.json": b'{"dependencies": {"express": "4"}}', "src/server.ts": SERVER,
                              "src/auth.ts": b"export const requireAuth = (q,s,n) => n();\n",
                              "src/db.ts": b'import { Pool } from "pg"; export const db = new Pool();\n'})
        cls.index = build_index(cls.repo)
        cls.clean = repo_with(CLEAN_PY)
        cls.clean_index = build_index(cls.clean)

    def test_every_catalogue_domain_has_one_control_with_a_receipt(self):
        result = assurance.evaluate(ROWS, self.index)
        self.assertEqual(len(result["controls"]), len(ROWS))
        self.assertEqual(result["coverage"]["catalogue_domains_without_definition"], [])
        for c in result["controls"]:
            self.assertIn(c["state"], assurance.STATES)
            self.assertEqual(len(c["receipt_sha256"]), 64)
            self.assertEqual(c["revision"], self.index["revision"])
            self.assertTrue(c["id"].startswith("E01-") and c["version"])

    def test_static_findings_fail_and_dependencies_block(self):
        controls = by_domain(assurance.evaluate(ROWS, self.index))
        for name in ("Identity", "Persistence", "WebDefences", "SupplyChain", "Backend"):
            self.assertEqual(controls[name]["state"], "fail", name)
        self.assertEqual(controls["Tenancy"]["state"], "blocked")
        self.assertIn("Identity", controls["Tenancy"]["reason"])

    def test_clean_static_scan_is_never_a_security_pass(self):
        controls = by_domain(assurance.evaluate(ROWS, self.clean_index))
        self.assertEqual(controls["Secrets"]["state"], "unknown")
        self.assertNotIn("pass", {c["state"] for c in controls.values()})

    def test_external_acceptance_is_revision_bound(self):
        good = [{"control": "E01-Secrets", "passed": True, "revision": self.clean_index["revision"], "verification": 7}]
        result = by_domain(assurance.evaluate(ROWS, self.clean_index, acceptance=good))
        self.assertEqual(result["Secrets"]["state"], "pass")
        self.assertEqual(result["Secrets"]["confidence"], "external")
        stale = [{**good[0], "revision": "0" * 40}]
        out = assurance.evaluate(ROWS, self.clean_index, acceptance=stale)
        self.assertEqual(by_domain(out)["Secrets"]["state"], "unknown")
        self.assertEqual(out["stale_acceptance"], ["E01-Secrets"])
        failed = [{**good[0], "passed": False}]
        self.assertEqual(by_domain(assurance.evaluate(ROWS, self.clean_index, acceptance=failed))["Secrets"]["state"], "fail")

    def test_trusted_runtime_receipts_can_pass_non_security_controls_only(self):
        trusted = runtime.run(self.clean, self.clean_index, adapters=("build", "unit_tests"), trusted=True)
        if not trusted["isolation"]:
            self.skipTest("verification requires OS isolation")
        controls = by_domain(assurance.evaluate(ROWS, self.clean_index, trusted))
        self.assertEqual(controls["Build"]["state"], "pass")
        self.assertEqual(controls["Build"]["confidence"], "runtime-trusted")
        untrusted = runtime.run(self.clean, self.clean_index, adapters=("build", "unit_tests"))
        self.assertEqual(by_domain(assurance.evaluate(ROWS, self.clean_index, untrusted))["Build"]["state"], "unknown")

    def test_stale_runtime_receipts_are_not_used(self):
        observed = {"revision": "f" * 40, "receipts": {"build": [{"state": "pass", "trust": "trusted_target"}]}}
        controls = by_domain(assurance.evaluate(ROWS, self.clean_index, observed))
        self.assertNotEqual(controls["Build"]["state"], "pass")

    def test_failure_isolation(self):
        def broken(index):
            raise RuntimeError("boom")
        with mock.patch.dict(assurance.STATIC, {"Secrets": broken}):
            controls = by_domain(assurance.evaluate(ROWS, self.index))
        self.assertEqual(controls["Secrets"]["state"], "blocked")
        self.assertIn("evaluator error", controls["Secrets"]["reason"])
        self.assertEqual(controls["Identity"]["state"], "fail")

    def test_execution_budget(self):
        ticks = iter(range(0, 10_000, 10))
        result = assurance.evaluate(ROWS, self.index, budget_seconds=25, clock=lambda: next(ticks))
        states = [c["state"] for c in result["controls"]]
        self.assertIn("not_performed", states)
        self.assertTrue(any(c.get("reason") == "execution budget exhausted" for c in result["controls"]))

    def test_dependency_cycle_rejected(self):
        cyclic = [("A", "x", False, "always", None, (), ("B",), "b"), ("B", "x", False, "always", None, (), ("A",), "b")]
        with self.assertRaises(ValueError):
            assurance._order(cyclic)

    def test_runtime_fails_closed_without_isolation(self):
        with mock.patch.object(runtime, "isolation_available", lambda: False):
            out = runtime.run(self.clean, self.clean_index, adapters=("build", "unit_tests"))
        for adapter in ("build", "unit_tests"):
            self.assertEqual(out["receipts"][adapter][0]["state"], "blocked")
            self.assertIn("fail closed", out["receipts"][adapter][0]["reason"])

    def test_external_only_adapters_never_self_certify(self):
        out = runtime.run(self.clean, self.clean_index, adapters=("authorization", "persistence"), trusted=True)
        for adapter in ("authorization", "persistence"):
            self.assertEqual(out["receipts"][adapter][0]["state"], "not_performed")

    def test_unsupported_domains_name_their_blocker(self):
        controls = by_domain(assurance.evaluate(ROWS, self.index))
        for c in controls.values():
            if c["state"] == "unsupported":
                self.assertTrue(c["reason"])


class IdentityRound2(unittest.TestCase):
    def test_public_recovery_routes_and_private_reads(self):
        from osb_engine.assurance import _identity
        index = {"completeness": [
            {"file": "a.js", "methods": ["POST"], "path": "/forgotpw", "auth": "not_detected", "flags": [], "handler": "h"},
            {"file": "a.js", "methods": ["POST"], "path": "/notes", "auth": "not_detected", "flags": [], "handler": "h"},
            {"file": "a.js", "methods": ["GET"], "path": "/admin/usersapi", "auth": "not_detected", "flags": [], "handler": "h"},
            {"file": "a.js", "methods": ["GET"], "path": "/products", "auth": "not_detected", "flags": [], "handler": "h"}]}
        _, hits = _identity(index)
        self.assertEqual(sorted(h["route"] for h in hits), ["GET /admin/usersapi", "POST /notes"])
