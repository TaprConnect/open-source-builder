import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from repair import repair
from readiness import manifest_checks, route_findings


class ApplicationTests(unittest.TestCase):
    def test_public_site_has_no_auth_requirement(self):
        self.assertEqual(route_findings("page.ts", "", set()), [])

    def test_present_auth_is_not_verified(self):
        finding, = route_findings("route.ts", "// auth() may be unused", {"auth"})
        self.assertEqual(finding["status"], "candidate_evidence_requires_trace")

    def test_malformed_manifest(self):
        for source in ["null", "{", '{"scripts":[]}', '{"dependencies":null}']:
            with self.subTest(source=source):
                findings, patch = manifest_checks("package.json", source, set())
                self.assertEqual(findings[0]["status"], "invalid_manifest")
                self.assertIsNone(patch)

    def test_existing_scripts_preserved(self):
        findings, patch = manifest_checks("package.json", '{"scripts":{"lint":"check","build":"custom"},"dependencies":{"next":"1"}}', set())
        self.assertEqual((findings, patch), ([], None))

    def test_patch_preserves_existing_formatting(self):
        cases = {
            "four_spaces": ('{\n    "name": "x",\n    "dependencies": {\n        "next": "1"\n    }\n}\n',
                            '{\n    "name": "x",\n    "dependencies": {\n        "next": "1"\n    },\n'
                            '    "scripts": {\n        "build": "next build"\n    }\n}\n'),
            "tabs": ('{\n\t"dependencies": {\n\t\t"next": "1"\n\t}\n}\n',
                     '{\n\t"dependencies": {\n\t\t"next": "1"\n\t},\n\t"scripts": {\n\t\t"build": "next build"\n\t}\n}\n'),
            "compact": ('{"dependencies":{"next":"1"}}\n',
                        '{"dependencies":{"next":"1"},"scripts":{"build":"next build"}}\n'),
        }
        for name, (source, expected) in cases.items():
            with self.subTest(name):
                findings, patch = manifest_checks("package.json", source, set())
                self.assertEqual({f["status"] for f in findings}, {"missing_package_script"})
                removed = [l for l in patch.splitlines() if l.startswith("-") and not l.startswith("---")]
                self.assertLessEqual(len(removed), 1, patch)
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
                    (root / "package.json").write_text(source, newline="")
                    subprocess.run(["git", "apply", "-"], cwd=root, input=patch.encode(), check=True)
                    self.assertEqual((root / "package.json").read_text(newline=""), expected)

    def test_patch_withheld_when_rewrite_would_lose_content(self):
        for source in ['{"name":"a","name":"b","dependencies":{"next":"1"}}\n',
                       '{\r\n  "dependencies": {\r\n    "next": "1"\r\n  }\r\n}\r\n',
                       '{"dependencies": {"next": "\\u0031"}}\n',
                       '{"dependencies":{"next":"1"}}']:
            with self.subTest(source=source):
                findings, patch = manifest_checks("package.json", source, set())
                self.assertIsNone(patch)
                self.assertIn("patch_withheld_unsupported_formatting", {f["status"] for f in findings})

    def test_cli_and_applicable_patch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            def git(*args, **kw):
                return subprocess.run(["git", *args], cwd=root, check=True, capture_output=True, **kw)
            git("init")
            path = "app/api/projects/route.ts"
            (root / path).parent.mkdir(parents=True)
            (root / path).write_text("const records = new Map();\n")
            (root / "package.json").write_text('{"dependencies":{"next":"1","eslint":"1"}}\n')
            (root / "eslint.config.mjs").touch()
            git("add", ".")
            git("-c", "user.name=Tests", "-c", "user.email=tests@localhost", "commit", "-m", "fixture")
            args = [sys.executable, str(Path(__file__).with_name("scanner.py").resolve()), tmp,
                    "--include-manifest-patches", "--private-route", path, "--durable-route", path, "--durable-route", "missing.ts"]
            report = json.loads(subprocess.check_output(args))["readiness"]
            self.assertEqual(report["route_candidates"], [path])
            statuses = {f["status"] for f in report["findings"]}
            self.assertTrue({"in_memory_storage_requires_trace", "no_direct_evidence", "missing_declared_path"} <= statuses)
            patch = report["proposed_manifest_patches"][0]["patch"]
            git("apply", "--check", "-", input=patch.encode())
            self.assertEqual(repair(tmp), ["package.json"])
            self.assertEqual(repair(tmp, apply=True), ["package.json"])
            with self.assertRaises(ValueError):
                repair(tmp, apply=True)
            self.assertEqual(json.loads((root / "package.json").read_text())["scripts"],
                             {"lint": "eslint .", "build": "next build"})
