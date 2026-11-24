"""Plug-in behaviour must not depend on the interpreter version (requires-python >= 3.10)."""
import builtins
import unittest
from unittest import mock

from osb_engine import plugins

PYPROJECT = (b'# comment\n[project]\nname = "demo"\nversion = "1"\n'
             b'dependencies = [\n  "requests>=2",  # http\n  \'PyYAML\',\n  "python-jose[cryptography]; python_version>\'3\'",\n]\n'
             b'[project.optional-dependencies]\ntest = ["pytest==8.0"]\n[tool.x]\ndependencies = ["not-this"]\n')


def without_tomllib():
    real = builtins.__import__

    def fake(name, *args, **kwargs):
        if name == "tomllib":
            raise ImportError(name)
        return real(name, *args, **kwargs)
    return mock.patch.object(builtins, "__import__", fake)


class PluginCompatibility(unittest.TestCase):
    def test_sql_tables_extracted(self):
        result = plugins._sql(b"CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT);\n"
                              b"CREATE TABLE orders (id INTEGER, user_id INTEGER REFERENCES users(id));\n")
        self.assertEqual(result["state"], "SYMBOL_INDEXED")
        self.assertEqual({t["name"] for t in result["facts"]["tables"]}, {"users", "orders"})

    def test_sql_side_effects_still_denied(self):
        self.assertEqual(plugins._sql(b"ATTACH DATABASE '/tmp/x.db' AS x;")["state"], "INDEXED")

    def check_pyproject(self):
        result = plugins._pyproject(PYPROJECT)
        self.assertIn(result["state"], ("PARSED", "SYMBOL_INDEXED"))
        self.assertEqual(result["facts"]["dependencies"], ["PyYAML", "pytest", "python-jose", "requests"])
        toml = plugins._toml(b'title = "x"\n[server]\nport = 1\n')
        self.assertIn(toml["state"], ("PARSED", "SYMBOL_INDEXED"))
        self.assertEqual(toml["facts"]["keys"], ["server", "title"])

    def test_pyproject_dependencies(self):
        self.check_pyproject()

    def test_pyproject_dependencies_without_tomllib(self):
        with without_tomllib():
            self.check_pyproject()

    def test_subset_parser_never_raises(self):
        with without_tomllib():
            for data in (b"[", b'a = [\n"x', b'x = """\n[project]\n"""', b"\xff"):
                self.assertIn(plugins._pyproject(data)["state"], ("INDEXED", "PARSED", "SYMBOL_INDEXED"))
