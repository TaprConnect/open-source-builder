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


def without_toml_parsers():
    real = builtins.__import__

    def fake(name, *args, **kwargs):
        if name in ("tomllib", "tomli"):
            raise ImportError(name)
        return real(name, *args, **kwargs)
    return mock.patch.object(builtins, "__import__", fake)


class TomlSubsetIntegrity(unittest.TestCase):
    """S05-010: the last-resort subset parser must not invent dependencies."""

    def deps(self, data):
        with without_toml_parsers():
            result = plugins._pyproject(data)
        self.assertEqual(result["state"], "PARSED")
        self.assertIn("partial", result["reason"])
        return result["facts"]["dependencies"]

    def test_multiline_strings_are_not_syntax(self):
        data = (b'[project]\nname = "x"\ndescription = """\n[project]\ndependencies = ["evil"]\n"""\n'
                b'dependencies = ["real"]\n')
        self.assertEqual(self.deps(data), ["real"])

    def test_literal_multiline_and_quoted_hash(self):
        data = b"[project]\nreadme = '''\ndependencies = ['nope']\n'''\ndependencies = [\"a # not a comment\", # c\n  'b']\n"
        self.assertEqual(self.deps(data), ["a", "b"])

    def test_other_tables_and_unterminated_input(self):
        self.assertEqual(self.deps(b'[tool.poetry]\ndependencies = ["no"]\n[project]\n'), [])
        self.assertEqual(self.deps(b'[project]\ndependencies = [\n"x"\n'), [])

    def test_maintained_parser_preferred(self):
        try:
            import tomli  # noqa: F401
        except ImportError:
            tomli = None
        result = plugins._pyproject(PYPROJECT)
        if plugins._toml_parser() is not None:
            self.assertEqual(result["state"], "SYMBOL_INDEXED")
            self.assertNotIn("reason", result)
