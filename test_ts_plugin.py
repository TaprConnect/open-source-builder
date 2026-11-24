"""S05-009: TypeScript/JavaScript intelligence from a real parser, in the shared fact schema."""
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from osb_engine import plugins, ts_plugin
from osb_engine.intelligence import build_index, valid_facts
from osb_engine.repository import Repository

SERVER = b'''import express from "express";
import { requireAuth } from "./auth";
import { db } from "./db";
const app = express();
const notes: string[] = [];
app.get("/api/notes/:id", requireAuth, async (req, res) => { res.json(await db.query("SELECT 1 WHERE id=$1", [req.params.id])); });
app.post("/api/notes", (req, res) => { notes.push(req.body.text); res.json({ok: true}); });
app.delete("/api/notes/:id", requireAuth, async (req, res) => { await db.query(`DELETE FROM n WHERE id=${req.params.id}`); res.end(); });
app.put("/api/run", (req, res) => { require("child_process").exec(req.body.cmd); res.end(); });
export function exportNotes(): string { throw new Error("Not implemented"); }
export function later() {}
const port = process.env.PORT ?? 3000; const key = process.env.API_KEY;
try { app.listen(port); } catch (e) {}
'''
APP = b'export function App() { const s = () => fetch("/api/notes", {method: "POST"}); ' \
      b'const l = (id: string) => fetch(`/api/notes/${id}`); const x = () => fetch("/api/missing"); return <b onClick={s}>x</b>; }\n'


def repo_with(files):
    root = Path(tempfile.mkdtemp())
    for name, data in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_bytes(data)
    git = ["git", "-C", str(root), "-c", "user.name=t", "-c", "user.email=t@t"]
    subprocess.run(git + ["init", "-q"], check=True)
    subprocess.run(git + ["add", "."], check=True)
    subprocess.run(git + ["commit", "-qm", "x"], check=True)
    return Repository(root)


class TypeScriptFacts(unittest.TestCase):
    def facts(self, path, data):
        result = plugins.extract("typescript", data, path)
        self.assertTrue(valid_facts(result), result)
        return result

    def test_parser_is_installed_for_this_suite(self):
        self.assertTrue(ts_plugin.available(), "install open-source-builder[typescript] (tree-sitter)")

    def test_express_routes_middleware_and_issues(self):
        result = self.facts("src/server.ts", SERVER)
        self.assertEqual(result["state"], "SYMBOL_INDEXED")
        facts = result["facts"]
        routes = {(r["methods"][0], r["path"]) for r in facts["routes"]}
        self.assertEqual(routes, {("GET", "/api/notes/:id"), ("POST", "/api/notes"),
                                  ("DELETE", "/api/notes/:id"), ("PUT", "/api/run")})
        guarded = [f for n, f in facts["functions"].items() if n.startswith("<handler GET")][0]
        self.assertIn("requireAuth", guarded["decorators"])
        post = [f for n, f in facts["functions"].items() if n.startswith("<handler POST")][0]
        self.assertEqual(post["mutates"], ["notes"])
        self.assertEqual(sorted(t["kind"] for t in facts["taint"]), ["command_injection", "sql_injection"])
        kinds = {(i["kind"], i["function"]) for i in facts["issues"]}
        self.assertEqual(kinds, {("not_implemented", "exportNotes"), ("placeholder", "later"),
                                 ("swallowed_exception", "<module>")})
        self.assertEqual(facts["env"], ["API_KEY", "PORT"])
        self.assertEqual([r["name"] for r in facts["env_required"]], ["API_KEY"])
        self.assertEqual({i["module"] for i in facts["imports"]}, {"express", "./auth", "./db", "child_process"})

    def test_next_routers_and_fetches(self):
        app = self.facts("app/api/items/[id]/route.ts", b"export async function GET() {}\nexport const POST = async () => {};\n")
        self.assertEqual({(r["methods"][0], r["path"]) for r in app["facts"]["routes"]},
                         {("GET", "/api/items/[id]"), ("POST", "/api/items/[id]")})
        pages = self.facts("pages/api/users.ts", b"export default function handler(req, res) { res.end(); }\n")
        self.assertEqual(pages["facts"]["routes"][0]["path"], "/api/users")
        fetches = self.facts("src/App.tsx", APP)["facts"]["fetches"]
        self.assertEqual([(f["method"], f["path"]) for f in fetches],
                         [("POST", "/api/notes"), ("GET", "/api/notes/:param"), ("GET", "/api/missing")])

    def test_syntax_errors_are_partial_not_complete(self):
        result = self.facts("bad.ts", b"function ( {{{ export const = ;\n")
        self.assertEqual(result["state"], "PARSED")
        self.assertIn("partial", result["reason"])

    def test_bounded_traversal(self):
        deep = b"const x = " + b"[" * 20000 + b"]" * 20000 + b";\n"
        result = self.facts("deep.ts", deep)
        self.assertIn(result["state"], ("INDEXED", "PARSED", "SYMBOL_INDEXED"))
        with mock.patch.object(ts_plugin, "NODE_BUDGET", 50):
            bounded = plugins.extract("typescript", SERVER, "s.ts")
        self.assertEqual(bounded["state"], "INDEXED")
        self.assertIn("bounded", bounded["error"])

    def test_missing_parser_is_unsupported(self):
        with mock.patch.object(ts_plugin, "available", lambda: False):
            result = plugins.extract("javascript", b"const a = 1;", "a.js")
        self.assertEqual(result["state"], "INDEXED")
        self.assertTrue(result["reason"].startswith("unsupported"))

    def test_undecodable_source(self):
        self.assertEqual(plugins.extract("typescript", b"\xff\xfe", "a.ts")["state"], "INDEXED")

    def test_cross_file_index(self):
        repo = repo_with({"package.json": b'{"dependencies": {"express": "4"}}',
                          "src/server.ts": SERVER, "src/auth.ts": b"export const requireAuth = (q,s,n) => n();\n",
                          "src/db.ts": b'import { Pool } from "pg"; export const db = new Pool();\n',
                          "src/web/App.tsx": APP})
        index = build_index(repo)
        routes = {(c["methods"][0], c["path"]): c for c in index["completeness"]}
        self.assertEqual(routes[("POST", "/api/notes")]["auth"], "not_detected")
        self.assertIn("in_memory_persistence", routes[("POST", "/api/notes")]["flags"])
        self.assertEqual(routes[("GET", "/api/notes/:id")]["auth"], "detected")
        self.assertEqual({(l["method"], l["route"]) for l in index["frontend_links"]},
                         {("POST", "/api/notes"), ("GET", "/api/notes/:id")})
        self.assertEqual([u["path"] for u in index["unmatched_fetches"]], ["/api/missing"])
        self.assertEqual([m["module"] for m in index["missing_dependencies"]], ["pg"])
        self.assertIn(["src/server.ts", "src/auth.ts"], index["graph"]["edges"])
        self.assertTrue(index["completeness_summary"]["frontend_analysis"].startswith("static"))


class PostHoldoutPatterns(unittest.TestCase):
    """Patterns added after the first blind holdout (evidence/s05/report.json); not holdout evidence."""
    SRC = (b'const cp = require("child_process"); const { exec } = require("child_process");\n'
           b'const API_TOKEN = "sk_live_51Habcdefghijk";\n'
           b'app.get("/a", (req, res) => { Todo.find({}).exec(function (err) { res.send(req.query.x); });\n'
           b'  cp.exec("ls " + req.query.d); exec(req.body.c);\n'
           b'  User.findOne({ username: req.body.username, password: req.body.password });\n'
           b'  res.redirect(req.query.url); needle.get(req.query.u); db.query(`SELECT ${req.query.id}`); });\n')

    def test_sinks_and_credentials(self):
        facts = plugins.extract("javascript", self.SRC, "a.js")["facts"]
        self.assertEqual(sorted((t["kind"], t["line"]) for t in facts["taint"]),
                         [("command_injection", 4), ("command_injection", 4), ("nosql_injection", 5),
                          ("open_redirect", 6), ("sql_injection", 6), ("ssrf", 6)])
        self.assertEqual([c["name"] for c in facts["credentials"]], ["API_TOKEN"])

    def test_query_builder_exec_is_not_a_shell(self):
        facts = plugins.extract("javascript", b'app.get("/b", (req, res) => { Todo.find({}).exec(function () { res.send(req.query.q); }); });\n', "b.js")["facts"]
        self.assertEqual(facts["taint"], [])


class PrecisionRound2(unittest.TestCase):
    """Fixes measured on holdout 2 (appsecco/dvna); not holdout evidence."""

    def test_member_alias_of_child_process(self):
        facts = plugins.extract("javascript", b"var exec = require('child_process').exec;\n"
                                b"module.exports.ping = function (req, res) { exec('ping ' + req.body.address); };\n", "h.js")["facts"]
        self.assertEqual([t["kind"] for t in facts["taint"]], ["command_injection"])

    def test_nosql_only_with_a_mongo_driver(self):
        handler = b"exports.find = function (req, res) { db.User.find({ where: { login: req.body.login } }); };\n"
        sql = build_index(repo_with({"package.json": b'{"dependencies": {"sequelize": "6"}}', "h.js": handler}))
        self.assertEqual(sql["taint"], [])
        mongo = build_index(repo_with({"package.json": b'{"dependencies": {"mongoose": "6"}}', "h.js": handler}))
        self.assertEqual([t["kind"] for t in mongo["taint"]], ["nosql_injection"])


class DataFlowRound3(unittest.TestCase):
    """Fixes measured on holdout 3 (cr0hn/vulnerable-node); not holdout evidence."""

    def kinds(self, src):
        return sorted(t["kind"] for t in plugins.extract("javascript", src, "r.js")["facts"]["taint"])

    def test_request_data_through_local_variables(self):
        self.assertEqual(self.kinds(
            b'const { exec } = require("child_process");\n'
            b'router.post("/ping", (req, res) => { const host = req.body.host || "x"; const cmd = `ping ${host}`; exec(cmd); });\n'
            b'router.get("/dl", (req, res) => { const name = req.query.file; fs.readFile(path.join(DIR, name), cb); });\n'),
            ["command_injection", "path_traversal"])

    def test_redirects_to_fixed_local_paths_are_not_open(self):
        self.assertEqual(self.kinds(b'app.get("/a", (req, res) => { res.redirect("/login?next=" + encodeURIComponent(req.originalUrl)); });\n'
                                    b'app.get("/b", (req, res) => { res.redirect(`/products/${req.params.id}`); });\n'), [])
        self.assertEqual(self.kinds(b'app.get("/c", (req, res) => { const u = req.query.url; res.redirect(u); });\n'), ["open_redirect"])
