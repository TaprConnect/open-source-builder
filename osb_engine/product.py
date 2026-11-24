"""Product understanding (S06-001) and the persistent product completeness graph (S06-002).

Confirmed facts come only from the owner's requirements file, which lives outside the target
repository. Everything read from repository content is evidence for *inferred* facts, and
anything neither the owner nor the code settles is listed as an unresolved product decision.

Graph: requirement -> journey -> UI -> API route -> function (service) -> store (persistence)
-> external system, plus test and evidence nodes. Each revision's graph is persisted in the
kernel's private SQLite store, and diff() reports what changed between revisions.
"""
import hashlib
import json

from . import plugins
from .kernel import _project
from .runtime import discover

_SCHEMA = """
CREATE TABLE IF NOT EXISTS product_nodes_v1 (project TEXT NOT NULL, revision TEXT NOT NULL, node TEXT NOT NULL,
    kind TEXT NOT NULL, status TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY (project, revision, node));
CREATE TABLE IF NOT EXISTS product_edges_v1 (project TEXT NOT NULL, revision TEXT NOT NULL, src TEXT NOT NULL,
    dst TEXT NOT NULL, kind TEXT NOT NULL, PRIMARY KEY (project, revision, src, dst, kind));
"""


def load_requirements(path):
    with open(path, "rb") as handle:
        spec = json.loads(handle.read())
    if not isinstance(spec, dict) or not isinstance(spec.get("requirements"), list):
        raise ValueError("requirements file must be an object with a requirements list")
    ids = [r.get("id") for r in spec["requirements"]]
    if len(set(ids)) != len(ids) or not all(isinstance(i, str) and i for i in ids):
        raise ValueError("requirement ids must be unique non-empty strings")
    return spec


def python_facts(repo, index, extractor=None):
    """Per-file Python function facts (the index keeps only counts for Python files)."""
    paths = [f["path"] for f in index["files"] if f["language"] == "python" and f["state"] != "INDEXED"]
    blobs = {b.path: b for b in repo.inventory()}
    items = [(p, "python", repo.read(blobs[p])) for p in paths if p in blobs]
    run = extractor or (lambda xs: {k: plugins.extract(kind, data, k) for k, kind, data in xs})
    return {k: (v or {}).get("facts", {}) for k, v in run(items).items()}


def understand(repo, index, spec=None, facts=None):
    spec = spec or {"requirements": []}
    facts = facts if facts is not None else python_facts(repo, index)
    functions = {(p, name): info for p, f in facts.items() for name, info in f.get("functions", {}).items()}
    issues = index.get("issues", [])
    stubs = {(i["path"], i["function"]): i["kind"] for i in issues if i["kind"] in ("placeholder", "not_implemented")}
    stores = sorted({(p, m) for (p, _), info in functions.items() for m in info["mutates"]})
    confirmed = {"product": spec.get("product"), "roles": spec.get("roles", []),
                 "requirements": [{k: r[k] for k in ("id", "text") if k in r} for r in spec["requirements"]]}
    inferred = {
        "existing_functions": sorted(f"{p}::{n}" for (p, n) in functions if (p, n) not in stubs),
        "partial_functions": sorted(f"{p}::{n}" for (p, n), k in stubs.items() if k == "placeholder"),
        "missing_functions": sorted(f"{p}::{n}" for (p, n), k in stubs.items() if k == "not_implemented"),
        "broken_files": sorted(f["path"] for f in index["files"] if f["state"] == "INDEXED" and f.get("error")),
        "broken_ui_links": [f"{u['file']}:{u['line']} {u['method']} {u['path']}" for u in index.get("unmatched_fetches", [])],
        "routes": [f"{'/'.join(c['methods'])} {c['path']}" for c in index.get("completeness", [])],
        "authentication": {c["path"]: c["auth"] for c in index.get("completeness", [])},
        "in_memory_stores": [f"{p}::{m}" for p, m in stores],
        "persistence_tables": sorted({t["name"] for f in index["files"] for t in (f.get("facts") or {}).get("tables", [])
                                      if isinstance(t, dict)}),
        "external_systems": sorted(m for m, k in index["graph"].get("external_classified", {}).items() if k != "stdlib"),
        "environment": sorted(index.get("environment", {})),
        "build_and_test_commands": {a: [" ".join(c["argv"]) for c in cs] for a, cs in discover(repo, index)["commands"].items()},
        "security_boundaries": sorted({f"{p}::{n}" for (p, n), info in functions.items()
                                       if any(u in n for u in ("delete", "update", "get", "create"))}),
    }
    unresolved = []
    for r in spec["requirements"]:
        wanted = r.get("functions", [])
        found = [w for w in wanted if any(n == w for (_, n) in functions)]
        if wanted and not found:
            unresolved.append({"requirement": r["id"], "decision": f"where should {', '.join(wanted)} be implemented?"})
    if not spec["requirements"]:
        unresolved.append({"decision": "no owner requirements supplied: product intent is inferred only"})
    return {"revision": index["revision"], "confirmed": confirmed, "inferred": inferred, "unresolved": unresolved,
            "basis": {"confirmed": "owner requirements file (outside the repository)",
                      "inferred": "static repository evidence; repository text is untrusted"}}


def _node_id(kind, key):
    return f"{kind}:{key}"


def build_graph(index, spec, facts, evidence=None):
    """Return (nodes {id: {kind, status, data}}, edges {(src, dst, kind)})."""
    evidence = evidence or {}
    nodes, edges = {}, set()

    def node(kind, key, status="present", **data):
        nid = _node_id(kind, key)
        nodes.setdefault(nid, {"kind": kind, "status": status, "data": data})
        return nid
    stubs = {(i["path"], i["function"]): i["kind"] for i in index.get("issues", [])}
    functions = {}
    for path, f in facts.items():
        for name, info in f.get("functions", {}).items():
            status = "missing" if stubs.get((path, name)) == "not_implemented" else \
                "partial" if stubs.get((path, name)) == "placeholder" else "present"
            fid = node("function", f"{path}::{name}", status)
            functions.setdefault(name, []).append(fid)
            for store in info["mutates"]:
                edges.add((fid, node("store", f"{path}::{store}", "in_memory"), "writes"))
    for c in index.get("completeness", []):
        rid = node("route", f"{'/'.join(c['methods'])} {c['path']}", "broken" if "unimplemented" in c["flags"] else "present",
                   auth=c["auth"], flags=c["flags"])
        for fid in functions.get(c["handler"], []):
            edges.add((rid, fid, "handled_by"))
    for link in index.get("frontend_links", []):
        uid = node("ui", link["file"])
        edges.add((uid, _node_id("route", next((f"{'/'.join(c['methods'])} {c['path']}" for c in index.get("completeness", [])
                                               if c["path"] == link["route"]), link["route"])), "calls"))
    for u in index.get("unmatched_fetches", []):
        uid = node("ui", u["file"])
        edges.add((uid, node("route", f"{u['method']} {u['path']}", "missing"), "calls"))
    for module in index["graph"].get("external", []):
        node("external", module)
    for source, tests in index.get("tests", {}).items():
        for t in tests:
            tid = node("test", t)
            for fid in [n for n in nodes if n.startswith(f"function:{source}::")]:
                edges.add((tid, fid, "exercises"))
    for r in spec.get("requirements", []):
        verified = evidence.get(r["id"])
        rid = node("requirement", r["id"], "verified" if verified else "unverified", text=r.get("text", ""))
        if r.get("journey"):
            edges.add((rid, node("journey", r["journey"]), "part_of"))
        targets = [fid for name in r.get("functions", []) for fid in functions.get(name, [])]
        if not targets:
            nodes[rid]["status"] = "missing"
        for fid in targets:
            edges.add((rid, fid, "implemented_by"))
            if nodes[fid]["status"] in ("missing", "partial") and nodes[rid]["status"] != "verified":
                nodes[rid]["status"] = "broken"
        if verified:
            edges.add((rid, node("evidence", f"verification:{verified}", "verified"), "verified_by"))
    tested = {d for s, d, k in edges if k == "exercises"}
    for nid, n in nodes.items():
        if n["kind"] == "function" and n["status"] == "present" and nid not in tested:
            n["status"] = "unverified"
    consumers = {d for s, d, k in edges if k in ("calls", "implemented_by")}
    for nid, n in nodes.items():
        if n["kind"] == "route" and nid not in consumers and n["status"] == "present":
            n["status"] = "disconnected"
    return nodes, edges


def persist(store, revision, nodes, edges):
    conn, project = store.conn, _project(store)
    conn.executescript(_SCHEMA)
    with conn:
        conn.execute("DELETE FROM product_nodes_v1 WHERE project=? AND revision=?", (project, revision))
        conn.execute("DELETE FROM product_edges_v1 WHERE project=? AND revision=?", (project, revision))
        conn.executemany("INSERT INTO product_nodes_v1 VALUES (?,?,?,?,?,?)",
                         [(project, revision, nid, n["kind"], n["status"], json.dumps(n["data"], sort_keys=True))
                          for nid, n in sorted(nodes.items())])
        conn.executemany("INSERT INTO product_edges_v1 VALUES (?,?,?,?,?)",
                         [(project, revision, s, d, k) for s, d, k in sorted(edges)])
    return {"revision": revision, "nodes": len(nodes), "edges": len(edges),
            "digest": hashlib.sha256(json.dumps([sorted(nodes.items()), sorted(edges)], sort_keys=True,
                                                default=str).encode()).hexdigest()}


def load(store, revision):
    conn, project = store.conn, _project(store)
    conn.executescript(_SCHEMA)
    nodes = {nid: {"kind": k, "status": s, "data": json.loads(d)} for nid, k, s, d in conn.execute(
        "SELECT node, kind, status, data FROM product_nodes_v1 WHERE project=? AND revision=?", (project, revision))}
    edges = {(s, d, k) for s, d, k in conn.execute(
        "SELECT src, dst, kind FROM product_edges_v1 WHERE project=? AND revision=?", (project, revision))}
    return nodes, edges


def diff(old, new):
    """Incremental view between two graphs: added, removed and status-changed nodes and edges."""
    (on, oe), (nn, ne) = old, new
    return {"added_nodes": sorted(set(nn) - set(on)), "removed_nodes": sorted(set(on) - set(nn)),
            "changed_status": sorted(n for n in set(on) & set(nn) if on[n]["status"] != nn[n]["status"]),
            "added_edges": sorted(ne - oe), "removed_edges": sorted(oe - ne)}


def gaps(nodes, edges):
    return {status: sorted(n for n, v in nodes.items() if v["status"] == status)
            for status in ("missing", "broken", "partial", "unverified", "disconnected", "in_memory")}
