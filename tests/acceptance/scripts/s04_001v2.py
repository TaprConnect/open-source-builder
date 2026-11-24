import json,os,shutil,subprocess,sys,sysconfig,tempfile,time
def cli(*a): return subprocess.run([sys.executable,"-m","osb_engine",*a],capture_output=True,text=True,timeout=3600)
def ok(*a):
    r=cli(*a); assert r.returncode==0,(a[:2],r.stderr[-800:]); return json.loads(r.stdout)
w=tempfile.mkdtemp(); t=os.path.join(w,"t"); p=os.path.join(w,"p"); os.mkdir(p,0o700)
files={
 "app/__init__.py":"",
 "app/__main__.py":"from app.cli import run\nrun()\n",
 "app/cli.py":"import json\nimport requests\nfrom .core import compute\n\ndef run():\n    print(compute(2))\n",
 "app/core.py":"from . import helpers\n\ndef compute(x):\n    return helpers.double(x)\n\ndef unused_feature():\n    return 1\n\nclass LegacyThing:\n    pass\n",
 "app/helpers.py":"from app import core\n\ndef double(x):\n    return x * 2\n\ndef _private():\n    return core\n",
 "app/api.py":"__all__ = ['exported']\n\ndef exported():\n    return 1\n",
 "tools/build.py":"if __name__ == '__main__':\n    print('build')\n",
 "config/settings.json":"{\"debug\": true,",
 "config/app.toml":"[server]\nport = 8080\n",
 "db/schema.sql":"CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT NOT NULL);\nCREATE TABLE orders (id INTEGER PRIMARY KEY, user_id INTEGER REFERENCES users(id), total REAL);\n",
 "web/main.ts":"export function hello(): string { return 'hi'; }\n",
}
for k,v in files.items():
    os.makedirs(os.path.dirname(os.path.join(t,k)),exist_ok=True); open(os.path.join(t,k),"w").write(v)
g=lambda *a: subprocess.run(["git","-C",t,"-c","user.name=T","-c","user.email=t@i","-c","core.autocrlf=false",*a],check=True,capture_output=True)
g("init"); g("add","."); g("commit","-m","s")
idx=ok("index",t,os.path.join(p,"s.sqlite"))
files_by={f["path"]:f for f in idx["files"]}
truth_edges={("app/__main__.py","app/cli.py"),("app/cli.py","app/core.py"),("app/core.py","app/helpers.py"),("app/helpers.py","app/core.py")}
got_edges={tuple(e) for e in idx["graph"]["edges"]}
truth_cycles=[sorted(["app/core.py","app/helpers.py"])]
truth_entry={"app/__main__.py","tools/build.py"}
truth_dead={("app/core.py","unused_feature"),("app/core.py","LegacyThing")}
got_dead={(d["path"],d["symbol"]) for d in idx["dead_code_candidates"]}
def pr(truth,got):
    tp=len(truth&got); return {"precision":tp/len(got) if got else 1.0,"recall":tp/len(truth) if truth else 1.0}
scores={"edges":pr(truth_edges,got_edges),"dead":pr(truth_dead,got_dead),"entry":pr(truth_entry,set(idx["entry_points"]))}
assert all(s["precision"]==1.0 and s["recall"]==1.0 for s in scores.values()),(scores,got_edges,got_dead,idx["entry_points"])
assert sorted(sorted(c) for c in idx["graph"]["cycles"])==truth_cycles,idx["graph"]["cycles"]
assert "requests" in idx["graph"]["external"] and "json" in idx["graph"]["external"]
sql=files_by["db/schema.sql"]; assert sql["state"]=="SYMBOL_INDEXED" and {s["name"] for s in sql["facts"]["tables"]}=={"users","orders"}
assert {c for s in sql["facts"]["tables"] if s["name"]=="orders" for c in s["columns"]}=={"id","user_id","total"}
assert files_by["config/settings.json"]["state"]=="INDEXED" and files_by["config/settings.json"]["error"]
assert files_by["config/app.toml"]["state"] in ("PARSED","SYMBOL_INDEXED")
assert files_by["web/main.ts"]["state"] in ("SYMBOL_INDEXED","DEPENDENCIES_RESOLVED","PARSED") and "facts" in files_by["web/main.ts"]  # S05-009: TS is parsed
assert files_by["app/core.py"]["state"]=="DEPENDENCIES_RESOLVED"
assert not any(f["state"] in ("SEMANTICALLY_REVIEWED","RUNTIME_VERIFIED") for f in idx["files"])
big=os.path.join(w,"stdlib"); shutil.copytree(sysconfig.get_paths()["stdlib"],big,ignore=shutil.ignore_patterns("__pycache__","site-packages","dist-packages","test","tests","idlelib","lib2to3"))
gb=lambda *a: subprocess.run(["git","-C",big,"-c","user.name=T","-c","user.email=t@i",*a],check=True,capture_output=True)
gb("init"); gb("add","-A"); gb("commit","-qm","s")
t0=time.time(); s=ok("index",big,os.path.join(p,"big.sqlite")); dt=round(time.time()-t0,1)
print("MEASURE "+json.dumps({"fixture_scores":scores,"stdlib_files":len(s["files"]),"stdlib_seconds":dt,"stdlib_states":s["summary"]["states"],"stdlib_resolution_rate":s["summary"]["resolution_rate"],"stdlib_cycles":len(s["graph"]["cycles"])}))
print("PASS repository intelligence index: exact ground truth, honest states, stdlib scale")
