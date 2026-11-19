import json,os,subprocess,sys,tempfile,time
sys.path.insert(0,os.getcwd())
from pathlib import Path
def cli(*a,env=None): return subprocess.run([sys.executable,"-m","osb_engine",*a],capture_output=True,text=True,timeout=600,env=env)
def ok(*a,env=None):
    r=cli(*a,env=env); assert r.returncode==0,(a,r.stderr[-600:]); return json.loads(r.stdout)
def repo(files):
    w=Path(tempfile.mkdtemp()); t=w/"t"; t.mkdir(); p=w/"p"; p.mkdir(mode=0o700)
    g=lambda *a: subprocess.run(["git","-C",str(t),"-c","user.name=T","-c","user.email=t@invalid","-c","core.autocrlf=false",*a],check=True,capture_output=True)
    g("init")
    for k,v in files.items(): (t/k).parent.mkdir(parents=True,exist_ok=True); (t/k).write_bytes(v)
    g("add","."); g("commit","-m","s"); return t,str(p/"s.sqlite")
bomb=b"x = [" + b"1," * 900000 + b"]\n"
t,db=repo({"ok.py":b"def a(): pass\n","bomb.py":bomb})
start=time.time()
out=ok("plan",str(t),db,"--analysis-cpu","2","--analysis-memory","96")
files={f["path"]:f for f in out["report"]["files"]}
assert files["bomb.py"]["status"]=="analysis_failed",files["bomb.py"]["status"]
assert files["ok.py"]["status"]!="analysis_failed" and "analysis" in files["ok.py"],files["ok.py"]
assert out["run_id"] and time.time()-start<300
t2,db2=repo({"pkg/__init__.py":b"","pkg/m.py":b"import pkg\ndef f():\n    try:\n        pass\n    except Exception:\n        pass\n","package.json":b'{"name":"x","scripts":{}}'})
iso=ok("audit",str(t2),db2)["report"]
from osb_engine.audit import scan
from osb_engine.controls import catalogue
from osb_engine.repository import Repository
from osb_engine.store import Store
p3=Path(tempfile.mkdtemp())/"p"; p3.mkdir(mode=0o700)
with Store(Repository(t2),p3/"s.sqlite") as st:
    ref,_=scan(st.repo,st,catalogue(str(Path("profiles")/"checks.tsv")))
for k in ("files","findings","dependencies"):
    assert iso[k]==ref[k],k
print("PASS isolated resource-limited analysis: hostile file isolated to analysis_failed, benign results identical to in-process")
