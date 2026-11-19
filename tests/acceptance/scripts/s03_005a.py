import json,os,subprocess,sys,tempfile,zipfile,glob
src=os.getcwd()
def cli(*a,env=None,cwd=None): return subprocess.run([sys.executable,"-m","osb_engine",*a],capture_output=True,text=True,timeout=600,env=env,cwd=cwd)
def ok(*a,**k):
    r=cli(*a,**k); assert r.returncode==0,(a,r.stderr[-600:]); return r.stdout
dist=tempfile.mkdtemp(); site=tempfile.mkdtemp()
r=subprocess.run([sys.executable,"-c","import sys;from setuptools import build_meta;print(build_meta.build_wheel(sys.argv[1]))",dist],capture_output=True,text=True,cwd=src)
assert r.returncode==0,r.stderr[-800:]
wheel=glob.glob(os.path.join(dist,"*.whl"))[0]
with zipfile.ZipFile(wheel) as z:
    names=z.namelist(); z.extractall(site)
    ep=[n for n in names if n.endswith("entry_points.txt")]
    assert ep and "osb = osb_engine.__main__:main" in z.read(ep[0]).decode(), names
assert any(n=="osb_engine/kernel.py" for n in names) and not any(n.startswith("test_") for n in names), names
env={**os.environ,"PYTHONPATH":site}
doc=json.loads(subprocess.run([sys.executable,"-c","import sys;from osb_engine.__main__ import main;sys.exit(main(['doctor']))"],capture_output=True,text=True,env=env,cwd=tempfile.mkdtemp()).stdout)
assert doc["classification"]=="linux-isolated" and all(doc["capabilities"].values()),doc
w=tempfile.mkdtemp(); t=os.path.join(w,"t"); os.makedirs(os.path.join(t,"pkg","sub")); p=os.path.join(w,"p"); os.mkdir(p,0o700); db=os.path.join(p,"s.sqlite")
g=lambda *a: subprocess.run(["git","-C",t,"-c","user.name=T","-c","user.email=t@i","-c","core.autocrlf=false",*a],check=True,capture_output=True)
open(os.path.join(t,"pkg","sub","m.py"),"wb").write(b"def f():\n    pass\n"); g("init"); g("add","."); g("commit","-m","s")
d=json.loads(ok("discover",os.path.join(t,"pkg","sub"))); assert os.path.realpath(d["root"])==os.path.realpath(t) and len(d["revision"])>=40 and d["project_identity"],d
cfg=os.path.join(p,"osb.json"); json.dump({"version":1,"analysis":{"cpu":3,"memory":128,"budget":120},"cache":{"max_entries":50,"max_bytes":1048576,"retention_days":7},"budget":{"max_blob":100000,"max_total":1000000}},open(cfg,"w"))
out=json.loads(ok("plan",t,db,"--config",cfg)); assert out["report"]["budget"]["max_blob"]==100000,out["report"]["budget"]
for bad in ({"version":2},{"version":1,"unknown":1},{"version":1,"analysis":{"cpu":"3"}},{"version":1,"analysis":{"cpu":100000}}):
    json.dump(bad,open(cfg,"w")); r=cli("plan",t,db,"--config",cfg); assert r.returncode==2 and "Command blocked" in r.stderr,(bad,r.stderr)
inside=os.path.join(t,"osb.json"); json.dump({"version":1},open(inside,"w")); r=cli("plan",t,db,"--config",inside); assert r.returncode==2,r.stderr
os.unlink(inside)
txt=ok("audit",t,db,"--format","text"); assert "revision" in txt.lower() and "coverage" in txt.lower() and "findings" in txt.lower(),txt
r=cli("--error-format","json","reserve",t,db,"nope","nope","60"); err=json.loads(r.stderr); assert r.returncode==2 and err["exit"]==2 and err["error"]=="blocked" and err["message"],r.stderr
print("PASS packaging, doctor, versioned config validation, discovery, text reports, structured errors")
