import json,os,subprocess,tempfile
from pathlib import Path
def invoke(*args,token=None):
 return subprocess.run(["python3","-m","osb_engine",*args],text=True,input=token,capture_output=True,timeout=120)
def ok(*args,token=None):
 r=invoke(*args,token=token); assert r.returncode==0,(args,r.stderr); return json.loads(r.stdout)
work=Path(tempfile.mkdtemp())
pd=work/"private";pd.mkdir(mode=0o700); db=str(pd/"store.sqlite")
repo=work/"target";repo.mkdir()
outbox=work/"outbox";outbox.mkdir(mode=0o700)
inputs=work/"inputs";inputs.mkdir()
def git(*args): return subprocess.run(["git","-C",str(repo),"-c","user.name=T","-c","user.email=t@invalid",*args],check=True,capture_output=True,text=True).stdout
git("init"); (repo/"a.py").write_text("def a(): pass\n"); (repo/"b.py").write_text("def b(): pass\n"); git("add","."); git("commit","-m","seed")
base=[str(repo),db]; plan=ok("plan",*base)["run_id"]; a=ok("status",*base,plan)["tasks"][0]["id"]
lease=ok("reserve",*base,plan,a,"300"); g,t=str(lease["generation"]),lease["token"]
ok("grant",*base,plan,a,g,"--operation","edit","a.py")
config_before=(repo/".git/config").read_bytes(); store_before=Path(db).read_bytes()
worker=inputs/"worker.py"
worker.write_text(f"""
import json,os,socket
r={{}}
def attempt(name,fn):
    try:
        fn(); r[name]="succeeded"
    except Exception as e:
        r[name]=type(e).__name__
attempt("write_checkout",lambda: open("/work/a.py","a").write("x"))
attempt("create_checkout",lambda: open("/work/new.py","w").write("x"))
attempt("write_git",lambda: open("/work/.git/config","a").write("x"))
attempt("network",lambda: socket.create_connection(("1.1.1.1",53),timeout=2))
r["store_visible"]=os.path.exists({db!r}) or os.path.exists({str(pd)!r})
r["env"]=dict(os.environ)
open("/outbox/report.json","w").write(json.dumps(r))
open("/outbox/01-ok.patch","w").write("--- a/a.py\\n+++ b/a.py\\n@@ -1 +1 @@\\n-def a(): pass\\n+def a(): return 1\\n")
open("/outbox/02-bad.patch","w").write("--- a/b.py\\n+++ b/b.py\\n@@ -1 +1 @@\\n-def b(): pass\\n+def b(): return 2\\n")
""")
res=ok("run-worker",*base,plan,a,g,str(outbox),"--input",f"worker.py={worker}","--","python3","-I","/inputs/worker.py",token=t)
assert res["returncode"]==0,res
rep=json.loads((outbox/"report.json").read_text())
for k in ("write_checkout","create_checkout","write_git","network"):
 assert rep[k]!="succeeded",(k,rep)
assert rep["store_visible"] is False
assert t not in json.dumps(rep["env"]) and not any(t in f.read_text(errors="ignore") for f in outbox.iterdir())
assert (repo/".git/config").read_bytes()==config_before and not (repo/"new.py").exists()
results={r["patch"]:r for r in res["patches"]}
assert results["01-ok.patch"]["applied"] is True and results["02-bad.patch"]["applied"] is False,results
assert (repo/"a.py").read_text()=="def a(): return 1\n" and (repo/"b.py").read_text()=="def b(): pass\n"
d=ok("dispatch",*base,plan,a,g,"edit","a.py",token=t); assert d["authorised"] is True
print("PASS isolated worker: read-only checkout and .git, no store, no token, no network; kernel-applied outbox patches")
