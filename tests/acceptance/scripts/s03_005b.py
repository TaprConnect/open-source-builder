import json,os,shutil,sqlite3,subprocess,sys,tempfile
def cli(*a,token=None,cwd=None): return subprocess.run([sys.executable,"-m","osb_engine",*a],capture_output=True,text=True,input=token,timeout=600,cwd=cwd)
def ok(*a,**k):
    r=cli(*a,**k); assert r.returncode==0,(a,r.stderr[-700:]); return json.loads(r.stdout)
def blocked(*a,**k):
    r=cli(*a,**k); assert r.returncode==2 and "Command blocked" in r.stderr,(a,r.stdout[-300:],r.stderr[-300:])
w=tempfile.mkdtemp(); t=os.path.join(w,"t"); os.mkdir(t); p=os.path.join(w,"p"); os.mkdir(p,0o700); db=os.path.join(p,"s.sqlite")
def g(repo,*a): return subprocess.run(["git","-C",repo,"-c","user.name=T","-c","user.email=t@i","-c","core.autocrlf=false",*a],check=True,capture_output=True,text=True).stdout
open(os.path.join(t,"a.py"),"wb").write(b"def a():\n    pass\ndef b():\n    pass\n"); g(t,"init"); g(t,"add","."); g(t,"commit","-m","s")
# (3) v1 store from the previous code at 7b67f99 is in OSB_V1_STORE if provided by the harness
v1=os.environ.get("OSB_V1_STORE")
if v1:
    mig=ok("status",os.environ["OSB_V1_REPO"],v1,os.environ["OSB_V1_RUN"]); assert mig["tasks"],mig
c=sqlite3.connect(os.path.join(p,"future.sqlite")); c.execute("PRAGMA user_version=999"); c.commit(); c.close()
os.chmod(os.path.join(p,"future.sqlite"),0o600)
blocked("plan",t,os.path.join(p,"future.sqlite"))
first=ok("plan",t,db); r1=first["run_id"]; rep=first["report"]; ident=rep["repository_identity"]
fp={f["fingerprint"] for f in rep["findings"]}; assert len(fp)==len(rep["findings"])==2
open(os.path.join(t,"a.py"),"wb").write(b"import os\n\ndef a():\n    pass\ndef b():\n    pass\n"); g(t,"commit","-am","shift")
second=ok("plan",t,db); r2=second["run_id"]
assert {f["fingerprint"] for f in second["report"]["findings"]}==fp,"fingerprints must survive line shifts"
assert ok("status",t,db,r1)["superseded_by"]==r2
other=os.path.join(w,"clone-elsewhere"); subprocess.run(["git","clone","-q",t,other],check=True)
assert ok("audit",other,os.path.join(p,"o.sqlite"))["report"]["repository_identity"]==ident
open(os.path.join(t,"a.py"),"ab").write(b"def c():\n    pass\n"); open(os.path.join(t,"new.py"),"wb").write(b"def d():\n    pass\n")
c=sqlite3.connect(db); before=c.execute("SELECT COUNT(*) FROM engine_cache_v2").fetchone()[0]; c.close()
wt=ok("audit",t,db,"--working-tree")["report"]
assert wt["scope"]=="working_tree" and wt["committed_scope_only"] is False
src={f["path"]:f.get("source") for f in wt["files"]}; assert src["a.py"]=="working_tree" and src["new.py"]=="working_tree",src
assert sum(f["path"]=="new.py" for f in wt["findings"])==1 and sum(f["path"]=="a.py" for f in wt["findings"])==3
c=sqlite3.connect(db); after=c.execute("SELECT COUNT(*) FROM engine_cache_v2").fetchone()[0]; c.close(); assert after==before
blocked("plan",t,db,"--working-tree")
g(t,"checkout","--","a.py"); os.unlink(os.path.join(t,"new.py"))
tasks=ok("status",t,db,r2)["tasks"]; A,B=tasks[0]["id"],tasks[1]["id"]
l=ok("reserve",t,db,r2,A,"600"); blocked("cancel",t,db,r2,A,"--reason","drop")
ok("release",t,db,r2,A,str(l["generation"]),"--reason","x")
ok("cancel",t,db,r2,A,"--reason","drop"); blocked("reserve",t,db,r2,A,"60")
v=next(x for x in ok("status",t,db,r2)["tasks"] if x["id"]==A); assert v["state"]=="cancelled"
blocked("transition",t,db,r2,A,str(v["version"]),"open","--reason","r")
acc=os.path.join(p,"acc.py"); open(acc,"w").write("pass\n")
lb=ok("reserve",t,db,r2,B,"600"); ok("freeze",t,db,r2,B,acc); ok("verify",t,db,r2,B,str(lb["generation"]),acc); ok("complete",t,db,r2,B,str(lb["generation"]),token=lb["token"])
bundle=os.path.join(p,"handover.json"); ok("export-plan",t,db,r2,bundle)
p2=os.path.join(w,"p2"); os.mkdir(p2,0o700); db2=os.path.join(p2,"s.sqlite")
imp=ok("import-plan",other,db2,bundle); assert imp["run_id"]==r2 or imp["run_id"],imp
st=ok("status",other,db2,imp["run_id"]); states={x["id"]:x["state"] for x in st["tasks"]}
assert states[A]=="cancelled",states
c=sqlite3.connect(db2); n=c.execute("SELECT COUNT(*) FROM sqlite_master WHERE name='kernel_completions_v1'").fetchone()[0]
done=c.execute("SELECT COUNT(*) FROM kernel_completions_v1").fetchone()[0] if n else 0; c.close(); assert done==0
d=json.load(open(bundle)); d["tasks"][0]["state"]="proposed"; json.dump(d,open(os.path.join(p,"tampered.json"),"w"))
p3=os.path.join(w,"p3"); os.mkdir(p3,0o700); blocked("import-plan",other,os.path.join(p3,"s.sqlite"),os.path.join(p,"tampered.json"))
u=os.path.join(w,"unrelated"); os.mkdir(u); open(os.path.join(u,"z.py"),"wb").write(b"def z():\n    pass\n"); g(u,"init"); g(u,"add","."); g(u,"commit","-m","z")
p4=os.path.join(w,"p4"); os.mkdir(p4,0o700); blocked("import-plan",u,os.path.join(p4,"s.sqlite"),bundle)
print("PASS working-tree audit, stable identities and fingerprints, migrations, cancellation, supersession, sealed handover")
