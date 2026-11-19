import json,os,subprocess,sys,tempfile
def cli(*a): return subprocess.run([sys.executable,"-m","osb_engine",*a],capture_output=True,text=True,timeout=600)
def ok(*a):
    r=cli(*a); assert r.returncode==0,(a,r.stderr[-600:]); return json.loads(r.stdout)
def repo(files):
    w=tempfile.mkdtemp(); t=os.path.join(w,"t"); os.mkdir(t); p=os.path.join(w,"p"); os.mkdir(p,0o700)
    g=lambda *a: subprocess.run(["git","-C",t,"-c","user.name=T","-c","user.email=t@i","-c","core.autocrlf=false",*a],check=True,capture_output=True)
    g("init")
    for k,v in files.items(): open(os.path.join(t,k),"wb").write(v)
    g("add","."); g("commit","-m","s"); return t,os.path.join(p,"s.sqlite")
t,db=repo({"ok.py":b"def a():\n    return 1\n","big.py":b"x = 1\n"*4000,"bomb.py":b"x = [" + b"1," * 900000 + b"]\n"})
out=ok("plan",t,db,"--max-blob","2000000","--analysis-cpu","2","--analysis-memory","96")
rep=out["report"]
assert out["report"]["coverage"]["complete"] is False,rep["coverage"]
c=rep["coverage"]["counts"]; assert c.get("analysis_failed")==1,c
out2=ok("plan",t,db.replace("s.sqlite","s2.sqlite"),"--max-blob","20000","--analysis-cpu","2","--analysis-memory","96")
rules={f["rule"] for f in out2["report"]["findings"]}
assert {"coverage.oversized"} <= rules, rules
tasks=ok("status",t,db.replace("s.sqlite","s2.sqlite"),out2["run_id"])["tasks"]
assert any(x["finding"]["rule"].startswith("coverage.") for x in tasks)
assert out2["report"]["release_ready"] is False and all(c["status"]!="pass" for c in out2["report"]["controls"])
t2,db2=repo({"ok.py":b"def a():\n    return 1\n"})
r2=ok("plan",t2,db2)["report"]
assert r2["coverage"]["complete"] is True and not any(f["rule"].startswith("coverage.") for f in r2["findings"]),r2["coverage"]
print("PASS incomplete coverage is counted, reported incomplete and turned into blocking plan tasks")
