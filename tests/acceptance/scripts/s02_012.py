import concurrent.futures,json,os,subprocess,tempfile
from pathlib import Path
def invoke(*a,token=None): return subprocess.run(["python3","-m","osb_engine",*a],text=True,input=token,capture_output=True,timeout=300)
def ok(*a,token=None):
    r=invoke(*a,token=token); assert r.returncode==0,(a,r.stderr); return json.loads(r.stdout)
def blocked(*a,token=None):
    r=invoke(*a,token=token); assert r.returncode==2 and "Command blocked" in r.stderr,(a,r.stdout,r.stderr)
w=Path(tempfile.mkdtemp()); pd=w/"p"; pd.mkdir(mode=0o700); db=str(pd/"s.sqlite")
t=w/"t"; t.mkdir()
g=lambda *a: subprocess.run(["git","-C",str(t),"-c","user.name=T","-c","user.email=t@invalid",*a],check=True,capture_output=True)
g("init"); (t/"a.py").write_text("def a(): pass\ndef b(): pass\n"); g("add","."); g("commit","-m","s")
base=[str(t),db]; plan=ok("plan",*base)["run_id"]; task=ok("status",*base,plan)["tasks"][0]["id"]
l=ok("reserve",*base,plan,task,"900"); gen,tok=str(l["generation"]),l["token"]
for bad in ("-1","100001","x"): r=invoke("quota",*base,plan,task,"--kind","mutate","--limit",bad); assert r.returncode==2,bad
blocked("quota",*base,plan,task,"--kind","delete","--limit","1") if invoke("quota",*base,plan,task,"--kind","delete","--limit","1").returncode==2 else None
ok("grant",*base,plan,task,gen,"--operation","edit","n0.py","n1.py","n2.py","n3.py","n4.py","n5.py","a.py")
ok("quota",*base,plan,task,"--kind","mutate","--limit","3")
bad=pd/"bad.patch"; bad.write_text("--- a/a.py\n+++ b/a.py\n@@ -1,2 +1,2 @@\n-def zzz(): pass\n+def a(): return 1\n def b(): pass\n")
blocked("mutate",*base,plan,task,gen,str(bad),token=tok)
patches=[]
for i in range(6):
    f=pd/f"n{i}.patch"; f.write_text(f"--- /dev/null\n+++ b/n{i}.py\n@@ -0,0 +1 @@\n+n = {i}\n"); patches.append(str(f))
with concurrent.futures.ThreadPoolExecutor(6) as pool:
    res=list(pool.map(lambda f: invoke("mutate",*base,plan,task,gen,f,token=tok),patches))
codes=sorted(r.returncode for r in res); assert codes==[0,0,0,2,2,2],(codes,[r.stderr for r in res])
assert len(list(t.glob("n*.py")))==3
acc=pd/"acc.py"; acc.write_text("pass\n"); ok("freeze",*base,plan,task,str(acc)); ok("quota",*base,plan,task,"--kind","verify","--limit","1")
ok("verify",*base,plan,task,gen,str(acc)); blocked("verify",*base,plan,task,gen,str(acc))
ok("quota",*base,plan,task,"--kind","worker","--limit","1")
idir=w/"inputs"; idir.mkdir(); inp=idir/"w.py"; inp.write_text("import time\ntime.sleep(2)\n")
outs=[]
for i in range(3):
    o=w/f"out{i}"; o.mkdir(mode=0o700); outs.append(o)
with concurrent.futures.ThreadPoolExecutor(3) as pool:
    res=list(pool.map(lambda o: invoke("run-worker",*base,plan,task,gen,str(o),"--input",f"w.py={inp}","--","python3","-I","/inputs/w.py",token=tok),outs))
codes=sorted(r.returncode for r in res); assert codes==[0,2,2],(codes,[r.stderr for r in res])
print("PASS quotas: concurrent mutate, verify and worker runs cannot oversubscribe; failed actions consume nothing")
