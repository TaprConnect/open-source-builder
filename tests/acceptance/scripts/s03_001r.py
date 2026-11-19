import json,os,subprocess,sys,tempfile,time
sys.path.insert(0,os.getcwd())
from unittest.mock import patch
from osb_engine import isolation,sandboxed,analysis
if isolation.available():
    probe=r"""
import resource,sys,tempfile
sys.path.insert(0,%r)
from osb_engine.isolation import run_isolated
flood=["python3","-c","import sys\nwhile 1: sys.stdout.write('x'*1000000)"]
t=time.time() if False else None
import time
for cap in (1024,None):
    s=time.time(); code,out,err=run_isolated(tempfile.mkdtemp(),flood,{},60,max_output=cap); d=time.time()-s
    assert code==-2 and d<20,(cap,code,d)
rss=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
assert rss<200*1024,rss
print("flood-ok",rss)
""" % os.getcwd()
    r=subprocess.run([sys.executable,"-c",probe],capture_output=True,text=True,timeout=120); assert r.returncode==0,(r.stdout,r.stderr[-800:])
good=["analysed",{"symbols":[],"imports":[],"calls":[],"findings":[{"rule":"r","line":1,"state":"candidate","explanation":"e"}],"facts":{}}]
assert sandboxed._valid(good)
for bad in (["analysed",{"symbols":[],"imports":[],"calls":[],"findings":[1],"facts":{}}],["bogus",good[1]],["analysed",{**good[1],"extra":1}],["analysed",{**good[1],"findings":[{"rule":"r","line":"1","state":"candidate","explanation":"e"}]}]):
    assert not sandboxed._valid(bad),bad
def slow(root,argv,inputs,timeout,env=None,stdin_data=b"",limits=None,max_output=None):
    time.sleep(1); items=json.loads(stdin_data)["items"]
    return 0,json.dumps({"version":analysis.VERSION,"results":{k:good for k,_,_ in items}}).encode(),b""
with patch.object(sandboxed,"available",return_value=True), patch.object(sandboxed,"run_isolated",slow):
    a=sandboxed.isolated_analyser("/nonexistent",2,64,timeout=5,budget_seconds=3,workers=2)
    s=time.time(); res=a([("python:%d"%i,"python",b"x=1\n") for i in range(20)]); d=time.time()-s
assert d<3+5+2,d
assert any(v is None for v in res.values()) and any(v is not None for v in res.values()),res
seen=[]
def fake_run(cmd,**kw):
    seen.append(cmd); raise subprocess.TimeoutExpired(cmd,20)
with patch.object(isolation,"_PROBE",None), patch.object(isolation.sys,"platform","linux"), patch.object(isolation.shutil,"which",return_value="/usr/bin/bwrap"), patch.object(isolation.subprocess,"run",fake_run):
    assert isolation.available() is False and isolation._PROBE is None,"timeout must not be cached"
assert "prlimit" in seen[0] and "python3" in seen[0],seen[0]
w=tempfile.mkdtemp(); t=os.path.join(w,"t"); os.mkdir(t); p=os.path.join(w,"p"); os.mkdir(p,0o700)
g=lambda *a: subprocess.run(["git","-C",t,"-c","user.name=T","-c","user.email=t@i","-c","core.autocrlf=false",*a],check=True,capture_output=True)
g("init"); open(os.path.join(t,"a.py"),"wb").write(b"def a(): pass\n"); g("add","."); g("commit","-m","s")
env={**os.environ,"OSB_TRUSTED_TARGETS":"1"}
r=subprocess.run([sys.executable,"-m","osb_engine","plan",t,os.path.join(p,"s.sqlite")],capture_output=True,text=True,env=env,timeout=300)
assert r.returncode==0,r.stderr[-500:]
mode=json.loads(r.stdout)["metrics"]["analysis"]
if isolation.available(): assert mode=="isolated",mode
else: assert mode=="in_process_trusted" and "warning" in r.stderr.lower(),(mode,r.stderr)
print("PASS bounded output, per-file deep-validated results, analysis budget, recorded trust mode, real probe")
