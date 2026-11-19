import json,os,subprocess,sys,tempfile,textwrap
sys.path.insert(0,os.getcwd())
from pathlib import Path
src=os.getcwd()
def cli(*a,token=None): return subprocess.run([sys.executable,"-m","osb_engine",*a],capture_output=True,text=True,input=token,timeout=120)
def ok(*a,token=None):
    r=cli(*a,token=token); assert r.returncode==0,(a,r.stderr); return json.loads(r.stdout)
def blocked(*a,token=None):
    r=cli(*a,token=token); assert r.returncode==2 and "Command blocked" in r.stderr,(a,r.stdout,r.stderr); return r.stderr
def crash(code):
    script=textwrap.dedent(code); r=subprocess.run([sys.executable,"-c","import sys;sys.path.insert(0,%r)\n"%src+script],capture_output=True,text=True,timeout=120)
    assert r.returncode==9,(r.returncode,r.stderr)
def setup():
    w=Path(tempfile.mkdtemp()); t=w/"t"; t.mkdir(); p=w/"p"; p.mkdir(mode=0o700)
    g=lambda *a: subprocess.run(["git","-C",str(t),"-c","user.name=T","-c","user.email=t@invalid","-c","core.autocrlf=false",*a],check=True,capture_output=True)
    g("init"); (t/"a.py").write_bytes(b"def a(): pass\ndef b(): pass\n"); g("add","."); g("commit","-m","s")
    base=[str(t),str(p/"s.sqlite")]; plan=ok("plan",*base)["run_id"]; task=ok("status",*base,plan)["tasks"][0]["id"]
    l=ok("reserve",*base,plan,task,"600"); gen=str(l["generation"]); tok=l["token"]
    ok("grant",*base,plan,task,gen,"--operation","edit","a.py","n.py")
    return w,t,p,base,plan,task,gen,tok
EDIT=b"--- a/a.py\n+++ b/a.py\n@@ -1,2 +1,2 @@\n-def a(): pass\n+def a(): return 1\n def b(): pass\n"
NEW=b"--- /dev/null\n+++ b/n.py\n@@ -0,0 +1 @@\n+n = 1\n"
HARNESS='''
import os
from osb_engine import mutation, completion
from osb_engine.repository import Repository
from osb_engine.store import Store
st=Store(Repository({t!r}),{db!r})
'''
w,t,p,base,plan,task,gen,tok=setup()
assert ok("recover",*base)["recovered"] is False
crash(HARNESS.format(t=base[0],db=base[1])+f'''
real=mutation._apply
def dying(repo,data,reverse=False):
    real(repo,data,reverse); os._exit(9)
mutation._apply=dying
mutation.mutate(st,{plan!r},{task!r},{gen},{tok!r},{EDIT!r})
''')
assert (t/"a.py").read_bytes()==b"def a(): return 1\ndef b(): pass\n"
assert "recover" in blocked("dispatch",*base,plan,task,gen,"edit","a.py",token=tok)
r=ok("recover",*base); assert r["recovered"] is True and r["action"]=="restored",r
assert (t/"a.py").read_bytes()==b"def a(): pass\ndef b(): pass\n"
pf=p/"e.patch"; pf.write_bytes(EDIT); ok("mutate",*base,plan,task,gen,str(pf),token=tok)
w,t,p,base,plan,task,gen,tok=setup()
crash(HARNESS.format(t=base[0],db=base[1])+f'''
real=mutation._end_journal
def dying(*a,**k): os._exit(9)
mutation._end_journal=dying
mutation.mutate(st,{plan!r},{task!r},{gen},{tok!r},{EDIT!r})
''')
blocked("dispatch",*base,plan,task,gen,"edit","a.py",token=tok)
r=ok("recover",*base); assert r["action"]=="adopted",r
assert (t/"a.py").read_bytes()==b"def a(): return 1\ndef b(): pass\n"
ok("dispatch",*base,plan,task,gen,"edit","a.py",token=tok)
w,t,p,base,plan,task,gen,tok=setup()
for name,data in (("e.patch",EDIT),("n.patch",NEW)):
    (p/name).write_bytes(data); ok("mutate",*base,plan,task,gen,str(p/name),token=tok)
crash(HARNESS.format(t=base[0],db=base[1])+f'''
real=completion._apply
calls=[]
def dying(repo,data,reverse=False):
    real(repo,data,reverse); calls.append(1)
    if len(calls)==1: os._exit(9)
completion._apply=dying
completion.release(st,{plan!r},{task!r},{gen},"abandon",revert=True)
''')
blocked("dispatch",*base,plan,task,gen,"edit","a.py",token=tok)
assert ok("recover",*base)["action"]=="restored"
assert (t/"a.py").read_bytes()==b"def a(): return 1\ndef b(): pass\n" and (t/"n.py").read_bytes()==b"n = 1\n"
ok("release",*base,plan,task,gen,"--reason","abandon","--revert")
assert (t/"a.py").read_bytes()==b"def a(): pass\ndef b(): pass\n" and not (t/"n.py").exists()
print("PASS interrupted mutate and release recover by exact restore or adoption; operations refuse until recovered")
