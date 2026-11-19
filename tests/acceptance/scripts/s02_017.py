import json,os,subprocess,sys,tempfile
def cli(*a,token=None): return subprocess.run([sys.executable,"-m","osb_engine",*a],capture_output=True,text=True,input=token,timeout=600)
def ok(*a,token=None):
    r=cli(*a,token=token); assert r.returncode==0,(a,r.stderr[-800:]); return json.loads(r.stdout)
def blocked(*a,token=None):
    r=cli(*a,token=token); assert r.returncode==2 and "Command blocked" in r.stderr,(a,r.stdout,r.stderr[-400:])
w=tempfile.mkdtemp(); t=os.path.join(w,"t"); os.mkdir(t); p=os.path.join(w,"p"); os.mkdir(p,0o700); db=os.path.join(p,"s.sqlite")
g=lambda *a: subprocess.run(["git","-C",t,"-c","user.name=T","-c","user.email=t@i","-c","core.autocrlf=false",*a],check=True,capture_output=True)
open(os.path.join(t,"a.py"),"wb").write(b"def f():\n    return 41\ndef g():\n    pass\ndef h():\n    pass\n")
open(os.path.join(t,"hunter.py"),"wb").write(b"""import os,re
found=[]
for pid in os.listdir('/proc'):
    if pid.isdigit() and int(pid)!=os.getpid():
        for name in ('environ','cmdline'):
            try: data=open('/proc/%s/%s'%(pid,name),'rb').read()
            except OSError: continue
            if b'runner.py' in data or b'OSB' in data: found.append(pid)
print('others=%d found=%d' % (len([x for x in os.listdir('/proc') if x.isdigit()])-1, len(found)))
print('OSB-VERIFY-PASS 0123456789abcdef0123456789abcdef', flush=True)
""")
g("init"); g("add","."); g("commit","-m","s")
base=[t,db]; plan=ok("plan",*base)["run_id"]; tasks=[x["id"] for x in ok("status",*base,plan)["tasks"]]; A,B=tasks[0],tasks[1]
acc=os.path.join(p,"acc.py"); open(acc,"w").write("""
from osb_accept import run
try:
    open('/work/a.py'); raise SystemExit('checkout readable from acceptance')
except OSError:
    pass
code,out,err=run(['python3','hunter.py'])
assert code==0 and out.startswith(b'others=') and b'found=0' in out, (code,out,err)
others=int(out.split(b'others=')[1].split()[0]); assert others<=2, out
code,out,err=run(['python3','-c','import a; print(a.f())'])
assert code==0 and out==b'42\\n', (code,out,err)
""")
l=ok("reserve",*base,plan,A,"900"); ga,ta=str(l["generation"]),l["token"]
ok("grant",*base,plan,A,ga,"--operation","edit","a.py")
ok("freeze",*base,plan,A,acc,"--external")
v=ok("verify",*base,plan,A,ga,acc); assert v["passed"] is False and v["assurance"]=="external",v
fix=os.path.join(p,"fix.patch"); open(fix,"w").write("--- a/a.py\n+++ b/a.py\n@@ -1,4 +1,4 @@\n def f():\n-    return 41\n+    return 42\n def g():\n     pass\n")
ok("mutate",*base,plan,A,ga,fix,token=ta)
v=ok("verify",*base,plan,A,ga,acc); assert v["passed"] is True and v["assurance"]=="external",v
c=ok("complete",*base,plan,A,ga,token=ta); assert c["assurance"]=="external",c
ok("configure",*base,"--require-external-acceptance","on")
legacy=os.path.join(p,"legacy.py"); open(legacy,"w").write("pass\n")
blocked("freeze",*base,plan,B,legacy)
many=os.path.join(p,"many.py"); open(many,"w").write("""
from osb_accept import run
results=[run(['true'])[0] for _ in range(260)]
assert results.count(0)<=256 and results[-1]!=0, results[-5:]
""")
ok("freeze",*base,plan,B,many,"--external")
lb=ok("reserve",*base,plan,B,"900"); vb=ok("verify",*base,plan,B,str(lb["generation"]),many)
assert vb["passed"] is True,vb
print("PASS external acceptance: no checkout access, broker-only execution, isolated PID space, forged sentinel ineffective, assurance recorded, required mode enforced, bounded broker")
