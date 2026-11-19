import json,subprocess,tempfile,time
from pathlib import Path
def invoke(*a,token=None): return subprocess.run(["python3","-m","osb_engine",*a],text=True,input=token,capture_output=True,timeout=120)
def ok(*a,token=None):
    r=invoke(*a,token=token); assert r.returncode==0,(a,r.stderr); return json.loads(r.stdout)
def blocked(*a,token=None):
    r=invoke(*a,token=token); assert r.returncode==2 and "Command blocked" in r.stderr,(a,r.stdout,r.stderr)
w=Path(tempfile.mkdtemp()); p=w/"p"; p.mkdir(mode=0o700); t=w/"t"; t.mkdir()
g=lambda *a: subprocess.run(["git","-C",str(t),"-c","user.name=T","-c","user.email=t@invalid",*a],check=True,capture_output=True)
g("init"); (t/"a.py").write_text("def a(): pass\ndef b(): pass\n"); g("add","."); g("commit","-m","s")
base=[str(t),str(p/"s.sqlite")]; plan=ok("plan",*base)["run_id"]; A,B=[x["id"] for x in ok("status",*base,plan)["tasks"]][:2]
def pf(name,text):
    f=p/name; f.write_text(text); return str(f)
P1=pf("p1.patch","--- /dev/null\n+++ b/n1.py\n@@ -0,0 +1 @@\n+n = 1\n")
P1x=pf("p1x.patch","--- /dev/null\n+++ b/n1.py\n@@ -0,0 +1 @@\n+n = 2\n")
P2=pf("p2.patch","--- /dev/null\n+++ b/n2.py\n@@ -0,0 +1 @@\n+n = 2\n")
P3=pf("p3.patch","--- /dev/null\n+++ b/n3.py\n@@ -0,0 +1 @@\n+n = 3\n")
la=ok("reserve",*base,plan,A,"600"); g1,t1=str(la["generation"]),la["token"]
ok("grant",*base,plan,A,g1,"--operation","edit","n1.py","n2.py","n3.py")
ok("configure",*base,"--require-approval","on")
blocked("mutate",*base,plan,A,g1,P1,token=t1)
ok("approve",*base,plan,A,g1,P1)
blocked("mutate",*base,plan,A,g1,P1x,token=t1)
ok("mutate",*base,plan,A,g1,P1,token=t1); assert (t/"n1.py").read_text()=="n = 1\n"
ok("approve",*base,plan,A,g1,P2); ok("mutate",*base,plan,A,g1,P2,token=t1)
(t/"n2.py").unlink(); (p/"rev.patch").write_text("--- a/n2.py\n+++ /dev/null\n@@ -1 +0,0 @@\n-n = 2\n")
(t/"n2.py").write_text("n = 2\n")
blocked("mutate",*base,plan,A,g1,P2,token=t1)
ok("approve",*base,plan,A,g1,P3); ok("revoke",*base,plan,A,g1,"--reason","rotate")
la2=ok("reserve",*base,plan,A,"600"); g2,t2=str(la2["generation"]),la2["token"]
ok("grant",*base,plan,A,g2,"--operation","edit","n3.py")
blocked("mutate",*base,plan,A,g2,P3,token=t2)
ok("configure",*base,"--require-approval","off"); ok("mutate",*base,plan,A,g2,P3,token=t2)
blocked("reserve",*base,plan,B,"60"); blocked("grant",*base,plan,B,g2,"--operation","edit","x.py")
blocked("dispatch",*base,plan,B,g2,"edit","x.py",token=t2); blocked("mutate",*base,plan,B,g2,P1,token=t2)
ok("renew",*base,plan,A,g2,"1",token=t2); time.sleep(1.5)
blocked("reserve",*base,plan,B,"60")
print("PASS patch-bound single-use approvals per generation; conflicting task cannot act while the slot is held or retained")
