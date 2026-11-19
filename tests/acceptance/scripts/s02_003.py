import json,sqlite3,subprocess
from pathlib import Path
def invoke(*args,token=None):
 return subprocess.run(["python3","-m","osb_engine",*args],text=True,input=token,capture_output=True,timeout=60)
def ok(*args,token=None):
 r=invoke(*args,token=token); assert r.returncode==0,(args,r.stderr); return json.loads(r.stdout)
def deny(*args,token=None):
 r=invoke(*args,token=token); assert r.returncode==2 and "Command blocked" in r.stderr,(args,r.returncode,r.stdout,r.stderr)
pd=Path("/tmp/private-c");pd.mkdir(mode=0o700); db=str(pd/"store.sqlite")
repo=Path("/tmp/target");repo.mkdir()
def git(*args): subprocess.run(["git","-C",str(repo),"-c","user.name=T","-c","user.email=t@invalid",*args],check=True,capture_output=True)
git("init"); (repo/"a.py").write_text("def a(): pass\ndef b(): pass\ndef c(): pass\n"); git("add","."); git("commit","-m","seed")
base=[str(repo),db]; plan=ok("plan",*base)["run_id"]
A,B,C=[t["id"] for t in ok("status",*base,plan)["tasks"]][:3]
def f(name,text):
 p=pd/name; p.write_text(text); return str(p)
def count(table):
 c=sqlite3.connect("file:"+db+"?mode=ro",uri=True)
 try: return c.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
 finally: c.close()
accA=f("accA.py","import pathlib\nassert pathlib.Path('a.py').read_text().startswith('def a(): return 1\\n')\n")
accB=f("accB.py","import pathlib\nassert pathlib.Path('b.py').read_text()=='done\\n'\n")
cheat=f("cheat.py","pass\n")
ok("depend",*base,plan,B,A); ok("depend",*base,plan,C,B)
deny("depend",*base,plan,A,C)
deny("reserve",*base,plan,B,"300")
la=ok("reserve",*base,plan,A,"300"); ga,ta=str(la["generation"]),la["token"]
ok("grant",*base,plan,A,ga,"--operation","edit","a.py","x.py")
deny("complete",*base,plan,A,ga,token=ta)
ok("freeze",*base,plan,A,accA); ok("freeze",*base,plan,A,accA); deny("freeze",*base,plan,A,cheat)
deny("complete",*base,plan,A,ga,token=ta)
v=ok("verify",*base,plan,A,ga,accA); assert v["passed"] is False and v["returncode"]!=0
deny("complete",*base,plan,A,ga,token=ta)
n=count("kernel_verifications_v1"); deny("verify",*base,plan,A,ga,cheat); assert count("kernel_verifications_v1")==n
edit=f("e1.patch","--- a/a.py\n+++ b/a.py\n@@ -1,3 +1,3 @@\n-def a(): pass\n+def a(): return 1\n def b(): pass\n def c(): pass\n")
ok("mutate",*base,plan,A,ga,edit,token=ta)
assert ok("verify",*base,plan,A,ga,accA)["passed"] is True
deny("complete",*base,plan,A,ga,token="forged")
ok("pause",*base,"--reason","hold"); deny("complete",*base,plan,A,ga,token=ta); ok("resume",*base,"--reason","go")
(repo/"stray.py").write_text("x\n"); deny("complete",*base,plan,A,ga,token=ta); (repo/"stray.py").unlink()
ok("mutate",*base,plan,A,ga,f("e2.patch","--- /dev/null\n+++ b/x.py\n@@ -0,0 +1 @@\n+x = 1\n"),token=ta)
deny("complete",*base,plan,A,ga,token=ta)
assert ok("verify",*base,plan,A,ga,accA)["passed"] is True
assert count("kernel_completions_v1")==0
done=ok("complete",*base,plan,A,ga,token=ta); assert done["completed"] is True
deny("complete",*base,plan,A,ga,token=ta); deny("reserve",*base,plan,A,"300")
deny("mutate",*base,plan,A,ga,edit,token=ta)
lb=ok("reserve",*base,plan,B,"300"); gb,tb=str(lb["generation"]),lb["token"]
assert lb["generation"]==la["generation"]+1
ok("grant",*base,plan,B,gb,"--operation","edit","b.py"); ok("freeze",*base,plan,B,accB)
ok("mutate",*base,plan,B,gb,f("b1.patch","--- /dev/null\n+++ b/b.py\n@@ -0,0 +1 @@\n+done\n"),token=tb)
deny("release",*base,plan,B,gb,"--reason","abandon")
ok("release",*base,plan,B,gb,"--reason","abandon","--revert")
assert not (repo/"b.py").exists() and (repo/"x.py").exists() and (repo/"a.py").read_text().startswith("def a(): return 1")
deny("renew",*base,plan,B,gb,"60",token=tb); deny("mutate",*base,plan,B,gb,str(pd/"b1.patch"),token=tb)
deny("reserve",*base,plan,C,"300")
lb2=ok("reserve",*base,plan,B,"300"); gb2,tb2=str(lb2["generation"]),lb2["token"]
deny("complete",*base,plan,B,gb2,token=tb2)
ok("grant",*base,plan,B,gb2,"--operation","edit","b.py")
ok("mutate",*base,plan,B,gb2,str(pd/"b1.patch"),token=tb2)
assert ok("verify",*base,plan,B,gb2,accB)["passed"] is True
git("commit","--allow-empty","-m","moved")
deny("complete",*base,plan,B,gb2,token=tb2)
assert count("kernel_completions_v1")==1
print("PASS frozen acceptance, supervisor verification, bound completion, dependencies, release with revert and no completion by release")
