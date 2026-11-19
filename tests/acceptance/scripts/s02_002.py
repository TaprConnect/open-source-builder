import json,sqlite3,subprocess,time
from pathlib import Path
def invoke(*args,token=None):
 return subprocess.run(["python3","-m","osb_engine",*args],text=True,input=token,capture_output=True,timeout=20)
def ok(*args,token=None):
 r=invoke(*args,token=token)
 assert r.returncode==0,(args,r.stderr)
 return json.loads(r.stdout)
def deny(*args,token=None):
 r=invoke(*args,token=token)
 assert r.returncode==2 and "Command blocked" in r.stderr,(args,r.returncode,r.stdout,r.stderr)
p=Path("/tmp/private-g");p.mkdir(mode=0o700)
db=str(p/"store.sqlite")
repo=Path("/tmp/target");repo.mkdir()
def git(*args):
 subprocess.run(["git","-C",str(repo),"-c","user.name=Test","-c","user.email=test@invalid",*args],check=True,capture_output=True)
git("init")
(repo/"a.py").write_text("def a(): pass\ndef b(): pass\n")
git("add",".");git("commit","-m","seed")
base=[str(repo),db]
def dispatches():
 c=sqlite3.connect("file:"+db+"?mode=ro",uri=True)
 try:
  if not c.execute("SELECT 1 FROM sqlite_master WHERE name='kernel_dispatches_v1'").fetchone(): return 0
  return c.execute("SELECT COUNT(*) FROM kernel_dispatches_v1").fetchone()[0]
 finally: c.close()
plan=ok("plan",*base)["run_id"]
a,b=[row["id"] for row in ok("status",*base,plan)["tasks"]]
lease=ok("reserve",*base,plan,a,"60")
g,t=str(lease["generation"]),lease["token"]
D=lambda task,gen,*op,token=t:("dispatch",*base,plan,task,gen,*op)
deny(*D(a,g,"edit","a.py"),token=t)
deny("grant",*base,plan,a,str(lease["generation"]+1),"--operation","edit","a.py")
for bad in ("/etc/passwd","../x","src/../a.py",".git/config","","./a.py"):
 deny("grant",*base,plan,a,g,"--operation","edit",bad)
deny("grant",*base,plan,b,g,"--operation","edit","a.py")
ok("grant",*base,plan,a,g,"--operation","edit","a.py","src/","--operation","test","tests/")
assert dispatches()==0
rec=ok(*D(a,g,"edit","a.py","src/x.py"),token=t)
assert rec["authorised"] is True and rec["revision"]==lease["revision"] and rec["operation"]=={"kind":"edit","paths":["a.py","src/x.py"]}
assert dispatches()==1
for op,tok in [(("edit","b.py"),t),(("edit","src"),t),(("delete","a.py"),t),(("test","a.py"),t),(("edit","src/../b.py"),t),(("edit",".git/hooks/x"),t),(("edit","a.py"),"wrong"),(("edit",),t)]:
 deny(*D(a,g,*op),token=tok)
deny(*D(a,str(lease["generation"]+1),"edit","a.py"),token=t)
deny(*D(b,g,"edit","a.py"),token=t)
assert dispatches()==1
ok("pause",*base,"--reason","incident review")
deny(*D(a,g,"edit","a.py"),token=t)
deny("grant",*base,plan,a,g,"--operation","edit","b.py")
ok("renew",*base,plan,a,g,"60",token=t)
ok("resume",*base,"--reason","cleared")
ok(*D(a,g,"edit","a.py"),token=t)
assert dispatches()==2
ok("revoke",*base,plan,a,g,"--reason","worker compromised")
deny(*D(a,g,"edit","a.py"),token=t)
deny("renew",*base,plan,a,g,"60",token=t)
deny("revoke",*base,plan,a,g,"--reason","again")
deny("reserve",*base,plan,b,"60")
new=ok("reserve",*base,plan,a,"4")
ng,nt=str(new["generation"]),new["token"]
assert new["generation"]==lease["generation"]+1 and nt!=t
deny(*D(a,ng,"edit","a.py"),token=nt)
deny(*D(a,ng,"edit","a.py"),token=t)
deny(*D(a,g,"edit","a.py"),token=t)
ok("grant",*base,plan,a,ng,"--operation","edit","a.py")
ok(*D(a,ng,"edit","a.py"),token=nt)
assert dispatches()==3
time.sleep(max(0,(new["expires_ns"]-time.time_ns())/1e9)+0.2)
deny(*D(a,ng,"edit","a.py"),token=nt)
again=ok("reserve",*base,plan,a,"60")
ag,at=str(again["generation"]),again["token"]
ok("grant",*base,plan,a,ag,"--operation","edit","a.py")
ok(*D(a,ag,"edit","a.py"),token=at)
assert dispatches()==4
git("commit","--allow-empty","-m","change")
deny(*D(a,ag,"edit","a.py"),token=at)
assert dispatches()==4
print("PASS grant, scoped dispatch, pause/resume, revocation, recovery fencing, expiry, stale revision and no side effects on denial")
