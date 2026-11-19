import concurrent.futures,json,subprocess,time
from pathlib import Path
def invoke(*args,token=None):
 return subprocess.run(["python3","-m","osb_engine",*args],text=True,input=token,capture_output=True,timeout=20)
def ok(*args,token=None):
 r=invoke(*args,token=token)
 assert r.returncode==0,r.stderr
 return json.loads(r.stdout)
def deny(*args,token=None):
 r=invoke(*args,token=token)
 assert r.returncode==2 and "Command blocked" in r.stderr,r.stderr
p=Path("/tmp/private-k");p.mkdir(mode=0o700)
db=str(p/"store.sqlite")
repo=Path("/tmp/target");repo.mkdir()
def git(*args):
 subprocess.run(["git","-C",str(repo),"-c","user.name=Test","-c","user.email=test@invalid",*args],check=True,capture_output=True)
git("init")
(repo/"a.py").write_text("def a(): pass\ndef b(): pass\n")
git("add",".");git("commit","-m","seed")
base=[str(repo),db]
plan=ok("plan",*base)["run_id"]
rows=ok("status",*base,plan)["tasks"]
tasks=[row["id"] for row in rows]
assert len(tasks)==2
deny("reserve",*base,plan,"unknown","60")
args=lambda task:[*base,plan,task]
with concurrent.futures.ThreadPoolExecutor(2) as pool:
 results=list(pool.map(lambda t:invoke("reserve",*args(t),"2"),tasks))
assert sorted(r.returncode for r in results)==[0,2],[r.stderr for r in results]
i=next(i for i,r in enumerate(results) if r.returncode==0)
a=args(tasks[i]); b=args(tasks[1-i])
lease=json.loads(results[i].stdout)
deny("reserve",*a,"60")
deny("renew",*a,str(lease["generation"]),"60",token="bad")
time.sleep(2.1)
deny("renew",*a,str(lease["generation"]),"60",token=lease["token"])
deny("reserve",*b,"60")
new=ok("reserve",*a,"60")
assert new["generation"]==lease["generation"]+1 and new["token"]!=lease["token"]
deny("renew",*a,str(lease["generation"]),"60",token=lease["token"])
deny("renew",*a,str(new["generation"]),"60",token=lease["token"])
deny("renew",*b,str(new["generation"]),"60",token=new["token"])
deny("renew",*a,str(new["generation"]),"3601",token=new["token"])
ok("renew",*a,str(new["generation"]),"60",token=new["token"])
git("commit","--allow-empty","-m","change")
deny("renew",*a,str(new["generation"]),"60",token=new["token"])
print("PASS real plan, concurrent ownership, recovery, fencing, stale revision and bounded renewals")
