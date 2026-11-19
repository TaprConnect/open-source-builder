import json,subprocess
from pathlib import Path
def invoke(*args,token=None):
 return subprocess.run(["python3","-m","osb_engine",*args],text=True,input=token,capture_output=True,timeout=20)
def ok(*args,token=None):
 r=invoke(*args,token=token); assert r.returncode==0,(args,r.stderr); return json.loads(r.stdout)
def deny(*args,token=None):
 r=invoke(*args,token=token); assert r.returncode==2 and "Command blocked" in r.stderr,(args,r.returncode,r.stdout,r.stderr)
p=Path("/tmp/private-r");p.mkdir(mode=0o700); db=str(p/"store.sqlite")
repo=Path("/tmp/target");repo.mkdir()
def git(*args): subprocess.run(["git","-C",str(repo),"-c","user.name=T","-c","user.email=t@invalid",*args],check=True,capture_output=True)
git("init"); (repo/"a.py").write_text("def a(): pass\n"); git("add","."); git("commit","-m","seed")
base=[str(repo),db]; plan=ok("plan",*base)["run_id"]; a=ok("status",*base,plan)["tasks"][0]["id"]
lease=ok("reserve",*base,plan,a,"60"); g=str(lease["generation"])
aliases=["GIT~1/config",".git./config",".git /config","a.py::$DATA",".git::$INDEX_ALLOCATION/config","CON","con.txt","LPT1","a.py.","a.py ","sub/.git/config","SUB/.Git/HEAD","x\ty","café.py","a:b","a*b","a?b","a\"b","a<b","a>b","a|b"]
for bad in aliases:
 deny("grant",*base,plan,a,g,"--operation","edit",bad)
 deny("dispatch",*base,plan,a,g,"edit",bad,token=lease["token"])
for good in ["a.py",".github/workflows/test.yml","src/","docs/v1.2/notes.md","pkg/__init__.py","Makefile","a-b_c.d"]:
 ok("grant",*base,plan,a,g,"--operation","edit",good)
print("PASS portable path policy rejects Windows device, stream, short-name, trailing and .git aliases")
