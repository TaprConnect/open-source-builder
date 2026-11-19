import json,os,subprocess,tempfile
from pathlib import Path
def invoke(*args,token=None):
 return subprocess.run(["python3","-m","osb_engine",*args],text=True,input=token,capture_output=True,timeout=120)
def ok(*args,token=None):
 r=invoke(*args,token=token); assert r.returncode==0,(args,r.stderr); return json.loads(r.stdout)
w=Path(tempfile.mkdtemp()); pd=w/"private"; pd.mkdir(mode=0o700); db=str(pd/"store.sqlite")
other=w/"other"; other.mkdir(); (other/"secret.txt").write_text("other project secret\n")
repo=w/"target"; repo.mkdir()
def git(*a): subprocess.run(["git","-C",str(repo),"-c","user.name=T","-c","user.email=t@invalid",*a],check=True,capture_output=True)
(repo/"a.py").write_text("def a(): pass\ndef b(): pass\n"); (repo/"evil.py").write_text("import os\nos._exit(0)\n")
git("init"); git("add","."); git("commit","-m","seed")
base=[str(repo),db]; plan=ok("plan",*base)["run_id"]; tasks=[t["id"] for t in ok("status",*base,plan)["tasks"]]
A,B=tasks[0],tasks[1]
la=ok("reserve",*base,plan,A,"600"); g,t=str(la["generation"]),la["token"]
def acc(name,text):
 f=pd/name; f.write_text(text); return str(f)
early=acc("early.py","import sys\nsys.path.insert(0,'.')\nimport evil\nraise SystemExit(1)\n")
ok("freeze",*base,plan,A,early)
v=ok("verify",*base,plan,A,g,early); assert v["passed"] is False,v
probe=acc("probe.py",f"""
import os,socket,sys
assert not os.path.exists({db!r}) and not os.path.exists({str(pd)!r}),"store visible"
assert not os.path.exists({str(other)!r}),"other project visible"
assert not any({t!r} in v for v in os.environ.values()),"token in env"
try:
    open("a.py","a").write("x"); raise SystemExit("checkout writable")
except OSError: pass
try:
    socket.create_connection(("1.1.1.1",53),timeout=2); raise SystemExit("network reachable")
except OSError: pass
assert open("a.py").read().startswith("def a(): pass")
""")
ok("release",*base,plan,A,g,"--reason","switch")
lb=ok("reserve",*base,plan,B,"600"); gb,tb=str(lb["generation"]),lb["token"]
ok("freeze",*base,plan,B,probe)
v=ok("verify",*base,plan,B,gb,probe); assert v["passed"] is True,v
done=ok("complete",*base,plan,B,gb,token=tb); assert done["completed"] is True
assert (repo/"a.py").read_text()=="def a(): pass\ndef b(): pass\n"
print("PASS isolated verification: early exit rejected, no store/other project/token/network/write access, completion via isolated pass")
