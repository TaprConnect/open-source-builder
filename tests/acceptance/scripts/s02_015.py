import json,subprocess,tempfile
from pathlib import Path
def invoke(*a,token=None): return subprocess.run(["python3","-m","osb_engine",*a],text=True,input=token,capture_output=True,timeout=120)
def ok(*a,token=None):
    r=invoke(*a,token=token); assert r.returncode==0,(a,r.stderr); return json.loads(r.stdout)
def blocked(*a,token=None):
    r=invoke(*a,token=token); assert r.returncode==2 and "Command blocked" in r.stderr,(a,r.stdout,r.stderr)
def setup():
    w=Path(tempfile.mkdtemp()); p=w/"p"; p.mkdir(mode=0o700); t=w/"t"; t.mkdir()
    g=lambda *a: subprocess.run(["git","-C",str(t),"-c","user.name=T","-c","user.email=t@invalid",*a],check=True,capture_output=True)
    g("init"); (t/"a.py").write_text("def a(): pass\ndef b(): pass\n"); g("add","."); g("commit","-m","s")
    base=[str(t),str(p/"s.sqlite")]; plan=ok("plan",*base)["run_id"]; return p,base,plan
def state(base,plan,task):
    v=next(x for x in ok("status",*base,plan)["tasks"] if x["id"]==task); return v["state"],v["version"]
def move(base,plan,task,new,expect_ok=True):
    s,v=state(base,plan,task); f=ok if expect_ok else blocked
    return f("transition",*base,plan,task,str(v),new,"--reason","r")
p,base,plan=setup(); A,B=[x["id"] for x in ok("status",*base,plan)["tasks"]][:2]
move(base,plan,A,"investigating")
la=ok("reserve",*base,plan,A,"600"); g,t=str(la["generation"]),la["token"]
move(base,plan,A,"open",False); move(base,plan,A,"blocked",False); move(base,plan,A,"proposed",False)
acc=p/"acc.py"; acc.write_text("pass\n"); ok("freeze",*base,plan,A,str(acc)); ok("verify",*base,plan,A,g,str(acc)); ok("complete",*base,plan,A,g,token=t)
move(base,plan,A,"open",False); move(base,plan,A,"blocked",False); move(base,plan,A,"proposed")
for nxt in ("open","blocked"): move(base,plan,A,nxt,False)
move(base,plan,B,"blocked"); blocked("reserve",*base,plan,B,"60"); move(base,plan,B,"open"); ok("reserve",*base,plan,B,"60")
p2,base2,plan2=setup(); C=ok("status",*base2,plan2)["tasks"][0]["id"]
move(base2,plan2,C,"investigating"); move(base2,plan2,C,"proposed")
print("PASS planning transitions consistent with kernel lease and completion; legacy projects unchanged")
