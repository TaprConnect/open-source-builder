import json,os,subprocess,sys,tempfile,time
def cli(*a,token=None): return subprocess.run([sys.executable,"-m","osb_engine",*a],capture_output=True,text=True,input=token,timeout=600)
def ok(*a,token=None):
    r=cli(*a,token=token); assert r.returncode==0,(a,r.stderr[-800:]); return json.loads(r.stdout)
def blocked(*a,token=None):
    r=cli(*a,token=token); assert r.returncode==2 and "Command blocked" in r.stderr,(a,r.stdout,r.stderr[-400:])
w=tempfile.mkdtemp(); t=os.path.join(w,"t"); os.mkdir(t); p=os.path.join(w,"p"); os.mkdir(p,0o700)
g=lambda *a: subprocess.run(["git","-C",t,"-c","user.name=T","-c","user.email=t@i","-c","core.autocrlf=false",*a],check=True,capture_output=True)
open(os.path.join(t,"a.py"),"wb").write(b"def f():\n    return 42\ndef g():\n    pass\ndef h():\n    pass\n"); g("init"); g("add","."); g("commit","-m","s")
base=[t,os.path.join(p,"s.sqlite")]; plan=ok("plan",*base)["run_id"]; A,B=[x["id"] for x in ok("status",*base,plan)["tasks"]][:2]
acc=os.path.join(p,"acc.py"); open(acc,"w").write("from osb_accept import run\ncode,out,err=run(['python3','-c','import a; print(a.f())'])\nassert out==b'42\\n',(code,out,err)\n")
la=ok("reserve",*base,plan,A,"900"); ga,ta=str(la["generation"]),la["token"]
legacy=os.path.join(p,"legacy.py"); open(legacy,"w").write("pass\n")
ok("freeze",*base,plan,A,legacy)
ok("configure",*base,"--require-external-acceptance","on")
blocked("verify",*base,plan,A,ga,legacy)
ok("configure",*base,"--require-external-acceptance","off"); ok("verify",*base,plan,A,ga,legacy); ok("configure",*base,"--require-external-acceptance","on")
blocked("complete",*base,plan,A,ga,token=ta)
ok("release",*base,plan,A,ga,"--reason","switch")
lb=ok("reserve",*base,plan,B,"900"); gb,tb=str(lb["generation"]),lb["token"]
ok("configure",*base,"--require-external-acceptance","off"); ok("freeze",*base,plan,B,acc); ok("configure",*base,"--require-external-acceptance","on")
up=ok("freeze",*base,plan,B,acc,"--external"); assert up["assurance"]=="external",up
v=ok("verify",*base,plan,B,gb,acc); assert v["passed"] is True and v["assurance"]=="external",v
assert ok("complete",*base,plan,B,gb,token=tb)["assurance"]=="external"
p2=os.path.join(w,"p2"); os.mkdir(p2,0o700); base2=[t,os.path.join(p2,"s.sqlite")]
plan2=ok("plan",*base2)["run_id"]; C=ok("status",*base2,plan2)["tasks"][0]["id"]
marker="osbsleep%d" % os.getpid()
stray=os.path.join(p2,"stray.py"); open(stray,"w").write("import json,base64,osb_accept\nosb_accept._requests.write(json.dumps({'argv':['python3','-c','import time; time.sleep(40)  # %s'],'stdin':'','timeout':60}).encode()+b'\\n')\nimport time; time.sleep(2)\n" % marker)
lc=ok("reserve",*base2,plan2,C,"900"); ok("freeze",*base2,plan2,C,stray,"--external")
s=time.time(); ok("verify",*base2,plan2,C,str(lc["generation"]),stray); d=time.time()-s
time.sleep(1)
left=subprocess.run(["pgrep","-f",marker],capture_output=True,text=True).stdout.split()
assert not left,(left,d)
print("PASS external policy enforced at verify and complete; upgrade before first verification; no broker command outlives verification")
