import json,os,subprocess,sys,tempfile
sys.path.insert(0,os.getcwd())
from pathlib import Path
def cli(*a,token=None): return subprocess.run([sys.executable,"-m","osb_engine",*a],capture_output=True,text=True,input=token,timeout=120)
def ok(*a,token=None):
    r=cli(*a,token=token); assert r.returncode==0,(a,r.stderr); return json.loads(r.stdout)
def blocked(*a,token=None):
    r=cli(*a,token=token); assert r.returncode==2 and "Command blocked" in r.stderr,(a,r.stdout,r.stderr)
w=Path(tempfile.mkdtemp()); src=w/"src"; src.mkdir()
g=lambda cwd,*a: subprocess.run(["git","-C",str(cwd),"-c","user.name=T","-c","user.email=t@invalid","-c","core.autocrlf=false",*a],check=True,capture_output=True)
g(src,"init"); (src/"a.py").write_bytes(b"def a(): pass\ndef b(): pass\n"); (src/"bin.dat").write_bytes(b"\x00\x01\n\x02")
(src/"id.txt").write_bytes(b"$Id$\nx\n"); (src/".gitattributes").write_bytes(b"*.txt ident\n"); g(src,"add","."); g(src,"commit","-m","s")
def setup(clone_crlf):
    t=w/("t%d"%len(list(w.iterdir()))); subprocess.run(["git","-c","core.autocrlf="+("true" if clone_crlf else "false"),"clone","-q",str(src),str(t)],check=True,capture_output=True)
    if not clone_crlf:
        for n in ("a.py","id.txt",".gitattributes"): (t/n).write_bytes((t/n).read_bytes().replace(b"\n",b"\r\n"))
    p=w/("p"+t.name); p.mkdir(mode=0o700); db=str(p/"s.sqlite"); base=[str(t),db]
    plan=ok("plan",*base)["run_id"]; task=ok("status",*base,plan)["tasks"][0]["id"]
    return t,base,plan,task
t,base,plan,task=setup(False)
blocked("reserve",*base,plan,task,"60")
ok("configure",*base,"--eol","crlf")
ok("reserve",*base,plan,task,"60"); ok("release",*base,plan,task,ok("status",*base,plan) and "1","--reason","x") if False else None
t2,base2,plan2,task2=setup(False); ok("configure",*base2,"--eol","crlf")
(t2/"a.py").write_bytes(b"def a(): pass\r\ndef b(): pass\n"); blocked("reserve",*base2,plan2,task2,"60")
(t2/"a.py").write_bytes(b"def a(): evil\r\ndef b(): pass\r\n"); blocked("reserve",*base2,plan2,task2,"60")
(t2/"a.py").write_bytes(b"def a(): pass\r\ndef b(): pass\r\n"); (t2/"id.txt").write_bytes(b"$Id: EVIL $\r\nx\r\n"); blocked("reserve",*base2,plan2,task2,"60")
(t2/"id.txt").write_bytes(b"$Id$\r\nx\r\n"); (t2/"bin.dat").write_bytes(b"\x00\x01\r\n\x02"); blocked("reserve",*base2,plan2,task2,"60")
(t2/"bin.dat").write_bytes(b"\x00\x01\n\x02"); ok("reserve",*base2,plan2,task2,"60")
if os.name=="nt":
    t3,base3,plan3,task3=setup(True)
    assert (t3/"a.py").read_bytes()==b"def a(): pass\r\ndef b(): pass\r\n", (t3/"a.py").read_bytes()
    blocked("reserve",*base3,plan3,task3,"60"); ok("configure",*base3,"--eol","crlf"); ok("reserve",*base3,plan3,task3,"60")
print("PASS eol policy: default byte-exact; crlf accepts only full conversion; mixed, edited, ident and binary changes reported")
