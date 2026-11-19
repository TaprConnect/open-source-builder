import json,os,subprocess,sys,tempfile,time
sys.path.insert(0,os.getcwd())
from pathlib import Path
def cli(*a): return subprocess.run([sys.executable,"-m","osb_engine",*a],capture_output=True,text=True,timeout=300)
def ok(*a):
    r=cli(*a); assert r.returncode==0,(a,r.stderr); return json.loads(r.stdout)
def blocked(*a):
    r=cli(*a); assert r.returncode==2 and "Command blocked" in r.stderr,(a,r.stdout,r.stderr); return r.stderr
w=Path(tempfile.mkdtemp())
g=lambda cwd,*a: subprocess.run(["git","-C",str(cwd),"-c","user.name=T","-c","user.email=t@invalid","-c","core.autocrlf=false","-c","protocol.file.allow=always",*a],check=True,capture_output=True)
sub=w/"sub"; sub.mkdir(); g(sub,"init"); (sub/"s.py").write_bytes(b"s = 1\n"); g(sub,"add","."); g(sub,"commit","-m","s"); (sub/"s.py").write_bytes(b"s = 2\n"); g(sub,"commit","-am","s2")
t=w/"t"; t.mkdir(); g(t,"init"); (t/"a.py").write_bytes(b"def a(): pass\n"); (t/"build").mkdir(); (t/"build/keep.txt").write_bytes(b"k\n")
g(t,"submodule","add",str(sub),"vendor"); g(t,"add","."); g(t,"commit","-m","seed")
p=w/"p"; p.mkdir(mode=0o700); base=[str(t),str(p/"s.sqlite")]
plan=ok("plan",*base)["run_id"]; task=ok("status",*base,plan)["tasks"][0]["id"]
def free():
    r=cli("reserve",*base,plan,task,"60")
    if r.returncode==0:
        ok("release",*base,plan,task,str(json.loads(r.stdout)["generation"]),"--reason","probe"); return True
    assert "Command blocked" in r.stderr,r.stderr; return False
assert free(),"clean submodule must pass"
(t/"vendor/s.py").write_bytes(b"s = 666\n"); assert not free(); (t/"vendor/s.py").write_bytes(b"s = 2\n"); assert free()
(t/"vendor/new.py").write_bytes(b"n\n"); assert not free(); (t/"vendor/new.py").unlink(); assert free()
g(t/"vendor","checkout","-q","HEAD~1"); assert not free(); g(t/"vendor","checkout","-q","-"); assert free()
(t/"build/out.o").write_bytes(b"obj"); assert not free()
for bad in ("../x/","/abs/",".git/","build","sub/.git/",""): blocked("configure",*base,"--exclude",bad)
ok("configure",*base,"--exclude","build/"); assert free()
(t/"other.o").write_bytes(b"x"); assert not free(); (t/"other.o").unlink()
(t/"build/keep.txt").write_bytes(b"tampered\n"); assert not free(); (t/"build/keep.txt").write_bytes(b"k\n")
ok("configure",*base,"--clear-excludes"); assert not free(); (t/"build/out.o").unlink(); assert free()
big=w/"big"; big.mkdir(); g(big,"init")
for i in range(3000): (big/f"f{i:04d}.txt").write_bytes((b"line %d\n" % i)*16)
g(big,"add","."); g(big,"commit","-m","big")
bp=w/"bp"; bp.mkdir(mode=0o700); bb=[str(big),str(bp/"s.sqlite")]
bplan=ok("plan",*bb)["run_id"]; btask=ok("status",*bb,bplan)["tasks"][0]["id"] if ok("status",*bb,bplan)["tasks"] else None
sys.path.insert(0,os.getcwd())
from osb_engine.kernel import worktree_changes
from osb_engine.repository import Repository
start=time.perf_counter(); assert worktree_changes(Repository(big))==set(); cost=time.perf_counter()-start
print(json.dumps({"files":3000,"full_check_seconds":round(cost,3)}))
assert cost<60
print("PASS verified submodules, scoped untracked exclusions, tracked files always compared, measured cost")
