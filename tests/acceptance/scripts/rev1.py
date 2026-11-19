import os,subprocess,sys,tempfile
sys.path.insert(0,os.getcwd())
from pathlib import Path
from osb_engine.audit import scan
from osb_engine.kernel import grant,reserve,renew,pause,resume,integrity
from osb_engine.mutation import mutate
from osb_engine import completion
from osb_engine.repository import Repository
from osb_engine.store import Store
def fixture(files):
    d=Path(tempfile.mkdtemp()); t=d/"t"; t.mkdir()
    g=lambda *a: subprocess.run(["git","-C",str(t),"-c","user.name=T","-c","user.email=t@invalid","-c","core.autocrlf=false",*a],check=True,capture_output=True)
    g("init")
    for k,v in files.items():
        (t/k).parent.mkdir(parents=True,exist_ok=True); (t/k).write_bytes(v)
    g("add","."); g("commit","-m","s"); __import__("time").sleep(1.5); g("update-index","--refresh")
    p=d/"p"; p.mkdir(mode=0o700); s=Store(Repository(t),p/"s.sqlite")
    rep,_=scan(s.repo,s,[]); run=s.save(rep); task=rep["findings"][0]["id"]
    l=reserve(s,run,task,300); return t,s,run,task,l["generation"],l["token"]
def refused(fn):
    try: fn()
    except ValueError: return True
    return False
# F1
t,s,run,task,g,tok=fixture({"a.py":b"def a(): pass\n","keep.py":b"KEEP = 1\n"})
grant(s,run,task,g,[("edit",["a.py"])])
st=os.stat(t/"keep.py"); (t/"keep.py").write_bytes(b"KEEP = 2\n"); os.utime(t/"keep.py",ns=(st.st_atime_ns,st.st_mtime_ns))
assert "keep.py" in integrity(s,s.conn),"F1 stat-cache bypass"
acc=b"pass\n"; completion.freeze(s,run,task,acc)
assert refused(lambda: completion.verify(s,run,task,g,acc)) or not completion.verify(s,run,task,g,acc)["passed"]
assert refused(lambda: completion.complete(s,run,task,g,tok)),"F1 complete"
# F2
t,s,run,task,g,tok=fixture({"a.py":b"def a(): pass\n"})
grant(s,run,task,g,[("delete",["a.py"])])
p=b"--- a/a.py\n+++ /dev/null\n@@ -1 +0,0 @@\n-def a(): pass\n--- /dev/null\n+++ b/a.py\n@@ -0,0 +1 @@\n+evil = 1\n"
assert refused(lambda: mutate(s,run,task,g,tok,p)),"F2 replace via delete grant"
assert (t/"a.py").read_bytes()==b"def a(): pass\n"
# F3
t,s,run,task,g,tok=fixture({"a.py":b"def a(): pass\n","src/x.py":b"x = 1\n"})
grant(s,run,task,g,[("edit",["src/"])])
assert refused(lambda: mutate(s,run,task,g,tok,b"--- /dev/null\n+++ b/src/.gitignore\n@@ -0,0 +1 @@\n+*\n")),"F3 kernel ignore file"
(t/".git/info/exclude").write_text("hidden.py\n"); (t/"hidden.py").write_text("x\n")
assert "hidden.py" in integrity(s,s.conn),"F3 ignored untracked file hidden"
(t/"hidden.py").unlink()
# F4
t,s,run,task,g,tok=fixture({"a.py":b"def a(): pass\ndef b(): pass\n"})
acc=b"pass\n"; completion.freeze(s,run,task,acc); pause(s,"stop")
assert refused(lambda: completion.verify(s,run,task,g,acc)),"F4 verify while paused"
renew(s,run,task,g,60,tok)
other=[r["id"] for r in s.view(run)["tasks"] if r["id"]!=task]
resume(s,"go")
# F5
if os.name=="posix":
    t,s,run,task,g,tok=fixture({"a.py":b"def a(): pass\n","b.py":b"b = 1\n"})
    grant(s,run,task,g,[("edit",["a.py"])])
    mutate(s,run,task,g,tok,b"--- a/a.py\n+++ b/a.py\n@@ -1 +1 @@\n-def a(): pass\n+def a(): return 1\n")
    os.chmod(t/"a.py",0o755); assert "a.py" in integrity(s,s.conn),"F5 ledger mode"
    os.chmod(t/"a.py",0o644); os.chmod(t/"b.py",0o755); assert "b.py" in integrity(s,s.conn),"F5 tracked mode"
    os.chmod(t/"b.py",0o644); assert integrity(s,s.conn)==[]
    pause(s,"stop"); assert refused(lambda: reserve(s,run,task,60)); resume(s,"go")
print("PASS review findings F1-F5 closed")
