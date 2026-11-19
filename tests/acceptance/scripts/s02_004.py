import json,os,sqlite3,subprocess
from pathlib import Path
def invoke(*args,token=None):
 return subprocess.run(["python3","-m","osb_engine",*args],text=True,input=token,capture_output=True,timeout=30)
def ok(*args,token=None):
 r=invoke(*args,token=token); assert r.returncode==0,(args,r.stderr); return json.loads(r.stdout)
def deny(*args,token=None):
 r=invoke(*args,token=token); assert r.returncode==2 and "Command blocked" in r.stderr,(args,r.returncode,r.stdout,r.stderr)
p=Path("/tmp/private-m");p.mkdir(mode=0o700); db=str(p/"store.sqlite")
outside=Path("/tmp/outside");outside.mkdir()
repo=Path("/tmp/target");repo.mkdir()
def git(*args): return subprocess.run(["git","-C",str(repo),"-c","user.name=T","-c","user.email=t@invalid",*args],check=True,capture_output=True,text=True).stdout
git("init")
(repo/"a.py").write_text("def a(): pass\n");(repo/"b.py").write_text("def b(): pass\n");(repo/"src").mkdir();(repo/"src/s.py").write_text("x = 1\n")
os.symlink("/tmp/outside",repo/"lnk")
git("add",".");git("commit","-m","seed")
base=[str(repo),db]; plan=ok("plan",*base)["run_id"]; a=ok("status",*base,plan)["tasks"][0]["id"]
lease=ok("reserve",*base,plan,a,"300"); g,t=str(lease["generation"]),lease["token"]
ok("grant",*base,plan,a,g,"--operation","edit","a.py","src/","lnk/","c.py","--operation","delete","b.py")
pd=Path("/tmp/private-m")
def patch(name,text):
 f=pd/name; f.write_text(text); return str(f)
def snap():
 return git("status","--porcelain=v1","--untracked-files=all"),{q:q.read_bytes() for q in repo.rglob("*") if q.is_file() and ".git" not in q.parts}
M=lambda f:("mutate",*base,plan,a,g,f)
def rows():
 c=sqlite3.connect("file:"+db+"?mode=ro",uri=True)
 try: return c.execute("SELECT COUNT(*) FROM kernel_dispatches_v1").fetchone()[0]
 finally: c.close()
edit=patch("edit.patch","--- a/a.py\n+++ b/a.py\n@@ -1 +1 @@\n-def a(): pass\n+def a(): return 1\n")
ok(*M(edit),token=t)
assert (repo/"a.py").read_text()=="def a(): return 1\n" and rows()==1
create=patch("create.patch","--- /dev/null\n+++ b/src/new.py\n@@ -0,0 +1 @@\n+y = 2\n")
ok(*M(create),token=t); assert (repo/"src/new.py").exists() and rows()==2
before=snap()
for name,text in [("unc.patch","--- /dev/null\n+++ b/d.py\n@@ -0,0 +1 @@\n+z\n"),
 ("mixed.patch","--- /dev/null\n+++ b/c.py\n@@ -0,0 +1 @@\n+c\n--- /dev/null\n+++ b/d.py\n@@ -0,0 +1 @@\n+d\n"),
 ("kind.patch","--- a/a.py\n+++ /dev/null\n@@ -1 +0,0 @@\n-def a(): return 1\n"),
 ("rename.patch","diff --git a/src/s.py b/src/t.py\nsimilarity index 100%\nrename from src/s.py\nrename to src/t.py\n"),
 ("link.patch","diff --git a/src/l b/src/l\nnew file mode 120000\n--- /dev/null\n+++ b/src/l\n@@ -0,0 +1 @@\n+/etc/passwd\n\\ No newline at end of file\n"),
 ("through.patch","--- /dev/null\n+++ b/lnk/x.py\n@@ -0,0 +1 @@\n+escape\n")]:
 deny(*M(patch(name,text)),token=t)
assert snap()==before and rows()==2 and not (outside/"x.py").exists()
deny(*M(edit),token="wrong")
ok(*M(patch("del.patch","--- a/b.py\n+++ /dev/null\n@@ -1 +0,0 @@\n-def b(): pass\n")),token=t)
assert not (repo/"b.py").exists() and rows()==3
(repo/"src/s.py").write_text("x = 999\n")
deny(*M(patch("e2.patch","--- a/src/new.py\n+++ b/src/new.py\n@@ -1 +1 @@\n-y = 2\n+y = 3\n")),token=t)
deny("dispatch",*base,plan,a,g,"edit","a.py",token=t)
(repo/"src/s.py").write_text("x = 1\n")
(repo/"stray.txt").write_text("unrecorded\n")
deny(*M(patch("e3.patch","--- a/src/new.py\n+++ b/src/new.py\n@@ -1 +1 @@\n-y = 2\n+y = 3\n")),token=t)
(repo/"stray.txt").unlink()
ok(*M(patch("e4.patch","--- a/src/new.py\n+++ b/src/new.py\n@@ -1 +1 @@\n-y = 2\n+y = 3\n")),token=t)
assert rows()==4
ok("pause",*base,"--reason","hold")
deny(*M(patch("e5.patch","--- a/src/new.py\n+++ b/src/new.py\n@@ -1 +1 @@\n-y = 3\n+y = 4\n")),token=t)
ok("resume",*base,"--reason","go")
ok("revoke",*base,plan,a,g,"--reason","stop")
deny(*M(str(pd/"e5.patch")),token=t)
assert (repo/"src/new.py").read_text()=="y = 3\n" and rows()==4
print("PASS mediated apply, scope and kind, rename/symlink/through-link denial, out-of-band detection, pause and revocation")
