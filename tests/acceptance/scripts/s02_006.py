import json,os,subprocess,sys,tempfile
from pathlib import Path
assert os.name=="nt"
def cli(*a):
    return subprocess.run([sys.executable,"-m","osb_engine",*a],capture_output=True,text=True,timeout=60)
def icacls(p,*a): subprocess.run(["icacls",str(p),*a],check=True,capture_output=True)
w=Path(tempfile.mkdtemp())
repo=w/"t"; repo.mkdir()
git=lambda *a: subprocess.run(["git","-C",str(repo),"-c","user.name=T","-c","user.email=t@invalid","-c","core.autocrlf=false",*a],check=True,capture_output=True)
git("init"); (repo/"a.py").write_bytes(b"def a(): pass\n"); git("add","."); git("commit","-m","s")
def store_dir(name):
    d=w/name; d.mkdir(); return d
ok=store_dir("ok"); r=cli("plan",str(repo),str(ok/"s.sqlite")); assert r.returncode==0,r.stderr
for name,sid in (("everyone","*S-1-1-0:(R)"),("users","*S-1-5-32-545:(RX)")):
    d=store_dir(name); icacls(d,"/grant",sid)
    r=cli("plan",str(repo),str(d/"s.sqlite")); assert r.returncode==2 and "Command blocked" in r.stderr,(name,r.stdout,r.stderr)
    assert not (d/"s.sqlite").exists(),name
f=store_dir("file"); r=cli("plan",str(repo),str(f/"s.sqlite")); assert r.returncode==0
icacls(f/"s.sqlite","/grant","*S-1-5-11:(R)")
r=cli("plan",str(repo),str(f/"s.sqlite")); assert r.returncode==2 and "Command blocked" in r.stderr,r.stderr
dn=store_dir("deny"); icacls(dn,"/deny","*S-1-5-32-546:(W)")
r=cli("plan",str(repo),str(dn/"s.sqlite")); assert r.returncode==0,r.stderr
print("PASS Windows store ACL: owner/SYSTEM/Administrators only; Everyone, Users and Authenticated Users refused; deny ACEs ignored")
