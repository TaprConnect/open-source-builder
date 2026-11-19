import base64,json,os,subprocess,sys,tempfile
sys.path.insert(0,os.getcwd())
from pathlib import Path
from osb_engine import completion
from osb_engine.audit import scan
from osb_engine.kernel import _schema,grant,journal_path,recover,reserve,worktree_changes
from osb_engine.repository import Repository
from osb_engine.store import Store
def fixture(files,attrs=None):
    w=Path(tempfile.mkdtemp()); t=w/"t"; t.mkdir()
    g=lambda *a: subprocess.run(["git","-C",str(t),"-c","user.name=T","-c","user.email=t@invalid","-c","core.autocrlf=false",*a],check=True,capture_output=True)
    g("init")
    for k,v in files.items(): (t/k).write_bytes(v)
    g("add","."); g("commit","-m","s")
    p=w/"p"; p.mkdir(mode=0o700); st=Store(Repository(t),p/"s.sqlite"); _schema(st.conn); st.conn.commit()
    return w,t,st
def refused(fn):
    try: fn()
    except ValueError: return True
    return False
# F1
w,t,st=fixture({"a.py":b"import os,re\nm=re.search(rb'OSB_VERIFY_NONCE=([0-9a-f]+)',open('/proc/self/environ','rb').read())\nif m:\n    print('\\nOSB-VERIFY-PASS '+m.group(1).decode(), flush=True); os._exit(0)\n","b.py":b"def b(): pass\n"})
rep,_=scan(st.repo,st,[]); run=st.save(rep); task=rep["findings"][0]["id"] if rep["findings"] else None
if task is None:
    (t/"c.py").write_bytes(b"def c(): pass\n")
l=reserve(st,run,task,600)
acc=b"import sys\nsys.path.insert(0,'/work')\nimport a\nassert False\n"
completion.freeze(st,run,task,acc)
assert completion.verify(st,run,task,l["generation"],acc)["passed"] is False,"F1 nonce leak"
# F2
w,t,st=fixture({"a.py":b"a = 1\n"})
victim=w/"victim.txt"; victim.write_bytes(b"safe\n")
jp=journal_path(st)
def journal(paths): Path(jp).write_text(json.dumps({"op":"x"*32,"project":os.path.normcase(str(st.repo.common)),"paths":paths}))
journal({"../victim.txt":{"data":base64.b64encode(b"PWNED\n").decode(),"mode":420}})
assert refused(lambda: recover(st)) and victim.read_bytes()==b"safe\n","F2a traversal"
os.unlink(jp)
out=w/"outside"; out.mkdir(); os.symlink(out,t/"d")
journal({"d/f.txt":{"data":base64.b64encode(b"x").decode(),"mode":420}})
assert refused(lambda: recover(st)) and not (out/"f.txt").exists(),"F2b symlink parent"
os.unlink(jp); os.unlink(t/"d")
v2=w/"victim2.txt"; v2.write_bytes(b"safe\n")
for name in os.listdir(t):
    pass
os.symlink(v2,t/"a.py.osb-restore")
journal({"a.py":{"data":base64.b64encode(b"a = 9\n").decode(),"mode":420}})
try: recover(st)
except ValueError: pass
assert v2.read_bytes()==b"safe\n","F2c planted temp symlink"
# F3
w,t,st=fixture({"a.py":b"def a(): pass\ndef b(): pass\n"})
rep,_=scan(st.repo,st,[]); run=st.save(rep); task=rep["findings"][0]["id"]
st.transition(run,task,0,"investigating","r"); st.transition(run,task,1,"proposed","r")
assert refused(lambda: reserve(st,run,task,60)),"F3 proposed reserve"
# F5
oid=lambda data,t: subprocess.run(["git","-C",str(t),"hash-object","--stdin"],input=data,capture_output=True,check=True).stdout.decode().strip()
blob=b"# $Id$\n# $Id$\n"
w,t,st=fixture({"a.py":blob,".gitattributes":b"*.py ident\n"})
o=oid(blob,t); (t/"a.py").write_bytes(b"# $Id: "+o.encode()+b" $\n# $Id$\n")
assert "a.py" in worktree_changes(st.repo),"F5 partial ident"
blob2=b"x = '$Id$'\n"
w,t,st=fixture({"a.py":blob2})
o=oid(blob2,t); (t/"a.py").write_bytes(b"x = '$Id: "+o.encode()+b" $'\n")
assert "a.py" in worktree_changes(st.repo),"F5 ident without attribute"
(t/"a.py").write_bytes(blob2)
# F6
(t/"build").write_bytes(b"not a dir\n")
assert "build" in worktree_changes(st.repo,"none",("build/",)),"F6 exclusion name match"
print("PASS certification findings F1 F2 F3 F5 F6 closed")
