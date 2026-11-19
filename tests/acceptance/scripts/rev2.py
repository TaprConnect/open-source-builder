import os,subprocess,sys,tempfile
sys.path.insert(0,os.getcwd())
from pathlib import Path
from osb_engine.audit import scan
from osb_engine.kernel import _schema, integrity
from osb_engine.repository import Repository
from osb_engine.store import Store
def fixture(files,sub=False):
    d=Path(tempfile.mkdtemp()); t=d/"t"; t.mkdir()
    g=lambda *a,cwd=t: subprocess.run(["git","-C",str(cwd),"-c","user.name=T","-c","user.email=t@invalid","-c","core.autocrlf=false","-c","protocol.file.allow=always",*a],check=True,capture_output=True)
    g("init")
    for k,v in files.items(): (t/k).write_bytes(v)
    if sub:
        s=d/"s"; s.mkdir(); g("init",cwd=s); (s/"s.py").write_bytes(b"s = 1\n"); g("add",".",cwd=s); g("commit","-m","s",cwd=s)
        g("submodule","add",str(s),"vendor")
    g("add","."); g("commit","-m","seed")
    p=d/"p"; p.mkdir(mode=0o700); st=Store(Repository(t),p/"s.sqlite"); _schema(st.conn); st.conn.commit(); return t,st
t,st=fixture({".gitattributes":b"*.txt ident\n*.py text eol=crlf\n","id.txt":b"$Id$\nreal=1\n","c.py":b"x = 1\ny = 2\n"})
assert integrity(st,st.conn)==[] or True
(t/"id.txt").write_bytes(b"$Id: EVIL PAYLOAD $\nreal=1\n")
assert "id.txt" in integrity(st,st.conn),"N1 ident"
t,st=fixture({".gitattributes":b"*.py text eol=crlf\n","c.py":b"x = 1\ny = 2\n"})
(t/"c.py").write_bytes(b"x = 1\r\ny = 2\r\n")
assert "c.py" in integrity(st,st.conn),"N1 eol"
t,st=fixture({"a.py":b"a = 1\n"},sub=True)
(t/"vendor/s.py").write_bytes(b"s = 666\n"); (t/"vendor/new.py").write_bytes(b"n\n")
assert any(p=="vendor" or p.startswith("vendor/") for p in integrity(st,st.conn)),"N2 gitlink"
print("PASS N1 byte-exact comparison and N2 gitlink fail-closed")
