import json,os,sqlite3,subprocess,sys,tempfile,time
sys.path.insert(0,os.getcwd())
def cli(*a): return subprocess.run([sys.executable,"-m","osb_engine",*a],capture_output=True,text=True,timeout=600)
def ok(*a):
    r=cli(*a); assert r.returncode==0,(a,r.stderr[-600:]); return json.loads(r.stdout)
w=tempfile.mkdtemp(); t=os.path.join(w,"t"); os.mkdir(t); p=os.path.join(w,"p"); os.mkdir(p,0o700); db=os.path.join(p,"s.sqlite")
g=lambda *a: subprocess.run(["git","-C",t,"-c","user.name=T","-c","user.email=t@i","-c","core.autocrlf=false",*a],check=True,capture_output=True)
for i in range(4): open(os.path.join(t,"m%d.py"%i),"wb").write(("def f%d():\n    pass\n"%i).encode())
open(os.path.join(t,"bomb.py"),"wb").write(b"x = [" + b"1," * 900000 + b"]\n")
g("init"); g("add","."); g("commit","-m","s")
L=["--analysis-cpu","2","--analysis-memory","96"]
def entries():
    c=sqlite3.connect(db)
    try: return c.execute("SELECT key,payload,payload_sha256,last_used_ns FROM engine_cache_v2 ORDER BY key").fetchall()
    finally: c.close()
first=ok("plan",t,db,*L); assert first["metrics"]["cache_misses"]==5 and first["metrics"]["cache_hits"]==0,first["metrics"]
assert len(entries())==4,"failed analysis must not be cached"
second=ok("plan",t,db,*L); assert second["metrics"]["cache_hits"]==4 and second["metrics"]["cache_misses"]==1,second["metrics"]
assert second["report"]["files"]==first["report"]["files"] and second["report"]["findings"]==first["report"]["findings"]
third=ok("plan",t,db,"--analysis-cpu","3","--analysis-memory","96"); assert third["metrics"]["cache_hits"]==0,third["metrics"]
from osb_engine.audit import scan
from osb_engine.controls import catalogue
from osb_engine.repository import Repository
from osb_engine.store import Store
with Store(Repository(t),db) as st:
    _,m=scan(st.repo,st,catalogue(os.path.join("profiles","checks.tsv")))
assert m["cache_hits"]==0,m
ok("cache-clear",t,db); ok("plan",t,db,*L)
c=sqlite3.connect(db); k=c.execute("SELECT key FROM engine_cache_v2 ORDER BY key").fetchall()
c.execute("UPDATE engine_cache_v2 SET payload=replace(payload,'function','klass') WHERE key=?",k[0])
bad=json.dumps(["analysed",{"symbols":[],"imports":[],"calls":[],"findings":[{"rule":1}],"facts":{}}],sort_keys=True,separators=(",",":"))
import hashlib
c.execute("UPDATE engine_cache_v2 SET payload=?, payload_sha256=? WHERE key=?",(bad,hashlib.sha256(bad.encode()).hexdigest(),k[1][0])); c.commit(); c.close()
fourth=ok("plan",t,db,*L)
assert fourth["report"]["files"]==first["report"]["files"] and fourth["report"]["findings"]==first["report"]["findings"]
assert fourth["metrics"]["cache_corrupt"]>=2,fourth["metrics"]
ok("cache-clear",t,db); assert entries()==[]
ok("plan",t,db,*L,"--cache-max-entries","2"); assert len(entries())==2
c=sqlite3.connect(db); c.execute("UPDATE engine_cache_v2 SET last_used_ns=1"); c.commit(); c.close()
ok("audit",t,db,*L,"--cache-retention-days","1","--cache-max-entries","1000")
assert all(e[3]>1 for e in entries()),"expired entries must be evicted before reuse"
print("PASS bounded keyed cache: reuse, invalidation by limits and trust, corruption and schema rejection, entry limit, retention, no failed results, clear")
