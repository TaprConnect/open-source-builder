import json,os,subprocess,sys,tempfile
def ok(*a):
    r=subprocess.run([sys.executable,"-m","osb_engine",*a],capture_output=True,text=True,timeout=1200); assert r.returncode==0,(a[:2],r.stderr[-800:]); return json.loads(r.stdout)
w=tempfile.mkdtemp(); t=os.path.join(w,"t"); p=os.path.join(w,"p"); os.mkdir(p,0o700)
files={"svc/__init__.py":"","svc/deps.py":"def get_current_user():\n    return 1\n\ndef get_db():\n    return None\n\noauth2_scheme = object()\n",
"svc/api.py":"from fastapi import APIRouter, Depends, Security\nfrom svc.deps import get_current_user, get_db, oauth2_scheme\nrouter = APIRouter()\n\n@router.post('/a')\ndef a(user=Depends(get_current_user)):\n    return {}\n\n@router.post('/b')\ndef b(token: str = Security(oauth2_scheme, scopes=['x'])):\n    return {}\n\n@router.post('/c')\ndef c(db=Depends(get_db)):\n    return {}\n"}
for k,v in files.items():
    os.makedirs(os.path.dirname(os.path.join(t,k)),exist_ok=True); open(os.path.join(t,k),"w").write(v)
g=lambda *a: subprocess.run(["git","-C",t,"-c","user.name=T","-c","user.email=t@i","-c","core.autocrlf=false",*a],check=True,capture_output=True)
g("init"); g("add","."); g("commit","-m","s")
got={c["path"]:c["auth"] for c in ok("index",t,os.path.join(p,"s.sqlite"))["completeness"]}
assert got=={"/a":"detected","/b":"detected","/c":"not_detected"},got
print("PASS dependency-injected authentication recognised; non-auth dependency not counted")
