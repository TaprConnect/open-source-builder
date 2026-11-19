import json,os,subprocess,sys,tempfile
def run(*a):
    r=subprocess.run([sys.executable,"-m","osb_engine",*a],capture_output=True,text=True,timeout=1200); assert r.returncode==0,(a[:2],r.stderr[-800:]); return json.loads(r.stdout)
def repo(files):
    w=tempfile.mkdtemp(); t=os.path.join(w,"t"); p=os.path.join(w,"p"); os.mkdir(p,0o700)
    for k,v in files.items():
        os.makedirs(os.path.dirname(os.path.join(t,k)) or t,exist_ok=True); open(os.path.join(t,k),"w").write(v)
    g=lambda *a: subprocess.run(["git","-C",t,"-c","user.name=T","-c","user.email=t@i","-c","core.autocrlf=false",*a],check=True,capture_output=True)
    g("init"); g("add","."); g("commit","-m","s"); return t,os.path.join(p,"s.sqlite")
settings=("REFRESH_TOKEN = \"demo-refresh-value\"\nSIGNING_SECRET = \"dev.local.only\"\nBROKER_PASSWORD = \"Lq5-synthetic-broker-72\"\n")
web=("import cv2\nimport psycopg2\nimport ujson\nfrom aiohttp import web\n\nroutes = web.RouteTableDef()\n\n\n"
 "@routes.get(\"/parcels/{pid}\")\nasync def parcel(request):\n    conn = request.app[\"db\"]\n    return await conn.fetchrow(f\"SELECT * FROM parcels WHERE id = {request.match_info['pid']}\")\n\n\n"
 "@routes.get(\"/parcels\")\nasync def parcels(request):\n    conn = request.app[\"db\"]\n    return await conn.fetchval(\"SELECT count(*) FROM parcels WHERE owner = $1\", request.query.get(\"owner\"))\n\n\n"
 "@routes.get(\"/proxy\")\nasync def proxy(request):\n    target = request.query.get(\"url\")\n    return await request.app[\"http\"].fetch(target)\n\n\n"
 "def decode(blob):\n    return ujson.loads(blob), cv2.imdecode, psycopg2.connect\n")
accounts=("from flask import Flask\nfrom flask_login import login_user\nfrom acct.models import User, db, require_login\n\napp = Flask(__name__)\n\n\n"
 "@app.post(\"/signup\")\ndef signup():\n    user = User()\n    user.set_password(\"x\")\n    db.session.add(user)\n    db.session.commit()\n    login_user(user)\n    return \"\", 201\n\n\n"
 "@app.post(\"/profile\")\ndef profile():\n    user = require_login()\n    db.session.add(user)\n    db.session.commit()\n    return \"\", 204\n")
models=("from flask_sqlalchemy import SQLAlchemy\n\ndb = SQLAlchemy()\n\n\nclass User(db.Model):\n    def set_password(self, raw):\n        self.hash = raw\n\n\ndef require_login():\n    return User()\n")
files={"requirements.txt":"aiohttp\nflask\nflask-login\nflask-sqlalchemy\npsycopg2-binary\nopencv-python-headless\n",
 "acct/__init__.py":"","acct/settings.py":settings,"acct/web.py":web,"acct/accounts.py":accounts,"acct/models.py":models}
t,db=repo(files); by={c["domain"]:c for c in run("controls",t,db)["controls"]}
sec={(v["file"],v["name"]) for v in by["Secrets"]["violations"]}; assert sec=={("acct/settings.py","BROKER_PASSWORD")},sec
sup={v["detail"].split()[-1] for v in by["SupplyChain"]["violations"]}; assert sup=={"ujson"},sup
wd={(v["file"],v["detail"].split(" in ")[-1]) for v in by["WebDefences"]["violations"]}; assert wd=={("acct/web.py","parcel")},wd
ident={v["route"] for v in by["Identity"]["violations"]}; assert ident=={"POST /signup"},ident
print("MEASURE "+json.dumps({"secrets":sorted(map(list,sec)),"supplychain":sorted(sup),"webdefences":sorted(map(list,wd)),"identity":sorted(ident)}))
print("PASS holdout-2 gaps fixed on fresh synthetic fixtures: word-like literals, multi-distribution imports, asyncpg fetch sinks, credential-issuing calls are not auth")