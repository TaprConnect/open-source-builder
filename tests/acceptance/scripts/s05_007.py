import json,os,subprocess,sys,tempfile
def run(*a):
    r=subprocess.run([sys.executable,"-m","osb_engine",*a],capture_output=True,text=True,timeout=1200); assert r.returncode==0,(a[:2],r.stderr[-800:]); return json.loads(r.stdout)
def repo(files):
    w=tempfile.mkdtemp(); t=os.path.join(w,"t"); p=os.path.join(w,"p"); os.mkdir(p,0o700)
    for k,v in files.items():
        os.makedirs(os.path.dirname(os.path.join(t,k)) or t,exist_ok=True); open(os.path.join(t,k),"w").write(v)
    g=lambda *a: subprocess.run(["git","-C",t,"-c","user.name=T","-c","user.email=t@i","-c","core.autocrlf=false",*a],check=True,capture_output=True)
    g("init"); g("add","."); g("commit","-m","s"); return t,os.path.join(p,"s.sqlite")
views=("import hmac\nfrom flask import Flask, request\nfrom flask_login import login_user\nfrom portal.store import db, Member, verify_signature\n\napp = Flask(__name__)\n\n\n"
 "@app.route(\"/sign-in\", methods=[\"GET\", \"POST\"])\ndef sign_in():\n    member = Member.query.first()\n    if member and member.check_password(request.form[\"pw\"]):\n        login_user(member)\n        db.session.commit()\n    return \"\"\n\n\n"
 "@app.post(\"/hooks/billing\")\ndef billing_hook():\n    if not hmac.compare_digest(request.headers[\"X-Sig\"], \"s\"):\n        return \"\", 401\n    db.session.commit()\n    return \"\"\n\n\n"
 "@app.post(\"/hooks/shipping\")\ndef shipping_hook():\n    verify_signature(request.data)\n    db.session.commit()\n    return \"\"\n\n\n"
 "@app.post(\"/feedback\")\ndef feedback():\n    login_user(Member())\n    db.session.commit()\n    return \"\", 202\n")
store=("from flask_sqlalchemy import SQLAlchemy\n\ndb = SQLAlchemy()\n\n\nclass Member(db.Model):\n    def check_password(self, raw):\n        return raw == self.pw\n\n\ndef verify_signature(body):\n    return bool(body)\n")
files={"requirements.txt":"flask\nflask-login\nflask-sqlalchemy\n","portal/__init__.py":"","portal/views.py":views,"portal/store.py":store}
t,db=run_repo=repo(files); by={c["domain"]:c for c in run("controls",t,db)["controls"]}
ident={v["route"] for v in by["Identity"]["violations"]}
assert ident=={"POST /feedback"},ident
print("MEASURE "+json.dumps({"identity":sorted(ident)}))
print("PASS credential-verifying calls count as authentication evidence; credential-issuing calls alone do not")