import json,os,subprocess,sys,tempfile
def ok(*a):
    r=subprocess.run([sys.executable,"-m","osb_engine",*a],capture_output=True,text=True,timeout=1200); assert r.returncode==0,(a[:2],r.stderr[-800:]); return json.loads(r.stdout)
w=tempfile.mkdtemp(); t=os.path.join(w,"t"); p=os.path.join(w,"p"); os.mkdir(p,0o700)
files={
"app/__init__.py":"",
"app/repo.py":"import sqlite3\n\ndef _conn():\n    return sqlite3.connect('db')\n\ndef save_order(order):\n    c = _conn()\n    c.execute('insert into orders values (?)', (1,))\n    c.commit()\n\ndef lookup():\n    return {'status': 'ok'}\n\ndef remove(order_id):\n    _conn().execute('delete from orders where id=?', (order_id,))\n",
"app/auth.py":"def login_required(f):\n    return f\n\ndef requires_role(name):\n    return lambda f: f\n",
"app/routes.py":"from flask import Flask\nfrom app import repo\nfrom app.auth import login_required, requires_role\napp = Flask(__name__)\n\n@app.post('/orders')\n@login_required\ndef create_order():\n    repo.save_order({})\n    return {}\n\n@app.post('/refunds')\ndef refund():\n    return repo.lookup()\n\n@app.delete('/orders/<id>')\n@requires_role('admin')\ndef delete_order(id):\n    repo.remove(id)\n    return {}\n",
}
for k,v in files.items():
    os.makedirs(os.path.dirname(os.path.join(t,k)),exist_ok=True); open(os.path.join(t,k),"w").write(v)
g=lambda *a: subprocess.run(["git","-C",t,"-c","user.name=T","-c","user.email=t@i","-c","core.autocrlf=false",*a],check=True,capture_output=True)
g("init"); g("add","."); g("commit","-m","s")
idx=ok("index",t,os.path.join(p,"s.sqlite"))
got={(c["path"],tuple(c["methods"])):(sorted(c["flags"]),c["auth"]) for c in idx["completeness"]}
truth={("/orders",("POST",)):(["untested"],"detected"),("/refunds",("POST",)):(["no_persistence","untested"],"not_detected"),("/orders/<id>",("DELETE",)):(["untested"],"detected")}
assert got==truth,got
s=idx["completeness_summary"]; assert s["routes"]==3 and "unsupported" in s["frontend_analysis"],s
print("PASS cross-module persistence and authentication evidence exact")
