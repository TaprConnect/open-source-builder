import json,os,subprocess,sys,tempfile
def ok(*a):
    r=subprocess.run([sys.executable,"-m","osb_engine",*a],capture_output=True,text=True,timeout=1200); assert r.returncode==0,(a[:2],r.stderr[-800:]); return json.loads(r.stdout)
def repo(files):
    w=tempfile.mkdtemp(); t=os.path.join(w,"t"); p=os.path.join(w,"p"); os.mkdir(p,0o700)
    for k,v in files.items():
        os.makedirs(os.path.dirname(os.path.join(t,k)) or t,exist_ok=True); open(os.path.join(t,k),"w").write(v)
    g=lambda *a: subprocess.run(["git","-C",t,"-c","user.name=T","-c","user.email=t@i","-c","core.autocrlf=false",*a],check=True,capture_output=True)
    g("init"); g("add","."); g("commit","-m","s"); return t,os.path.join(p,"s.sqlite")
SUPPORTED={"Persistence","Identity","Backend","Reliability","SupplyChain","Quality","WebDefences","Architecture"}
defects={"requirements.txt":"flask\n","app/__init__.py":"","app/a.py":"from app import b\n\ndef fa():\n    return b\n","app/b.py":"from app import a\n\ndef fb():\n    return a\n",
 "app/web.py":"import sqlite3\nimport redis\nfrom flask import Flask, request\napp = Flask(__name__)\nNOTES = []\ndb = sqlite3.connect('x')\n\n@app.post('/notes')\ndef add():\n    NOTES.append(request.json)\n    return {}\n\n@app.get('/find')\ndef find():\n    return db.execute('select %s' % request.args['q']).fetchall()\n\n@app.delete('/notes/<id>')\ndef remove(id):\n    raise NotImplementedError\n\ndef load():\n    try:\n        return open('x').read()\n    except Exception:\n        pass\n"}
t,db=repo(defects); res=ok("controls",t,db)
by={c["domain"]:c for c in res["controls"]}
assert len(by)==66 and len(res["controls"])==66
fields={"id","domain","family","applicability","static_evaluator","runtime_evaluator","evidence","required_outcome","severity","remediation","support","status","violations"}
assert all(fields<=set(c) for c in res["controls"]),[sorted(fields-set(c)) for c in res["controls"]][:1]
assert all(c["status"]!="pass" for c in res["controls"])
STATIC=SUPPORTED|{"Secrets","Configuration","Observability"}
assert {d for d,c in by.items() if c["support"]=="static"}==STATIC
assert all(c["status"]=="unsupported" for d,c in by.items() if d not in STATIC)
for d in SUPPORTED:
    assert by[d]["status"]=="violation" and by[d]["violations"] and all(v.get("file") for v in by[d]["violations"]),(d,by[d])
clean={"pyproject.toml":'[project]\nname="c"\nversion="1"\ndependencies=["flask"]\n',"svc/__init__.py":"","svc/util.py":"def add(a, b):\n    return a + b\n","tests/test_util.py":"from svc import util\n\ndef test_add():\n    assert util.add(1, 2) == 3\n"}
t2,db2=repo(clean); res2=ok("controls",t2,db2)
by2={c["domain"]:c for c in res2["controls"]}
assert not any(by2[d]["status"]=="violation" for d in SUPPORTED),{d:by2[d]["status"] for d in SUPPORTED}
assert by2["Persistence"]["status"]=="not_applicable" and by2["Identity"]["status"]=="not_applicable"
print("MEASURE "+json.dumps({"defects":{d:by[d]["status"] for d in SUPPORTED},"clean":{d:by2[d]["status"] for d in SUPPORTED},"summary":res["summary"]}))
print("PASS control framework: 66 declared controls, 8 executable static evaluators, no pass claims, unsupported reported")
