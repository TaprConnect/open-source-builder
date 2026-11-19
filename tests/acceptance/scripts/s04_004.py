import json,os,subprocess,sys,tempfile
def ok(*a):
    r=subprocess.run([sys.executable,"-m","osb_engine",*a],capture_output=True,text=True,timeout=1200); assert r.returncode==0,(a[:2],r.stderr[-800:]); return json.loads(r.stdout)
w=tempfile.mkdtemp(); t=os.path.join(w,"t"); p=os.path.join(w,"p"); os.mkdir(p,0o700)
files={
"app/__init__.py":"",
"app/items.py":"import sqlite3\nfrom flask import Flask\napp = Flask(__name__)\n\ndef db():\n    return sqlite3.connect('app.db')\n\n@app.get('/items')\ndef list_items():\n    return db().execute('select * from items').fetchall()\n\n@app.post('/items')\ndef create_item():\n    conn = db()\n    conn.execute('insert into items values (1)')\n    conn.commit()\n    return {}\n\n@app.delete('/items/<id>')\ndef delete_item(id):\n    raise NotImplementedError\n",
"app/notes.py":"from flask import Flask\napp = Flask(__name__)\nNOTES = []\n\n@app.post('/notes')\ndef add_note():\n    NOTES.append({'text': 'x'})\n    return {}\n\n@app.put('/profile')\ndef update_profile():\n    return {'ok': True}\n",
"tests/test_items.py":"from app import items\n\ndef test_list():\n    assert items.list_items is not None\n\nclass TestItems:\n    def test_create(self):\n        assert True\n",
}
for k,v in files.items():
    os.makedirs(os.path.dirname(os.path.join(t,k)),exist_ok=True); open(os.path.join(t,k),"w").write(v)
g=lambda *a: subprocess.run(["git","-C",t,"-c","user.name=T","-c","user.email=t@i","-c","core.autocrlf=false",*a],check=True,capture_output=True)
g("init"); g("add","."); g("commit","-m","s")
idx=ok("index",t,os.path.join(p,"s.sqlite"))
got={(c["path"],tuple(c["methods"])):sorted(c["flags"]) for c in idx["completeness"]}
truth={("/items",("GET",)):[],("/items",("POST",)):[],("/notes",("POST",)):["in_memory_persistence","untested"],("/profile",("PUT",)):["no_persistence","untested"],("/items/<id>",("DELETE",)):["unimplemented"]}
assert got==truth,got
dead={d["symbol"] for d in idx["dead_code_candidates"]}
assert not ({"test_list","TestItems"} & dead),dead
print("PASS completeness graph flags exact; test functions excluded from dead code")
