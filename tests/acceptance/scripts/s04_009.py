import json,os,subprocess,sys,tempfile
def ok(*a):
    r=subprocess.run([sys.executable,"-m","osb_engine",*a],capture_output=True,text=True,timeout=1200); assert r.returncode==0,(a[:2],r.stderr[-800:]); return json.loads(r.stdout)
w=tempfile.mkdtemp(); t=os.path.join(w,"t"); p=os.path.join(w,"p"); os.mkdir(p,0o700)
src='''import os, sqlite3, subprocess
from flask import Flask, request, send_file
app = Flask(__name__)
db = sqlite3.connect("x")

@app.get("/search")
def search():
    term = request.args.get("q")
    query = "select * from items where name = '%s'" % term
    return db.execute(query).fetchall()

@app.get("/search-safe")
def search_safe():
    term = request.args.get("q")
    return db.execute("select * from items where name = ?", (term,)).fetchall()

@app.post("/ping/<host>")
def ping(host):
    cmd = "ping -c1 " + host
    return subprocess.run(cmd, shell=True).returncode

@app.post("/ping-safe/<host>")
def ping_safe(host):
    return subprocess.run(["ping", "-c1", host]).returncode

@app.get("/download")
def download():
    name = request.args["file"]
    return send_file(os.path.join("/srv/files", name))

@app.get("/download-safe")
def download_safe():
    name = os.path.basename(request.args["file"])
    return open(os.path.join("/srv/files", name)).read()

@app.post("/calc")
def calc():
    expr = request.get_json()["expr"]
    return str(eval(expr))

@app.post("/calc-safe")
def calc_safe():
    n = int(request.form["n"])
    return str(eval("1 + %d" % n))
'''
os.makedirs(os.path.join(t,"web")); open(os.path.join(t,"web","__init__.py"),"w").write(""); open(os.path.join(t,"web","app.py"),"w").write(src)
g=lambda *a: subprocess.run(["git","-C",t,"-c","user.name=T","-c","user.email=t@i","-c","core.autocrlf=false",*a],check=True,capture_output=True)
g("init"); g("add","."); g("commit","-m","s")
idx=ok("index",t,os.path.join(p,"s.sqlite"))
got={(f["function"],f["kind"]) for f in idx["taint"]}
assert got=={("search","sql_injection"),("ping","command_injection"),("download","path_traversal"),("calc","code_injection")},got
assert all(f["file"]=="web/app.py" and f["line"]>0 for f in idx["taint"])
print("PASS intraprocedural taint: four true sinks found, four safe variants not flagged")
