import json,os,subprocess,sys,tempfile
def ok(*a):
    r=subprocess.run([sys.executable,"-m","osb_engine",*a],capture_output=True,text=True,timeout=1200); assert r.returncode==0,(a[:2],r.stderr[-800:]); return json.loads(r.stdout)
w=tempfile.mkdtemp(); t=os.path.join(w,"t"); p=os.path.join(w,"p"); os.mkdir(p,0o700)
files={
"app/__init__.py":"",
"app/api.py":"import os\nfrom flask import Flask\napp = Flask(__name__)\nDB = os.environ['DATABASE_URL']\n\n@app.get('/users')\ndef list_users():\n    return []\n\n@app.route('/users', methods=['POST'])\ndef create_user():\n    return {}\n\n@app.delete('/users/<id>')\ndef delete_user(id):\n    pass\n",
"app/urls.py":"from django.urls import path\n\ndef order_list(request):\n    return None\n\nurlpatterns = [path('orders/', order_list)]\n",
"app/service.py":"import os\n\nSECRET = os.getenv('SECRET_KEY')\n\ndef export_csv():\n    raise NotImplementedError\n\ndef compute(x):\n    return x + 1\n",
"app/store.py":"import os\n\ndef save(item):\n    try:\n        return item.write()\n    except Exception:\n        pass\n\ndef load(path):\n    try:\n        return open(path).read()\n    except:\n        return None\n\nDEBUG = os.environ.get('DEBUG', '0')\n",
"tests/test_service.py":"from app import service\n\ndef test_compute():\n    assert service.compute(1) == 2\n",
}
for k,v in files.items():
    os.makedirs(os.path.dirname(os.path.join(t,k)),exist_ok=True); open(os.path.join(t,k),"w").write(v)
g=lambda *a: subprocess.run(["git","-C",t,"-c","user.name=T","-c","user.email=t@i","-c","core.autocrlf=false",*a],check=True,capture_output=True)
g("init"); g("add","."); g("commit","-m","s")
idx=ok("index",t,os.path.join(p,"s.sqlite"))
routes={(r["path"],tuple(r["methods"]),r["function"]) for r in idx["routes"]}
assert routes=={("/users",("GET",),"list_users"),("/users",("POST",),"create_user"),("/users/<id>",("DELETE",),"delete_user"),("orders/",("ANY",),"order_list")},routes
assert idx["environment"]=={"DATABASE_URL":["app/api.py"],"DEBUG":["app/store.py"],"SECRET_KEY":["app/service.py"]},idx["environment"]
issues={(i["path"],i["kind"],i["function"]) for i in idx["issues"]}
assert issues=={("app/api.py","placeholder","delete_user"),("app/service.py","not_implemented","export_csv"),("app/store.py","swallowed_exception","save"),("app/store.py","bare_except","load")},issues
assert idx["tests"]=={"app/service.py":["tests/test_service.py"]},idx["tests"]
assert idx["untested_sources"]==["app/api.py","app/store.py","app/urls.py"],idx["untested_sources"]
print("PASS routes, environment, implementation issues and test mapping exact on ground truth")
