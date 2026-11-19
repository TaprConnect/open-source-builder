import json,os,subprocess,sys,tempfile
def ok(*a):
    r=subprocess.run([sys.executable,"-m","osb_engine",*a],capture_output=True,text=True,timeout=1200); assert r.returncode==0,(a[:2],r.stderr[-800:]); return json.loads(r.stdout)
REPOS={
"shop":{"files":{
 "pyproject.toml":'[project]\nname="shop"\nversion="1"\ndependencies=["flask","sqlalchemy"]\n',
 "shop/__init__.py":"","shop/models.py":"class Product:\n    pass\n",
 "shop/db.py":"from sqlalchemy.orm import Session\n\nclass ProductRepository:\n    def __init__(self, session):\n        self.session = session\n\n    def add(self, product):\n        self.session.add(product)\n        self.session.commit()\n\n    def all(self):\n        return self.session.query('p').all()\n",
 "shop/security.py":"def login_required(f):\n    return f\n",
 "shop/views.py":"from flask import Blueprint\nfrom shop.db import ProductRepository\nfrom shop.security import login_required\nfrom shop.models import Product\nbp = Blueprint('shop', __name__)\nrepo = ProductRepository(None)\n\n@bp.route('/products', methods=['GET'])\ndef products():\n    return repo.all()\n\n@bp.route('/products', methods=['POST'])\n@login_required\ndef create_product():\n    repo.add(Product())\n    return {}\n\n@bp.route('/cart', methods=['POST'])\ndef add_to_cart():\n    CART.append(1)\n    return {}\n\nCART = []\n\n@bp.route('/checkout', methods=['POST'])\n@login_required\ndef checkout():\n    pass\n",
 "shop/reports.py":"import pandas\n\ndef monthly_report():\n    return pandas.DataFrame()\n",
 "tests/test_views.py":"from shop import views\n\ndef test_products():\n    assert views.products\n"},
 "truth":{"unimplemented":{"/checkout POST"},"no_persistence":set(),"in_memory_persistence":{"/cart POST"},"untested":set(),
  "auth_not_detected":{"/cart POST"},"missing_dependency":{"pandas"},"import_cycle":set(),"dead_code":{"shop/reports.py:monthly_report"}}},
"api":{"files":{
 "requirements.txt":"fastapi\nasyncpg\n",
 "api/__init__.py":"","api/store.py":"import asyncpg\nfrom api import service\n\nasync def insert_user(conn, user):\n    await conn.execute('insert', user)\n",
 "api/service.py":"from api import store\n\ndef normalise(name):\n    return name.strip()\n",
 "api/auth.py":"def verify_token(token):\n    return True\n",
 "api/routes.py":"from fastapi import APIRouter\nfrom api import store\nfrom api.auth import verify_token\nrouter = APIRouter()\n\n@router.post('/users')\nasync def create_user(user: dict):\n    verify_token('x')\n    await store.insert_user(None, user)\n    return user\n\n@router.put('/users/{uid}')\nasync def update_user(uid: int):\n    return {'uid': uid}\n\n@router.get('/health')\nasync def health():\n    return {'ok': True}\n"},
 "truth":{"unimplemented":set(),"no_persistence":{"/users/{uid} PUT"},"in_memory_persistence":set(),"untested":{"/users POST","/users/{uid} PUT","/health GET"},
  "auth_not_detected":{"/users/{uid} PUT"},"missing_dependency":set(),"import_cycle":{"api/service.py|api/store.py"},"dead_code":{"api/service.py:normalise"}}},
"blog":{"files":{
 "requirements.txt":"django\n",
 "blog/__init__.py":"","blog/views.py":"from django.contrib.auth.decorators import login_required\nfrom blog.models import Post\n\n@login_required\ndef post_create(request):\n    Post().save()\n\ndef post_list(request):\n    return Post.objects.all()\n\ndef post_delete(request, pk):\n    raise NotImplementedError\n",
 "blog/models.py":"class Post:\n    def save(self):\n        pass\n",
 "blog/urls.py":"from django.urls import path\nfrom blog import views\nurlpatterns = [path('posts/new/', views.post_create), path('posts/', views.post_list), path('posts/<pk>/delete/', views.post_delete)]\n",
 "blog/tests/test_views.py":"from blog import views\n\ndef test_list():\n    assert views.post_list\n"},
 "truth":{"unimplemented":{"posts/<pk>/delete/ ANY"},"no_persistence":set(),"in_memory_persistence":set(),"untested":{"posts/new/ ANY","posts/ ANY","posts/<pk>/delete/ ANY"},
  "auth_not_detected":set(),"missing_dependency":set(),"import_cycle":set(),"dead_code":set()}},
}
TYPES=["unimplemented","no_persistence","in_memory_persistence","untested","auth_not_detected","missing_dependency","import_cycle","dead_code"]
WRITES={"POST","PUT","PATCH","DELETE"}
def observed(idx):
    o={k:set() for k in TYPES}
    for c in idx["completeness"]:
        key=f"{c['path']} {'/'.join(c['methods'])}"
        for f in c["flags"]: o[f].add(key)
        if c["auth"]=="not_detected" and set(c["methods"])&WRITES: o["auth_not_detected"].add(key)
    o["missing_dependency"]={m["module"] for m in idx["missing_dependencies"]}
    o["import_cycle"]={"|".join(sorted(c)) for c in idx["graph"]["cycles"]}
    o["dead_code"]={f"{d['path']}:{d['symbol']}" for d in idx["dead_code_candidates"]}
    return o
counts={k:{"tp":0,"fp":0,"fn":0} for k in TYPES}; details={}
for name,spec in REPOS.items():
    w=tempfile.mkdtemp(); t=os.path.join(w,"t"); p=os.path.join(w,"p"); os.mkdir(p,0o700)
    for k,v in spec["files"].items():
        os.makedirs(os.path.dirname(os.path.join(t,k)) or t,exist_ok=True); open(os.path.join(t,k),"w").write(v)
    g=lambda *a: subprocess.run(["git","-C",t,"-c","user.name=T","-c","user.email=t@i","-c","core.autocrlf=false",*a],check=True,capture_output=True)
    g("init"); g("add","."); g("commit","-m","s")
    o=observed(ok("index",t,os.path.join(p,"s.sqlite")))
    for k in TYPES:
        truth=spec["truth"][k]; got=o[k]
        counts[k]["tp"]+=len(truth&got); counts[k]["fp"]+=len(got-truth); counts[k]["fn"]+=len(truth-got)
        if truth!=got: details.setdefault(name,{})[k]={"missed":sorted(truth-got),"extra":sorted(got-truth)}
report={}
for k,c in counts.items():
    pr=c["tp"]/(c["tp"]+c["fp"]) if c["tp"]+c["fp"] else 1.0; rc=c["tp"]/(c["tp"]+c["fn"]) if c["tp"]+c["fn"] else 1.0
    report[k]={"precision":round(pr,3),"recall":round(rc,3),**c}
print("MEASURE "+json.dumps({"per_type":report,"mismatches":details}))
assert all(v["precision"]>=0.9 and v["recall"]>=0.9 for v in report.values()),(report,details)
print("PASS I01 acceptance: per-type precision and recall >= 0.9 on three realistic repositories")
