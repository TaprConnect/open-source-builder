import json,os,subprocess,sys,tempfile
def run(*a):
    r=subprocess.run([sys.executable,"-m","osb_engine",*a],capture_output=True,text=True,timeout=1200); assert r.returncode==0,(a[:2],r.stderr[-800:]); return json.loads(r.stdout)
def repo(files):
    w=tempfile.mkdtemp(); t=os.path.join(w,"t"); p=os.path.join(w,"p"); os.mkdir(p,0o700)
    for k,v in files.items():
        os.makedirs(os.path.dirname(os.path.join(t,k)) or t,exist_ok=True); open(os.path.join(t,k),"w").write(v)
    g=lambda *a: subprocess.run(["git","-C",t,"-c","user.name=T","-c","user.email=t@i","-c","core.autocrlf=false",*a],check=True,capture_output=True)
    g("init"); g("add","."); g("commit","-m","s"); return t,os.path.join(p,"s.sqlite")
app=("from fastapi import APIRouter, Depends\nfrom jose import jwt\nfrom shop.auth import check_permissions\nfrom shop.store import db, save_order\n\nrouter = APIRouter()\nCART = set()\nSORT = {\"new\": \"created_at\", \"price\": \"price\"}\n\n\n"
 "@router.put(\"/orders/{oid}\", dependencies=[Depends(check_permissions)])\ndef update_order(oid: int):\n    save_order(oid)\n    return {}\n\n\n"
 "@router.post(\"/cart/{sku}\", dependencies=[Depends(check_permissions)])\ndef add_to_cart(sku: str):\n    CART.add(sku)\n    return {}\n\n\n"
 "@router.delete(\"/orders/{oid}\")\ndef cancel_order(oid: int):\n    raise NotImplementedError\n\n\n"
 "@router.get(\"/orders\")\ndef list_orders(sort: str = \"\"):\n    col = SORT.get(sort, \"created_at\")\n    rank = SORT[sort]\n    return db.execute(f\"SELECT * FROM orders ORDER BY {col}, {rank}\")\n\n\n"
 "@router.get(\"/search\")\ndef search(term: str = \"\"):\n    return db.execute(f\"SELECT * FROM orders WHERE note = '{term}'\")\n\n\n"
 "def decode(token):\n    return jwt.decode(token, \"k\")\n")
store="import sqlite3\n\ndb = sqlite3.connect(\"shop.db\")\n\n\ndef save_order(oid):\n    db.execute(\"update orders set seen = 1 where id = ?\", (oid,))\n    db.commit()\n"
cli=("import abc\n\nimport click\n\n\n@click.group()\ndef cli():\n    \"\"\"Shop admin commands.\"\"\"\n\n\nclass Job(abc.ABC):\n    @abc.abstractmethod\n    def run(self):\n        \"\"\"Run the job.\"\"\"\n\n\n"
 "def export_orders():\n    \"\"\"Export orders.\"\"\"\n\n\nsettings = {}\nsettings[\"client_secret\"] = \"Tq8-synthetic-subscript-55\"\nsettings[\"secret_label\"] = \"Rk2-synthetic-label-31\"\n")
files={"pyproject.toml":'[project]\nname="shop"\nversion="1"\ndependencies=["fastapi","click","python-jose[cryptography]"]\n',
 "shop/__init__.py":"","shop/auth.py":"def check_permissions():\n    return True\n","shop/store.py":store,"shop/app.py":app,"shop/cli.py":cli}
t,db=repo(files); by={c["domain"]:c for c in run("controls",t,db)["controls"]}
routes=lambda d:{v["route"] for v in by[d]["violations"] if "route" in v}
ident=routes("Identity"); assert ident=={"DELETE /orders/{oid}"},ident
pers=routes("Persistence"); assert pers=={"POST /cart/{sku}","DELETE /orders/{oid}"},pers
back={v.get("route") or v["file"]+":"+v["detail"].split()[-1] for v in by["Backend"]["violations"]}
assert back=={"DELETE /orders/{oid}","shop/app.py:cancel_order","shop/cli.py:export_orders"},back
web={(v["file"],v["detail"].split(" in ")[-1]) for v in by["WebDefences"]["violations"]}; assert web=={("shop/app.py","search")},web
assert by["SupplyChain"]["status"]=="no_static_violation",by["SupplyChain"]["violations"]
sec={(v["file"],v["name"]) for v in by["Secrets"]["violations"]}; assert sec=={("shop/cli.py","client_secret")},sec
print("MEASURE "+json.dumps({"identity":sorted(ident),"persistence":sorted(pers),"backend":sorted(back),"webdefences":sorted(map(list,web)),"secrets":sorted(map(list,sec)),"supplychain":by["SupplyChain"]["status"]}))
print("PASS holdout-exposed gaps fixed on fresh synthetic fixtures: route dependencies auth, unimplemented and set-mutating write routes, python-jose, framework/abstract docstring functions, subscript credentials, constant-map whitelists")