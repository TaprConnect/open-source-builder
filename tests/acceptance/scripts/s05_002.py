import json,os,subprocess,sys,tempfile
def run(*a):
    r=subprocess.run([sys.executable,"-m","osb_engine",*a],capture_output=True,text=True,timeout=1200); assert r.returncode==0,(a[:2],r.stderr[-800:]); return r.stdout
def repo(files):
    w=tempfile.mkdtemp(); t=os.path.join(w,"t"); p=os.path.join(w,"p"); os.mkdir(p,0o700)
    for k,v in files.items():
        os.makedirs(os.path.dirname(os.path.join(t,k)) or t,exist_ok=True); open(os.path.join(t,k),"w").write(v)
    g=lambda *a: subprocess.run(["git","-C",t,"-c","user.name=T","-c","user.email=t@i","-c","core.autocrlf=false",*a],check=True,capture_output=True)
    g("init"); g("add","."); g("commit","-m","s"); return t,os.path.join(p,"s.sqlite")
STATIC={"Persistence","Identity","Backend","Reliability","SupplyChain","Quality","WebDefences","Architecture","Secrets","Configuration","Observability"}
VALUES=["Qv7-fixture-db-credential-93","Mw4-fixture-api-credential-58","Pk2-fixture-kw-credential-17","Hb8-fixture-env-credential-62"]
core=("import logging\nimport os\n\nlog = logging.getLogger(__name__)\n"
 "DB_PASSWORD = \"%s\"\nSETTINGS = {\"api_key\": \"%s\"}\n\n\ndef make(**kw):\n    return kw\n\n\ndef connect():\n    return make(user=\"svc\", password=\"%s\")\n\n\n"
 "STRIPE = os.environ[\"STRIPE_KEY\"]\nREDIS = os.getenv(\"REDIS_URL\")\nDB = os.environ[\"DATABASE_URL\"]\nPORT = os.environ.get(\"PORT\", \"8000\")\nTOKEN = os.environ[\"API_TOKEN\"]\n"
 "password_field = \"password\"\napi_key = \"changeme-later\"\nSECRET_KEY = \"\"\n\n\n"
 "def charge():\n    try:\n        return connect()\n    except Exception as exc:\n        return {\"error\": str(exc)}, 500\n\n\n"
 "def charge_logged():\n    try:\n        return connect()\n    except Exception:\n        log.exception(\"charge failed\")\n        return {\"error\": \"failed\"}, 500\n\n\n"
 "def charge_reraise():\n    try:\n        return connect()\n    except Exception:\n        raise\n\n\n"
 "def parse(v):\n    try:\n        return int(v)\n    except ValueError:\n        return None\n") % tuple(VALUES[:3])
defects={"app/__init__.py":"","app/core.py":core,
 ".env.example":"DATABASE_URL=\nAPI_TOKEN=your-token-here\nSECRET_KEY=change-me\n",
 ".env":"SECRET_KEY=%s\nDEBUG=true\nAPI_TOKEN=\n" % VALUES[3]}
t,db=repo(defects)
out=run("controls",t,db); res=json.loads(out)
by={c["domain"]:c for c in res["controls"]}
assert len(res["controls"])==66 and all(c["status"]!="pass" for c in res["controls"])
assert {d for d,c in by.items() if c["support"]=="static"}==STATIC
assert all(c["status"]=="unsupported" for d,c in by.items() if d not in STATIC)
sec={(v["file"],v["name"]) for v in by["Secrets"]["violations"]}
assert by["Secrets"]["status"]=="violation" and sec=={("app/core.py","DB_PASSWORD"),("app/core.py","api_key"),("app/core.py","password"),(".env","SECRET_KEY")},sec
assert all(v.get("line") for v in by["Secrets"]["violations"])
cfg={v["name"] for v in by["Configuration"]["violations"]}
assert by["Configuration"]["status"]=="violation" and cfg=={"STRIPE_KEY","REDIS_URL"},cfg
assert all(v["file"]=="app/core.py" for v in by["Configuration"]["violations"])
obs=by["Observability"]["violations"]
assert by["Observability"]["status"]=="violation" and [(v["file"],v["function"]) for v in obs]==[("app/core.py","charge")],obs
idx=run("index",t,db+"i")
for value in VALUES:
    assert value not in out and value not in idx,"credential value leaked into output"
clean={"pyproject.toml":'[project]\nname="c"\nversion="1"\ndependencies=["flask"]\n',"svc/__init__.py":"","svc/util.py":"def add(a, b):\n    return a + b\n","tests/test_util.py":"from svc import util\n\ndef test_add():\n    assert util.add(1, 2) == 3\n"}
t2,db2=repo(clean); by2={c["domain"]:c for c in json.loads(run("controls",t2,db2))["controls"]}
assert not any(by2[d]["status"]=="violation" for d in STATIC),{d:by2[d]["status"] for d in STATIC}
assert by2["Configuration"]["status"]=="not_applicable"
print("MEASURE "+json.dumps({"secrets":sorted(map(list,sec)),"configuration":sorted(cfg),"observability":len(obs),"safe_variants_unflagged":{"secrets":5,"configuration":3,"observability":3},"clean":{d:by2[d]["status"] for d in ("Secrets","Configuration","Observability")}}))
print("PASS secrets, configuration and observability evaluators: exact true positives, safe variants unflagged, no value leakage")