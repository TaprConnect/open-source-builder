import json,os,subprocess,sys,tempfile
def ok(*a):
    r=subprocess.run([sys.executable,"-m","osb_engine",*a],capture_output=True,text=True,timeout=1200); assert r.returncode==0,(a[:2],r.stderr[-800:]); return json.loads(r.stdout)
w=tempfile.mkdtemp(); t=os.path.join(w,"t"); p=os.path.join(w,"p"); os.mkdir(p,0o700)
files={"pyproject.toml":'[project]\nname = "demo"\nversion = "1"\ndependencies = ["requests>=2", "PyYAML"]\n',
 "requirements-dev.txt":"pytest==8.0  # tests\n-r other.txt\n",
 "pkg/__init__.py":"","pkg/main.py":"import os\nimport requests\nimport yaml\nimport numpy as np\nfrom pkg import util\n",
 "pkg/util.py":"import pytest\n"}
for k,v in files.items():
    os.makedirs(os.path.dirname(os.path.join(t,k)) or t,exist_ok=True); open(os.path.join(t,k),"w").write(v)
g=lambda *a: subprocess.run(["git","-C",t,"-c","user.name=T","-c","user.email=t@i","-c","core.autocrlf=false",*a],check=True,capture_output=True)
g("init"); g("add","."); g("commit","-m","s")
idx=ok("index",t,os.path.join(p,"s.sqlite"))
cls=idx["graph"]["external_classified"]
assert cls=={"os":"stdlib","requests":"declared","yaml":"declared","pytest":"declared","numpy":"undeclared"},cls
assert idx["missing_dependencies"]==[{"module":"numpy","files":["pkg/main.py"]}],idx["missing_dependencies"]
assert idx["summary"]["imports"]==6 and idx["summary"]["resolution_rate"]==round(5/6,4),idx["summary"]
print("PASS external imports classified honestly: stdlib, declared, undeclared")
