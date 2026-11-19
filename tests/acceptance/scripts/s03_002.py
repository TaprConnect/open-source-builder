import copy,json,os,sys
sys.path.insert(0,os.getcwd())
from osb_engine import analysis,sandboxed
samples=[("python",b"import os as o\nfrom . import x\ndef f():\n    o.path.join(1)\n    try:\n        pass\n    except Exception:\n        pass\nclass C:\n    def m(self): pass\n"),
 ("python",b"def (:\n"),("node_manifest",b'{"name":"x","scripts":{"build":"tsc","test":""},"dependencies":{"a":"1"}}'),("node_manifest",b"{bad")]
real=[json.loads(json.dumps(list(analysis.analyse(k,d)))) for k,d in samples]
for r in real: assert sandboxed._valid(r),r
base=real[0]
def forged(fn):
    r=copy.deepcopy(base); fn(r[1]); return r
cases=[lambda b:b["symbols"][0].update(extra=1), lambda b:b["symbols"][0].pop("end"), lambda b:b["symbols"][0].update(line="3"),
 lambda b:b["imports"][0].update(level=-1), lambda b:b["imports"][0].update(module=["x"]), lambda b:b["calls"][0].update(resolution="syntactic_local"),
 lambda b:b["calls"][0].update(target="x"*5000), lambda b:b.update(facts={"evil":{"nested":[1]}}), lambda b:b.update(facts={"scripts":[1],"dependencies":[]}),
 lambda b:b["symbols"].append("str"), lambda b:b["imports"].append([1,2]), lambda b:b["findings"][0].update(line=-5)]
for i,c in enumerate(cases):
    assert not sandboxed._valid(forged(c)),i
print("PASS element-level schema: real outputs accepted, forged elements rejected")
