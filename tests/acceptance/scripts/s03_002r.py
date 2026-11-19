import json,os,sys,sysconfig
sys.path.insert(0,os.getcwd())
from osb_engine import analysis,sandboxed
total=rejected=0
for dp,_,fs in os.walk(sysconfig.get_paths()["stdlib"]):
    for f in fs:
        if f.endswith(".py") and os.path.isfile(os.path.join(dp,f)):
            total+=1
            v=json.loads(json.dumps(list(analysis.analyse("python",open(os.path.join(dp,f),"rb").read()))))
            rejected+=not sandboxed._valid(v)
assert total>300 and rejected==0,(total,rejected)
good=["analysed",{"symbols":[],"imports":[],"calls":[{"caller":"f","target":None,"line":1,"resolution":"unresolved"}],"findings":[],"facts":{}}]
assert sandboxed._valid(good)
for bad in ({"caller":"f","target":5,"line":1,"resolution":"unresolved"},{"caller":None,"target":"x","line":1,"resolution":"unresolved"},{"caller":"f","target":"x"*5000,"line":1,"resolution":"unresolved"}):
    assert not sandboxed._valid(["analysed",{**good[1],"calls":[bad]}]),bad
print("PASS schema accepts all %d stdlib analyses and still rejects forged call elements"%total)
