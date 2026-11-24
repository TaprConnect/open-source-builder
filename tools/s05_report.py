"""Compute the Stage 05 holdout evidence from frozen ground truth, assurance outputs and recorded verdicts."""
import json, sys
sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent.parent))
from pathlib import Path
from osb_engine.assurance import DOMAINS
from osb_engine.controls import catalogue

ev = Path(sys.argv[1] if len(sys.argv) > 1 else "evidence/s05")
truth = json.loads((ev / "holdout_ground_truth.json").read_text())
verdicts = json.loads((ev / "holdout_verdicts.json").read_text())
report = {"stage": "S05", "certified": False, "projects": {}, "coverage": {}, "blockers": []}
for project, spec in truth["projects"].items():
    name = project.split("/")[1]
    out = json.loads((ev / f"holdout_{name}.assure.json").read_text())["assurance"]
    res = json.loads((ev / f"holdout_{name}.resources.json").read_text())
    ids = [d["id"] for d in spec["defects"]]
    got = {i: verdicts["detections"][i] for i in ids}
    modelled = [d["id"] for d in spec["defects"] if d["modelled"]]
    tp = sum(v == "TP" for v in got.values())
    findings = [f for f in verdicts["reported_security_findings"] if f["project"] == name]
    ftp = sum(f["verdict"] == "TP" for f in findings)
    report["projects"][project] = {
        "commit": spec["commit"], "summary": out["summary"], "resources": res,
        "recall_documented": {"tp": tp, "n": len(ids), "value": round(tp / len(ids), 3)},
        "recall_modelled": {"tp": sum(got[i] == "TP" for i in modelled), "n": len(modelled),
                            "value": round(sum(got[i] == "TP" for i in modelled) / len(modelled), 3) if modelled else None},
        "unverified": [i for i, v in got.items() if v == "unverified"],
        "false_negatives": [i for i, v in got.items() if v == "FN"],
        "precision_reviewed_sample": {"tp": ftp, "n": len(findings), "value": round(ftp / len(findings), 3) if findings else None},
        "false_positives": [f["where"] + ": " + f["why"] for f in findings if f["verdict"] == "FP"]}
rows = catalogue(Path("profiles/checks.tsv"))
static = [d[0] for d in DOMAINS if d[4]]
runtime = [d[0] for d in DOMAINS if d[5]]
neither = [d[0] for d in DOMAINS if not d[4] and not d[5]]
report["coverage"] = {"domains": len(rows), "static_evaluator": len(static), "runtime_adapter": len(runtime),
                      "no_executable_evaluator": neither, "static_domains": static}
report["blockers"] = ["Runtime adapters cannot install dependencies (isolated runs have no network), so most real projects' tests are blocked.",
                      "Security passes need owner-frozen external acceptance per project; none exist for the holdout projects.",
                      "Precision is from a reviewed sample by the implementing agent, not an independent reviewer.",
                      "Unmodelled categories: NoSQL injection, XSS, XXE, open redirect, prototype pollution, deserialization, SSRF, CVE scanning.",
                      "JavaScript hard-coded credentials are not extracted (nodejs-goof G6 missed)."]
print(json.dumps(report, indent=1))
