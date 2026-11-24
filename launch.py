"""Plan and validate an evidence dossier against the installed control catalogue."""
import argparse
import csv
import hashlib
import json
from pathlib import Path

from scanner import inventory

CATALOGUE = Path(__file__).parent / "profiles" / "checks.tsv"


def plan(root):
    snapshot = inventory(root)
    catalogue = CATALOGUE.read_bytes()
    rules = list(csv.DictReader(catalogue.decode().splitlines(), delimiter="\t"))
    controls = {row["domain"]: {**row, "status": "not_performed", "reason": "",
                                "receipt": None} for row in rules}
    if len(controls) != len(rules):
        raise ValueError("duplicate control ID")
    return {"schema": 1, "revision": snapshot["revision"],
            "catalogue_sha256": hashlib.sha256(catalogue).hexdigest(), "controls": controls}


def evaluate(root, dossier, ledger, evidence_dir):
    from coverage import assess
    baseline = plan(root)
    for key in ("revision", "schema", "catalogue_sha256"):
        if baseline[key] != dossier[key]:
            raise ValueError("stale or incompatible " + key)
    if set(baseline["controls"]) != set(dossier["controls"]):
        raise ValueError("control IDs differ from the catalogue")
    snapshot = inventory(root)
    if snapshot["revision"] != baseline["revision"]:
        raise ValueError("revision changed during assessment")
    coverage = assess(snapshot, ledger)
    open_controls = []
    accepted = 0
    directory = Path(evidence_dir).resolve(strict=True)
    for name, required in baseline["controls"].items():
        record = dossier["controls"][name]
        if any(record[key] != required[key] for key in ("domain", "activates_when", "evidence", "required_outcome")):
            raise ValueError("control definition changed: " + name)
        status = record["status"]
        if status not in {"pass", "fail", "blocked", "unknown", "not_performed", "not_applicable"}:
            raise ValueError("invalid status for " + name)
        if status not in {"pass", "not_applicable"}:
            open_controls.append({"control": name, "status": status})
            continue
        if not isinstance(record["reason"], str) or not record["reason"].strip():
            raise ValueError("missing rationale for " + name)
        evidence = record["receipt"]
        path = (directory / evidence["path"]).resolve(strict=True)
        if not path.is_relative_to(directory) or not path.is_file():
            raise ValueError("evidence outside private evidence directory")
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != evidence["sha256"]:
            raise ValueError("evidence hash changed for " + name)
        receipt = json.loads(raw)
        for key, expected in {"control": name, "revision": baseline["revision"], "status": status}.items():
            if receipt[key] != expected:
                raise ValueError("receipt mismatch: " + name)
        for key in ("reviewer", "environment", "observation"):
            if not isinstance(receipt[key], str) or not receipt[key].strip():
                raise ValueError("missing receipt field: " + key)
        accepted += status == "pass"
    return {"revision": baseline["revision"], "open_controls": open_controls, "coverage": coverage,
            "dossier_complete": accepted > 0 and not open_controls and coverage["attested_coverage_complete"],
            "assurance": "Validates reviewer attestations and referenced bytes; deployment status independently required."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    sub.add_parser("plan").add_argument("repository")
    check = sub.add_parser("check")
    for arg in ("repository", "dossier", "ledger", "evidence_dir"):
        check.add_argument(arg)
    args = parser.parse_args()
    if args.mode == "plan":
        print(json.dumps(plan(args.repository), indent=2))
        return 0
    try:
        dossier, ledger = [json.loads(Path(p).read_bytes()) for p in (args.dossier, args.ledger)]
        result = evaluate(args.repository, dossier, ledger, args.evidence_dir)
    except (OSError, KeyError, ValueError, TypeError) as error:
        parser.exit(2, f"Invalid dossier: {error}\n")
    print(json.dumps(result, indent=2))
    return 0 if result["dossier_complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
