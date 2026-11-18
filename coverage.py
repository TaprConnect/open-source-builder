"""Compare private reviewer attestations to an independently rebuilt snapshot."""
import argparse
import json
from scanner import inventory


def assess(snapshot, ledger):
    if ledger["revision"] != snapshot["revision"]:
        raise ValueError("Ledger belongs to another revision")
    pending = []
    blocked = []
    files = {row["path"]: row for row in snapshot["files"]}
    unknown = set(ledger["files"]) - files.keys()
    if unknown:
        raise ValueError("Ledger contains unknown paths")
    for path, row in files.items():
        if row["status"] != "indexed":
            blocked.append({"path": path, "reason": row["status"]})
            continue
        cursor = 1
        for first, last in sorted(ledger["files"].get(path, [])):
            if type(first) is not int or type(last) is not int or not 1 <= first <= last <= row["lines"]:
                raise ValueError("Invalid line range for " + path)
            if first > cursor:
                pending.append([path, cursor, first - 1])
            cursor = max(cursor, last + 1)
        if cursor <= row["lines"]:
            pending.append([path, cursor, row["lines"]])
    return {"revision": snapshot["revision"], "unreviewed": pending, "blocked": blocked,
            "attested_coverage_complete": not pending and not blocked}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repository")
    parser.add_argument("ledger")
    args = parser.parse_args()
    with open(args.ledger, encoding="utf-8") as stream:
        result = assess(inventory(args.repository), json.load(stream))
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["attested_coverage_complete"] else 1)
