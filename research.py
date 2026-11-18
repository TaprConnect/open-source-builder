"""Return the next unread committed source range from a private coverage ledger."""
import argparse
import json
from pathlib import Path

from coverage import assess
from scanner import git, inventory


def next_range(root, ledger=None, max_lines=100, max_chars=12000):
    if max_lines < 1 or max_chars < 1:
        raise ValueError("positive range limits required")
    snapshot = inventory(root)
    if ledger is None:
        ledger = {"revision": snapshot["revision"], "files": {}}
    gaps = assess(snapshot, ledger)
    result = {"revision": snapshot["revision"], "blocked": gaps["blocked"],
              "attested_coverage_complete": gaps["attested_coverage_complete"], "range": None}
    if not gaps["unreviewed"]:
        return result
    path, first, end = gaps["unreviewed"][0]
    oid = next(row["oid"] for row in snapshot["files"] if row["path"] == path)
    lines = git(root, "cat-file", "blob", oid).decode().split("\n")
    selected = []
    chars = 0
    for index in range(first - 1, min(end, first - 1 + max_lines)):
        line = lines[index]
        if chars + len(line) + 1 > max_chars:
            if not selected:
                result["oversized_line"] = {"path": path, "line": first, "characters": len(line)}
            break
        selected.append(line)
        chars += len(line) + 1
    if selected:
        result["range"] = {"path": path, "blob": oid, "first": first,
                           "last": first + len(selected) - 1, "lines": selected}
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repository")
    parser.add_argument("--ledger", type=Path)
    parser.add_argument("--max-lines", type=int, default=100)
    parser.add_argument("--max-chars", type=int, default=12000)
    args = parser.parse_args()
    ledger = json.loads(args.ledger.read_bytes()) if args.ledger else None
    print(json.dumps(next_range(args.repository, ledger, args.max_lines, args.max_chars), indent=2))
