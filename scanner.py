"""Inventory immutable Git blobs; never execute code from the reviewed tree."""
import argparse
import json
import os
import re
import subprocess

MAX_BYTES = 8 * 1024 * 1024
MARKERS = re.compile(r"\b(?:TODO|FIXME|NotImplementedError)\b")


def git(root, *args):
    return subprocess.check_output(["git", "-C", root, *args])


def inventory(root):
    revision = git(root, "rev-parse", "--verify", "HEAD^{commit}").decode().strip()
    rows = []
    objects = {}
    for entry in git(root, "ls-tree", "-rlz", revision).split(b"\0"):
        if not entry:
            continue
        header, path = entry.split(b"\t", 1)
        mode, kind, oid, size = header.split()
        row = {"path": os.fsdecode(path), "oid": oid.decode()}
        rows.append(row)
        if kind != b"blob" or mode == b"120000":
            row["status"] = "submodule" if kind != b"blob" else "symlink"
            continue
        if int(size) > MAX_BYTES:
            row["status"] = "oversized"
            continue
        if oid not in objects:
            data = git(root, "cat-file", "blob", oid.decode())
            try:
                source = data.decode("utf-8")
            except UnicodeDecodeError:
                source = None
            if source is None or "\0" in source:
                objects[oid] = {"status": "binary-or-unsupported"}
            else:
                lines = source.split("\n")
                if lines[-1] == "":
                    lines.pop()
                objects[oid] = {
                    "status": "indexed",
                    "lines": len(lines),
                    "marker_lines": [i for i, line in enumerate(lines, 1) if MARKERS.search(line)],
                }
        row.update(objects[oid])
    return {"revision": revision, "semantic_review": "not_performed", "files": rows}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repository")
    parser.add_argument("--private-route", action="append", default=[], help="Committed handler path requiring authentication")
    parser.add_argument("--durable-route", action="append", default=[], help="Committed handler path promising durable writes")
    parser.add_argument("--include-manifest-patches", action="store_true", help="Include manifest source context in private report")
    args = parser.parse_args()
    from readiness import review
    report = inventory(args.repository)
    report["readiness"] = review(report["files"], lambda oid: git(args.repository, "cat-file", "blob", oid),
                                 args.private_route, args.durable_route, args.include_manifest_patches)
    print(json.dumps(report, indent=2))
