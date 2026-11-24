"""Validate a justified patch against an isolated Git index before optional application."""
import argparse
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path

from scanner import git


def validate_and_apply(root, patch, manifest, apply=False, allow_remove=False):
    root = Path(root).resolve()
    if git(root, "rev-parse", "--show-prefix").strip() or git(root, "status", "--porcelain"):
        raise ValueError("use a clean checkout at its root")
    head = git(root, "rev-parse", "--verify", "HEAD").decode().strip()
    digest = hashlib.sha256(patch).hexdigest()
    if manifest["revision"] != head or manifest["patch_sha256"] != digest:
        raise ValueError("revision or patch digest mismatch")
    declarations = manifest["changes"]
    with tempfile.TemporaryDirectory() as tmp:
        env = {**os.environ, "GIT_INDEX_FILE": str(Path(tmp) / "index")}
        def staged(*args, data=None):
            return subprocess.run(["git", "-C", str(root), *args], input=data, env=env,
                                  capture_output=True, check=True).stdout
        staged("read-tree", head)
        staged("apply", "--cached", "--whitespace=error", "-", data=patch)
        raw = staged("diff", "--cached", "--no-renames", "--raw", "-z", head)
    fields = raw.rstrip(b"\0").split(b"\0") if raw else []
    changes = {}
    for header, path_bytes in zip(fields[::2], fields[1::2]):
        old_mode, new_mode, _, _, kind = header.lstrip(b":").split()
        if {old_mode, new_mode} - {b"100644", b"100755", b"000000"}:
            raise ValueError("special file changes require manual review")
        action = {b"A": "add", b"M": "modify", b"D": "remove"}.get(kind)
        if not action:
            raise ValueError("unsupported change type")
        path = os.fsdecode(path_bytes)
        changes[path] = action
    if not changes or set(changes) != set(declarations):
        raise ValueError("every changed path must have exactly one declaration")
    for path, action in changes.items():
        row = declarations[path]
        if row["action"] != action:
            raise ValueError("incorrect action: " + path)
        for key in ("justification", "acceptance", "rollback"):
            if not isinstance(row[key], str) or not row[key].strip():
                raise ValueError("missing " + key + " for " + path)
        if apply and action == "remove" and not allow_remove:
            raise ValueError("removal requires explicit approval and --allow-remove")
    if apply:
        if git(root, "rev-parse", "HEAD").decode().strip() != head:
            raise ValueError("target revision changed")
        # --index checks the index and working file agree before changing either.
        subprocess.run(["git", "-C", str(root), "apply", "--index", "--whitespace=error", "-"],
                       input=patch, check=True)
    return {"revision": head, "patch_sha256": digest, "changes": changes,
            "applied_to_index_and_worktree": apply, "verification": "not_performed"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for arg in ("repository", "patch", "manifest"):
        parser.add_argument(arg)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--allow-remove", action="store_true")
    args = parser.parse_args()
    try:
        result = validate_and_apply(args.repository, Path(args.patch).read_bytes(),
                                    json.loads(Path(args.manifest).read_bytes()), args.apply, args.allow_remove)
    except (KeyError, TypeError, ValueError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(2, f"Change rejected: {error}\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
