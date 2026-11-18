"""Preview or apply supported package-script repairs to a clean checkout."""
import argparse
import subprocess
from pathlib import Path

from readiness import review
from scanner import git, inventory


def repair(root, apply=False):
    root = Path(root).resolve()
    if git(root, "rev-parse", "--show-prefix").strip():
        raise ValueError("Use the repository root.")
    if git(root, "status", "--porcelain"):
        raise ValueError("Use a clean, isolated checkout.")
    snapshot = inventory(root)
    result = review(snapshot["files"], lambda oid: git(root, "cat-file", "blob", oid),
                    include_patches=True)
    proposals = result["proposed_manifest_patches"]
    if proposals:
        patch = "".join(item["patch"] for item in proposals).encode()
        command = ["git", "-C", str(root), "apply"]
        subprocess.run(command + ["--check", "-"], input=patch, check=True)
        if apply:
            subprocess.run(command + ["-"], input=patch, check=True)
    return [item["path"] for item in proposals]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repository")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    for path in repair(args.repository, args.apply):
        print("Applied:" if args.apply else "Proposed:", path)
