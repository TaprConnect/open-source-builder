"""Compare an owner-supplied acceptance test on two committed revisions.

Run only inside a disposable offline sandbox containing trusted test code.
Git worktrees isolate source copies, not processes, networks or credentials.
"""
import argparse
import hashlib
import json
import os
import pathlib
import subprocess
import tempfile


def git(repo, *args):
    return subprocess.check_output(
        ["git", "-C", str(repo), *args], text=True, stderr=subprocess.PIPE
    ).strip()


def observe(repo, commit, test, timeout):
    with tempfile.TemporaryDirectory() as tmp:
        checkout = pathlib.Path(tmp) / "source"
        git(repo, "worktree", "add", "--quiet", "--detach", str(checkout), commit)
        try:
            runner = pathlib.Path(tmp) / "acceptance.py"
            runner.write_bytes(test)
            import sys
            try:
                result = subprocess.run(
                    [sys.executable, "-I", str(runner)],
                    cwd=checkout, timeout=timeout, stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
            except subprocess.TimeoutExpired:
                return {"commit": commit, "outcome": "timeout"}
            # Uncaught Python exceptions also exit 1: require 42 instead.
            outcome = {0: "passed", 42: "assertion_failed"}.get(
                result.returncode, "runner_error"
            )
            return {"commit": commit, "outcome": outcome, "exit": result.returncode}
        finally:
            git(repo, "worktree", "remove", "--force", str(checkout))


def compare(repo, before, after, test_path, timeout):
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    revisions = [git(repo, "rev-parse", "--verify", "--end-of-options", ref + "^{commit}")
                 for ref in (before, after)]
    if revisions[0] == revisions[1]:
        raise ValueError("two distinct revisions required")
    test = pathlib.Path(test_path).read_bytes()
    base, candidate = [observe(repo, rev, test, timeout) for rev in revisions]
    return {"schema": 1, "test_sha256": hashlib.sha256(test).hexdigest(),
            "baseline": base, "candidate": candidate,
            "observed_repair": base["outcome"] == "assertion_failed"
                               and candidate["outcome"] == "passed"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for arg in ("repo", "before", "after", "test", "receipt"):
        parser.add_argument(arg)
    parser.add_argument("--timeout", type=int, default=30)
    args = parser.parse_args()
    receipt = compare(args.repo, args.before, args.after, args.test, args.timeout)
    destination = pathlib.Path(args.receipt)
    with tempfile.NamedTemporaryFile(mode="w", dir=destination.parent, delete=False) as fp:
        temp = pathlib.Path(fp.name)
        try:
            json.dump(receipt, fp, indent=2)
            fp.write("\n")
            fp.flush()
            os.fsync(fp.fileno())
            fp.close()
            os.replace(temp, destination)
        finally:
            temp.unlink(missing_ok=True)
    return 0 if receipt["observed_repair"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
