"""Run the frozen acceptance scripts against this checkout (S03-006).

Each script is the byte-exact file that was frozen before its task was implemented;
manifest.json pins its SHA-256. On Linux every script runs in its own bubblewrap
sandbox with a private /tmp and a fresh copy of the tracked source at /src (nested
sandboxes stay enabled because the kernel under test launches its own). Scripts
marked windows run directly on Windows hosts. Usage:

    python -m tests.acceptance.harness [name ...]
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
MANIFEST = json.loads((HERE / "manifest.json").read_text())
_ENTRY = "import os,sys,runpy;sys.path.insert(0,os.getcwd());runpy.run_path(sys.argv[1],run_name='__main__')"


def script(name):
    path = HERE / "scripts" / f"{name}.py"
    if hashlib.sha256(path.read_bytes()).hexdigest() != MANIFEST[name]["sha256"]:
        raise ValueError(f"{name}: script differs from its frozen hash")
    return path


def supported(name):
    """Return None when the script can run here, else the reason it cannot."""
    if MANIFEST[name].get("superseded_by"):
        return f"superseded by {MANIFEST[name]['superseded_by']}: {MANIFEST[name]['superseded_reason']}"
    platform = MANIFEST[name]["platform"]
    if platform == "windows" and os.name != "nt":
        return "Windows-only acceptance"
    if platform == "linux" and not sys.platform.startswith("linux"):
        return "requires Linux bubblewrap isolation"
    if sys.platform.startswith("linux") and shutil.which("bwrap") is None:
        return "bubblewrap not installed"
    return None


def _workspace():
    tracked = subprocess.run(["git", "-C", str(ROOT), "ls-files", "-z"], capture_output=True, check=True).stdout
    work = Path(tempfile.mkdtemp(prefix="osb-acceptance-"))
    src = work / "src"
    for rel in filter(None, tracked.decode().split("\0")):
        target = src / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / rel, target)
    return work, src


def run(name, timeout=1800):
    """Run one script; returns (returncode, stdout, stderr)."""
    path = script(name)
    reason = supported(name)
    if reason:
        raise RuntimeError(reason)
    work, src = _workspace()
    try:
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "PYTHONDONTWRITEBYTECODE": "1",
               "GIT_CONFIG_NOSYSTEM": "1"}
        if os.name == "nt":
            env.update({k: os.environ[k] for k in ("SYSTEMROOT", "TEMP", "TMP", "USERPROFILE") if k in os.environ})
            # Frozen scripts use synthetic fixtures; scripts frozen before S03-001 call plan without the
            # trust flag, so assert trust explicitly where isolated analysis is unavailable.
            env["OSB_TRUSTED_TARGETS"] = "1"
            cmd = [sys.executable, "-I", "-c", _ENTRY, str(path)]
            result = subprocess.run(cmd, cwd=src, env=env, capture_output=True, text=True, timeout=timeout)
        else:
            cmd = ["bwrap", "--unshare-all", "--die-with-parent", "--new-session", "--ro-bind", "/usr", "/usr"]
            for name_ in ("bin", "lib", "lib64", "sbin"):
                host = Path("/" + name_)
                if host.is_symlink():
                    cmd += ["--symlink", os.readlink(host), "/" + name_]
                elif host.is_dir():
                    cmd += ["--ro-bind", str(host), "/" + name_]
            # /etc read-only so the acceptance environment matches a real host (for example the
            # interpreter's sitecustomize symlink); the kernel's own sandboxes still omit /etc.
            cmd += ["--ro-bind", "/etc", "/etc"]
            cmd += ["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--bind", str(src), "/src",
                    "--ro-bind", str(path), "/acceptance.py", "--chdir", "/src", "--clearenv",
                    "--setenv", "PATH", "/usr/bin:/bin", "--setenv", "HOME", "/tmp",
                    "--setenv", "PYTHONDONTWRITEBYTECODE", "1", "--setenv", "GIT_CONFIG_NOSYSTEM", "1",
                    "--", "python3", "-I", "-c", _ENTRY, "/acceptance.py"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.returncode, result.stdout, result.stderr
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main(names):
    summary = {}
    for name in names or sorted(MANIFEST):
        reason = supported(name)
        if reason:
            summary[name] = "SKIPPED: " + reason
            continue
        code, out, err = run(name)
        summary[name] = "PASS" if code == 0 else f"FAIL ({code}): " + (err.strip().splitlines() or [""])[-1][:300]
        print(f"{name}: {summary[name]}", flush=True)
    print(json.dumps(summary, indent=1))
    return 0 if all(not v.startswith("FAIL") for v in summary.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
