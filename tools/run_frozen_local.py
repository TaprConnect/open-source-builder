"""Developer check: run frozen acceptance scripts against the working tree WITHOUT the outer sandbox.

Use only on hosts that cannot nest bubblewrap (the scripts' own inner isolation still applies).
CI runs the real harness (tests/acceptance/harness.py); this never replaces it.
"""
import os, shutil, subprocess, sys, tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tests.acceptance import harness

names = sys.argv[1:] or sorted(harness.MANIFEST)
failed = []
for name in names:
    if harness.supported(name) == "Windows-only acceptance":
        continue
    script = harness.script(name)
    work, src = harness._workspace()
    try:
        env = {"PATH": "/usr/bin:/bin", "HOME": str(work), "PYTHONDONTWRITEBYTECODE": "1", "GIT_CONFIG_NOSYSTEM": "1"}
        r = subprocess.run([sys.executable, "-I", "-c", harness._ENTRY, str(script)], cwd=src, env=env,
                           capture_output=True, text=True, timeout=1800)
        ok = r.returncode == 0
        print(f"{name}: {'PASS' if ok else 'FAIL ' + (r.stderr.strip().splitlines() or [''])[-1][:240]}", flush=True)
        if not ok:
            failed.append(name)
    finally:
        shutil.rmtree(work, ignore_errors=True)
print("FAILED:", failed)
sys.exit(1 if failed else 0)
