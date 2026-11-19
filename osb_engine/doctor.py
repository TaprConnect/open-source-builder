"""Host capability classification (F01-OPS) and human-readable report rendering (F01-CLI)."""
import os
import platform
import shutil
import subprocess
import sys

from . import isolation


def doctor():
    """Report what this host can enforce. Nothing here is assumed; each capability is probed."""
    try:
        git = subprocess.run(["git", "--version"], capture_output=True, text=True, timeout=20).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        git = None
    isolated = isolation.available()
    capabilities = {"worker_isolation": isolated, "verification": isolated, "isolated_analysis": isolated,
                    "external_acceptance": isolated, "resource_limits": isolated and shutil.which("prlimit") is not None}
    if not git:
        classification = "unsupported"
    elif sys.platform.startswith("linux"):
        classification = "linux-isolated" if all(capabilities.values()) else "linux-unisolated"
    elif os.name == "nt":
        classification = "windows-restricted"
    else:
        classification = "unsupported"
    limits = {"windows-restricted": "admission, mediation, integrity, journal, store ACL and planning only; "
                                    "tasks cannot be verified or completed and analysis needs --trusted-target",
              "linux-unisolated": "bubblewrap unusable here; verification, worker runs and isolated analysis refuse",
              "linux-isolated": "all kernel controls available",
              "unsupported": "Git missing or platform untested"}
    return {"platform": platform.platform(), "python": platform.python_version(), "git": git,
            "capabilities": capabilities, "classification": classification,
            "limitations": limits[classification]}


def text_report(command, output):
    """Concise human-readable summary of audit, plan or status output."""
    report = output.get("report", output)
    lines = [f"{command}: revision {report.get('revision', 'unknown')}"]
    coverage = report.get("coverage")
    if coverage:
        counts = ", ".join(f"{k}={v}" for k, v in coverage["counts"].items())
        lines.append(f"coverage: {'complete' if coverage['complete'] else 'INCOMPLETE'} ({counts})")
    rules = {}
    for finding in report.get("findings", []):
        rules[finding["rule"]] = rules.get(finding["rule"], 0) + 1
    lines.append(f"findings: {sum(rules.values())}")
    lines += [f"  {count:5d}  {rule}" for rule, count in sorted(rules.items(), key=lambda kv: (-kv[1], kv[0]))]
    if "tasks" in output:
        states = {}
        for task in output["tasks"]:
            states[task["state"]] = states.get(task["state"], 0) + 1
        lines.append("tasks: " + ", ".join(f"{k}={v}" for k, v in sorted(states.items())))
        lines.append(f"stale: {output.get('stale')}")
    if "run_id" in output:
        lines.append(f"run: {output['run_id']}")
    if "metrics" in output:
        lines.append("metrics: " + ", ".join(f"{k}={v}" for k, v in output["metrics"].items()))
    lines.append("release ready: no (runtime verification and semantic review not performed)")
    return "\n".join(lines) + "\n"
