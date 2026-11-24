"""Read-only evidence checks for committed Node web applications."""
import difflib
import json
import re
from pathlib import PurePosixPath

AUTH = re.compile(r"\b(?:getServerSession|requireUser|requireAuth|currentUser|auth|getUser|verifySession)\s*\(")
STORE = re.compile(r"\b(?:prisma|db|pool|repository|supabase)\s*\.\s*(?:\w+\s*\.\s*)?(?:insert|upsert|create|update|query|save|from|execute)\s*\(")
MEMORY = re.compile(r"\bnew\s+(?:Map|Set)\s*\(")
ROUTE = re.compile(r"(?:^|/)(?:app/api/.*/route|pages/api/.+)\.[cm]?[jt]sx?$")


def candidate(rule, path, state, action, test, line=None):
    return dict(rule=rule, path=path, line=line, status=state, repair=action, acceptance=test)


def route_findings(path, source, required):
    findings = []
    for rule, detector, action, test in [
        ("auth", AUTH, "Trace middleware and upstream identity first; apply the existing server-side identity and ownership check before accessing private records.",
         "Exercise authorised, anonymous and wrong-workspace requests against isolated test data."),
        ("persistence", STORE, "Trace delegated services; connect the write handler to the existing durable repository and await its result before acknowledging success.",
         "Save, restart with the same database, then read the record. Simulate a write failure and check the UI reports it."),
    ]:
        if rule not in required:
            continue
        match = detector.search(source)
        state = "candidate_evidence_requires_trace" if match else "no_direct_evidence"
        if rule == "persistence" and not match and MEMORY.search(source):
            match = MEMORY.search(source)
            state = "in_memory_storage_requires_trace"
        line = 1 + source.count("\n", 0, match.start()) if match else None
        findings.append(candidate(rule, path, state, action, test, line))
    return findings


def manifest_checks(path, source, paths):
    try:
        package = json.loads(source)
        if not isinstance(package, dict):
            raise ValueError()
        scripts = package.get("scripts", {})
        deps = {**package.get("dependencies", {}), **package.get("devDependencies", {})}
        if not isinstance(scripts, dict):
            raise ValueError()
    except (ValueError, TypeError):
        return [candidate("manifest", path, "invalid_manifest", "Repair the package manifest.", "Parse the manifest and run package checks.")], None

    findings = []
    additions = {}
    parent = PurePosixPath(path).parent
    has_eslint_config = any(str(parent / name) in paths for name in (
        "eslint.config.js", "eslint.config.cjs", "eslint.config.mjs", ".eslintrc.json"))
    for script, command in [
        ("lint", "eslint ." if "eslint" in deps and has_eslint_config else None),
        ("build", "next build" if "next" in deps else None),
    ]:
        if script == "build" and not ({"next", "vite", "astro"} & deps.keys()):
            continue
        if script in scripts and isinstance(scripts[script], str) and scripts[script].strip():
            continue
        findings.append(candidate(script, path, "missing_package_script",
            "Check inherited workspace commands and CI before adding the package script.",
            f"Run the real {script} command in an isolated clean checkout and retain the exit status."))
        if command and script not in scripts:
            additions[script] = command

    patch = None
    if additions and re.fullmatch(r"[A-Za-z0-9._/@-]+", path):
        style = round_trip_style(package, source)
        if style is None:
            # Rewriting would reformat the file or drop content (duplicate keys, escapes, CRLF).
            findings.append(candidate("manifest", path, "patch_withheld_unsupported_formatting",
                "Add the missing scripts by hand; an automatic rewrite would not preserve the existing file.",
                "Diff the manifest and confirm only the scripts entry changed."))
        else:
            package["scripts"] = {**scripts, **additions}
            updated = json.dumps(package, ensure_ascii=False, **style) + "\n"
            patch = "".join(difflib.unified_diff(source.splitlines(True), updated.splitlines(True),
                                                  fromfile="a/" + path, tofile="b/" + path))
    return findings, patch


def round_trip_style(package, source):
    """Return json.dumps options that reproduce source byte-for-byte, else None."""
    styles = [{"indent": indent} for indent in (2, 4, "\t")]
    styles += [{"separators": (",", ":")}, {}]
    for style in styles:
        if json.dumps(package, ensure_ascii=False, **style) + "\n" == source:
            return style
    return None


def review(rows, read_blob, private_routes=(), durable_routes=(), include_patches=False):
    paths = {row["path"] for row in rows}
    declared = {"auth": set(private_routes), "persistence": set(durable_routes)}
    findings, patches, candidates = [], [], []
    for row in rows:
        path = row["path"]
        required = {rule for rule, selected in declared.items() if path in selected}
        manifest = PurePosixPath(path).name == "package.json"
        if ROUTE.search(path):
            candidates.append(path)
        if not (manifest or required):
            continue
        if row["status"] != "indexed":
            findings.append(candidate("coverage", path, "blocked", "Obtain readable source.", "Review the exact target revision."))
            continue
        source = read_blob(row["oid"]).decode("utf-8")
        if manifest:
            checks, patch = manifest_checks(path, source, paths)
            findings.extend(checks)
            if patch and include_patches:
                patches.append({"path": path, "patch": patch})
        findings.extend(route_findings(path, source, required))
    for path in sorted(set.union(*declared.values()) - paths):
        findings.append(candidate("scope", path, "missing_declared_path", "Correct the requirement path or implement the promised entry point.", "Trace the actual customer journey."))
    return dict(route_candidates=candidates, findings=findings, proposed_manifest_patches=patches,
                runtime_verification="not_performed")
