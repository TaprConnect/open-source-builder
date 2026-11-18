# Local audit and guarded repair

Python 3.10+ and Git; run the builder from a trusted copy, using a trusted local target clone and a private external directory. POSIX: `mkdir -m 700 ../private-review`; on Windows restrict directory ACLs yourself. The SQLite database is trusted local state, not a multi-user or adversarial security boundary. Do not put model or provider credentials in it.

```sh
python -m osb_engine plan ../product ../private-review/state.sqlite
python -m osb_engine status ../product ../private-review/state.sqlite RUN_ID
python -m osb_engine transition ../product ../private-review/state.sqlite RUN_ID TASK_ID 0 investigating --reason 'Review evidence'
python -m unittest discover -v
```

`audit` scans and caches without creating tasks. `plan` stores a deterministic revision-bound report and candidate tasks. `status` detects stale revisions. `transition` uses optimistic version checks and persists a state history. It cannot mark a task passed or release ready. The default control catalogue is the existing `profiles/checks.tsv`; use `--catalogue` only for an explicitly trusted alternative. JSON output is private. The old `osb.py` pilot is retained for compatibility; the new CLI is `python -m osb_engine`.

## Supported analysis

- Python: AST syntax diagnostics, class/function symbol ranges, import edges and syntactic call references, placeholder bodies and limited risk indicators. Imports use simple project-relative module paths, not a Python runtime resolver. Dynamic imports, src-layout ambiguity, alias resolution, inherited methods, call targets, transitive dependencies and complete data/control flow remain unverified.
- Node: package.json shape and script presence. TypeScript/JavaScript source is not parsed. Missing script candidates may be satisfied elsewhere. No scripts or target source are executed.
- Other languages, symlinks, submodules, oversized, parse-blocked and budget-blocked paths receive explicit coverage states. The byte budget bounds the considered blob bytes, not AST amplification, total file inventory, memory or CPU. A hardened external resource-limited runner is required for hostile repositories.
- Cache: keyed by target path, blob, language and analyser/Python version. Unchanged blob analysis is reused across snapshots; report IDs exclude cache statistics. The cache is trusted, unsigned and has no eviction policy yet. Git inventory is still rebuilt each audit.

## Control execution

All catalogue rows are represented. Build, Quality, Security, Reliability, Network, Backend, SupplyChain, Infrastructure, Release, Database and Frontend have narrow static indicator checks. They are not fully executable acceptance evaluators. All 55 other domains in the original 66-domain catalogue are marked not_performed. Even the 11 checked domains remain unknown, not pass, because evidence is incomplete. The included 66-domain test uses a synthetic catalogue with the original domain IDs, not the actual upstream TSV bytes.

## Guarded repair

Prepare a text Git patch, a JSON object mapping each changed path to action (add/modify/remove), justification, acceptance and rollback, and the frozen acceptance script outside the target. The preview uses a temporary index; Git may write unreferenced objects. Inspect its output and diff before approving. The acceptance content is hashed, not executed.

```sh
python -m osb_engine preview ../dedicated-worktree ../private-review/change.patch ../private-review/changes.json ../private-review/acceptance.py
python -m osb_engine apply ../dedicated-worktree ../private-review/change.patch ../private-review/changes.json ../private-review/acceptance.py --approval-id APPROVAL_ID
```

Apply requires a clean linked worktree and exact preview binding. Removal needs `--allow-remove` separately. Common test/workflow/policy/manifest and secret-file paths are rejected; this is a conservative path filter, not a complete defence against indirect test weakening. Hashes are not signed authority; the operator is trusted and must explicitly approve. Worktrees share repository objects and configuration and do not isolate the running process. Use a disposable clone without credentials and a separately isolated test runner. No merge, push, deployment or execution of the acceptance script occurs. Review staged changes; rollback by discarding the dedicated worktree only with owner approval.
