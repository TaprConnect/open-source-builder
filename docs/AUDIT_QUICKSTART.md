# Experimental deterministic audit and persistent planning

Requires Python 3.10+, Git, and a trusted local environment. From the builder checkout:

```sh
python osb.py audit ../product
python osb.py plan ../product ../private-review/plan.sqlite
python osb.py status ../product ../private-review/plan.sqlite AUDIT_ID
python -m unittest -v test_osb
```

Create a private review directory outside the target first. Replace AUDIT_ID with the returned ID. The audit detects Python syntax errors and candidate placeholder function bodies using AST parsing. Unsupported languages, special files and budget-blocked files remain explicitly unanalysed. Findings are leads, not confirmed defects; intended abstract functions may legitimately contain a placeholder. The pilot persists open tasks, not automatic repairs. It never certifies a release. The 32 MiB aggregate blob budget is not a CPU, memory or model token budget. Use a trusted local Git environment; no enforced sandbox, semantic coverage, external integrations or autonomous runtime is provided. Dirty-worktree files are not reviewed by this command.

See [audit support boundaries](ENGINEERING_SPEC.md) for supported inputs and operating assumptions. Existing scanner, coverage, verification, readiness and patch utilities remain unchanged.
