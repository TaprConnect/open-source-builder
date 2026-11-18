# Open Source Builder

Provided by TaprConnect as part of its community support for people building software. Follow [@taprconnect on X](https://x.com/taprconnect) for project updates.

## Review a repository

Use Python 3.10+ and Git in a trusted environment. Run the scanner against a committed snapshot. It reads Git objects without executing the target application. It emits file metadata and candidate findings without copying source lines into the report.

```sh
python scanner.py /path/to/checkout > inventory.json
python -m unittest discover -v
```

For a connected chat, provide the repository link and ask the agent to read AGENTS.md. Source-only hosts can follow the review protocol. Running tests or recording a verified repair needs a coding environment. Keep generated reports private.

## Release scope

This initial implementation provides a snapshot inventory, source-line counts, candidate unfinished-code indicators and local evidence verification. Human or agent review still has to establish product intent and trace user journeys. Binary files, symlinks, submodules, non-UTF-8 text and oversized blobs receive explicit coverage states. Indexing never certifies semantic review.

Provider adapters, metered reasoning enforcement, hosted collaboration, automatic repairs, design generation, jurisdiction updates, tax calculations and production deployment verification remain future work. This release has no enterprise assurance or coverage certification.

## Verify a repair

In a disposable sandbox run `python verifier.py REPO BEFORE AFTER ACCEPTANCE.py RECEIPT.json`. Supply a trusted acceptance script outside the target tree. Use exit 42 to identify the expected baseline failure and exit 0 for success. Review the receipt before making a release decision. Git worktrees isolate source files only. Run untrusted code inside a separate sandbox with no credentials.

## Deep-review checkpoint

Save a private JSON ledger with the pinned revision and inclusive line ranges actually reviewed. Example shape: `{"revision":"<full commit id>","files":{"src/app.ts":[[1,100],[101,180]]}}`. Run `python coverage.py REPO ledger.json`. Exit 1 means ranges or blocked files remain. A clean ledger verifies interval coverage of the supplied attestations only. It cannot attest to human or model comprehension.

## Review profiles

The tab-separated catalogue in profiles/checks.tsv gives applicability conditions, required evidence and expected outcomes across product and engineering disciplines. These are review criteria. The local scanner does not automatically execute each profile. CI runs the included regression tests and snapshot scanner.
