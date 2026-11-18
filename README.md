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

## Check application readiness

Run the normal scanner to inventory candidate Next.js handlers and inspect Node package scripts. Identify routes that actually promise private access or durable writes:

```sh
python scanner.py ../my-app --private-route app/api/projects/route.ts --durable-route app/api/projects/route.ts
python repair.py ../my-app
python repair.py ../my-app --apply
```

The repair command previews by default. In a clean checkout it can add missing Next.js build and ESLint lint scripts where the corresponding dependency (and lint configuration) is present. Inspect the diff and run the project's checks in an isolated environment. The command does not install packages or run target scripts. Optional scanner flag `--include-manifest-patches` includes source context in the private report.

Auth and storage findings are lexical leads. Comments can match, delegated middleware can be missed, and package scripts can delegate to workspace or CI tooling. Trace the handler and run the supplied acceptance procedure before classifying a defect. No static result grants a security or deployment pass. See the [design, motion and assurance catalogue](profiles/design-references.md).
