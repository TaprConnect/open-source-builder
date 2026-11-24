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

The repair command previews by default. In a clean checkout it can add missing Next.js build and ESLint lint scripts where the corresponding dependency (and lint configuration) is present. Inspect the diff and run the project's checks in an isolated environment. A patch is offered only when the manifest re-serialises byte-for-byte in its existing style (2 or 4 spaces, tabs or single-line JSON, LF endings); otherwise the report says `patch_withheld_unsupported_formatting` and the scripts must be added by hand. The command does not install packages or run target scripts. Optional scanner flag `--include-manifest-patches` includes source context in the private report.

Auth and storage findings are lexical leads. Comments can match, delegated middleware can be missed, and package scripts can delegate to workspace or CI tooling. Trace the handler and run the supplied acceptance procedure before classifying a defect. No static result grants a security or deployment pass. See the [design, motion and assurance catalogue](profiles/design-references.md).

## Whole-product launch dossier

Use a trusted copy of this builder outside the target. Keep review state in a private directory outside both repositories. Each control has an applicability condition, expected evidence and an acceptance outcome. The catalogue covers general software, websites, APIs, desktop and mobile apps, libraries, CLI tools, data pipelines and AI products. Add product-specific tests for the owner's promises. See [public engineering sources](profiles/engineering-sources.md) for the evaluation and release practices used here.

```sh
python launch.py plan ../product > ../private-review/dossier.json
python launch.py check ../product ../private-review/dossier.json ../private-review/ledger.json ../private-review/evidence
```

Create the private directories first. Populate the ledger using the deep-review format above. Allowed control states are pass, fail, blocked, unknown, not_performed and not_applicable. For pass or not_applicable, provide a reason and a receipt reference such as `{"path":"identity.json","sha256":"<digest of exact file bytes>"}`. The private JSON receipt contains control (the exact domain ID), revision, status, reviewer, environment and observation. The verifier must inspect the actual referenced CI or test results described in the observation. Keep those records independently of builder edits. A matching hash establishes byte identity, not signer identity or the truth of an observation. Exit 0 means complete attested dossier, 1 means outstanding work, 2 means invalid inputs. No automatic launch, merge or deployment follows.

## Justified additions, edits and removals

The coding agent prepares a Git patch against the pinned revision. Store it and its review manifest outside the target checkout. Use a dedicated clean worktree. Describe each changed path in the manifest:

```json
{
  "revision": "<target HEAD>",
  "patch_sha256": "<SHA-256 of the patch file>",
  "changes": {
    "src/obsolete-adapter.ts": {
      "action": "remove",
      "justification": "All current and supported legacy entry points use the replacement adapter.",
      "acceptance": "Run compatibility fixtures for both old and new records.",
      "rollback": "Restore the adapter from the recorded starting revision."
    }
  }
}
```

```sh
python changes.py ../product ../change.patch ../change.json
python changes.py ../product ../change.patch ../change.json --apply
```

Use add, modify or remove. Approved removals additionally require --allow-remove. Preview builds a temporary Git index. Apply stages the changes and leaves tests and review pending. This utility validates scope and applies an agent-authored repair; it does not generate arbitrary fixes. Review all changes to tests, policies and workflows with the owner. Use separate credentials and a disposable runner for execution.

### Read the next gap during deep research

`python research.py ../product --ledger ../private-review/ledger.json --max-lines 100 --max-chars 12000` emits actual private source. Omit the ledger for the first read. The command reads a committed blob and never advances the ledger automatically. Inspect the range, record observations and only then attest to it. Oversized first lines are reported explicitly; adjust the bound in a trusted environment to inspect them. Treat source output as private. This local, on-demand reader rebuilds the snapshot each invocation; large-repo performance and end-to-end model token savings have not been benchmarked.
