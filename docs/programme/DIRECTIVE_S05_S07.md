# Open Source Builder — continuous implementation directive (Stages 05–07)

Preserved verbatim from the owner on 2026-11-24. This file is the authoritative
requirement source for Stages 05–07. Machine-readable status lives in
`docs/programme/registry.json`; session state lives in `docs/programme/HANDOVER.md`.
Task identifiers below are newly authorised implementation subdivisions, not
recovered historical task definitions.

## 1. Authoritative checkpoint

Continue the existing Open Source Builder engineering programme.

Repository: TaprConnect/open-source-builder
Current integrated branch: claude/sleepy-knuth-12w5sr
Verified commit: 4748423a68fca934ddb342562557732c3da55109
GitHub Actions run: 45355314641

Both Ubuntu CI jobs passed, including unit tests, frozen acceptance tests and unexpected-skip validation.
Preserve this verified baseline. Do not rebuild the kernel, recreate existing infrastructure or restart the programme.

## 2. Permanent specification continuity

This directive supplies the missing Stage 05–07 requirements. Treat the task identifiers below as newly authorised implementation subdivisions, not recovered historical task definitions.

Before implementation:

* Preserve this complete directive in a durable engineering specification within the development workspace.
* Maintain a machine-readable requirements and task registry.
* Map requirements to existing implementations, executable tests and evidence.
* Retain pending work across context resets and model changes.
* Automatically decompose requirements into smaller engineering tasks where necessary.
* Do not stop merely because a lower-level task identifier or implementation detail has not previously been specified.
* Distinguish genuine product ambiguity from ordinary engineering decisions.

The owner authorises you to make reasonable technical implementation decisions consistent with this specification.

## 3. Execution strategy

Complete Stages 05, 06 and 07 as one continuous engineering programme.

Use up to three genuinely independent workstreams where appropriate. Isolate concurrent writers through worktrees and explicit ownership.

Reuse the existing: execution kernel; SQLite persistence; task leases and permissions; mutation mediation; resource enforcement; isolation infrastructure; repository intelligence; analysis plugins; engineering control framework; acceptance harness; CI infrastructure. Do not duplicate these mechanisms.

Prioritise functional implementation over repetitive documentation and architectural deliberation.
Use deterministic code and tools wherever possible. Reserve expensive model reasoning for decisions that genuinely require it.
Freeze acceptance requirements before implementation. Batch related regression runs while retaining individual task evidence.

## STAGE 05 — E01 EXECUTABLE ENGINEERING CONTROLS

Objective: Transform the existing 66-domain engineering catalogue into an executable, extensible assurance system. Do not confuse catalogue entries with implemented evaluators. Inspect the actual catalogue and derive requirements from every existing domain.

### S05-003 — Shared execution and evidence framework

Implement or extend the common control engine to support: unique control identifiers and versions; applicability rules with supporting evidence; static and runtime evaluators; severity and confidence; evidence dependencies; required acceptance conditions; remediation requirements; revision-bound verification; explicit execution budgets; dependency-aware evaluation ordering; failure isolation; structured evidence receipts.

Required states include pass, fail, blocked, unknown, unsupported, not applicable and not performed.
A control may pass only when its defined acceptance evidence actually exists.
Static absence of a detected vulnerability must never automatically produce a security pass.

### S05-005 — Runtime verification infrastructure

Implement reusable verification adapters for: build commands; unit tests; integration tests; type checking; linting; browser and API behaviour; authentication and authorisation; data persistence; configuration and environment requirements; database migrations; dependency and supply-chain checks; error handling; recovery behaviour; accessibility where applicable; resource and performance checks.

Discover supported project commands and existing test infrastructure automatically.
Use isolated, bounded execution. Never expose host credentials.
Require trusted external acceptance when evaluating untrusted repositories.
Unsupported environments must fail closed rather than report successful verification.

### S05-008 — Complete control-domain implementation

Expand the existing control framework across all 66 catalogue domains. Use shared evaluators and common evidence mechanisms rather than implementing 66 unnecessarily independent engines.

For each domain, determine:
1. Whether the control applies.
2. Which evidence is required.
3. Whether an actual evaluator exists.
4. What the evaluator can establish.
5. Which deficiencies remain.
6. What remediation is appropriate.
7. How remediation will be independently verified.

Cover security, application architecture, frontend, backend, databases, integrations, configuration, infrastructure, accessibility, reliability, performance, deployment, operations, recovery, privacy and applicable business requirements.
Where a control requires an unavailable external system, report the actual blocker and implement the local verification contract where possible.
Do not award completion credit for unsupported placeholders.

### S05-009 — Multi-language intelligence prerequisite

Close the major intelligence gaps exposed by the earlier independent review.
Implement proper TypeScript and JavaScript parsing, including TSX and JSX where applicable.
Extend the existing intelligence system to identify: symbols and imports; route handlers; middleware and authentication dependencies; frontend-to-backend references; API contracts; persistence operations; environment dependencies; unimplemented functions; dependency relationships; candidate security-sensitive data flows.
Use real parsers rather than treating regular expressions as semantic analysis.
Extend SQL understanding while distinguishing SQLite-compatible analysis from PostgreSQL and other dialects.
Retain explicit unresolved and unsupported states.

### S05-010 — Coverage and resource integrity

Correct incomplete coverage states, including parse failures.
Ensure that aggregate memory, file count, bytes, time, recursion depth, output volume and parser execution are bounded.
Test large files, malformed inputs, excessive inventories, output flooding and resource exhaustion.
Review the Python 3.10 TOML fallback for malformed syntax, quoted comments, multiline strings and false dependency detection.
Prefer a maintained standards-compliant parser where justified. Never label incomplete parsing as complete semantic understanding.

### Stage 05 acceptance

Demonstrate the control system against multiple independently selected Python and TypeScript applications containing intentional defects. Include secure and insecure examples to measure both false positives and false negatives.

Publish the following within the evidence workspace: per-domain executable coverage; supported and unsupported evaluators; static versus runtime verification; precision and recall with sample sizes; false positives and false negatives; resource consumption; outstanding blockers.

Do not certify Stage 05 solely because the original synthetic fixtures pass.

## STAGE 06 — A02 AUTONOMOUS ENGINEERING AND REPAIR

Objective: Allow Open Source Builder to understand an incomplete application, construct an engineering plan, execute controlled repairs and verify the resulting behaviour. The existing guarded mutation engine is a foundation, not completion of this stage.

### S06-001 — Product understanding

Given an unfamiliar repository, identify: intended product; supported users and roles; core user journeys; existing functionality; partially implemented functionality; missing functionality; broken functionality; authentication and permissions; database and persistence requirements; API contracts; external integration dependencies; build and deployment requirements; security boundaries.
Separate confirmed requirements, inferred requirements and unresolved product decisions.
Do not silently invent product requirements.

### S06-002 — Product completeness graph

Construct a persistent graph connecting: user requirements → user journeys → UI components → API routes → services → database operations → external systems → tests → evidence.
Identify disconnected, missing, broken and unverified relationships.
Support incremental graph updates following code changes.

### S06-003 — Autonomous engineering planner

Generate dependency-aware engineering tasks from the completeness graph and control violations.
Each task must contain: stable identity; required outcome; supporting evidence; dependencies; allowed modification scope; acceptance conditions; risk classification; resource budget; rollback strategy; current state.
Prioritise blockers and defects that prevent working user journeys.
Avoid repeatedly rediscovering unchanged tasks.

### S06-004 — Repair generation

Implement an extensible repair pipeline supporting deterministic repairs and authorised model-generated patches. The pipeline must:
1. Understand the defect.
2. Reproduce the failure.
3. Freeze the acceptance condition.
4. Generate or select a repair.
5. Validate patch scope.
6. Apply through the existing mutation engine.
7. Execute independent verification.
8. Revert or contain unsuccessful changes.
9. Update the completeness graph.
10. Record the resulting evidence.

The repair pipeline must support more than package-manifest changes.
Demonstrate application logic repairs, persistence repairs, missing implementation repairs and authentication corrections.
Never weaken security controls or tests to make implementation appear successful.

### S06-005 — Model-independent execution

Implement a common model-provider and worker contract.
Support deterministic local execution and at least two independently configurable model backends where authorised and available.
The kernel must remain the authority for task state, execution permissions, mutation and verification.
Model outputs must not directly certify their own success.
Use bounded context retrieval, caching, structured outputs and incremental repository indexing.
Do not perform paid API calls without explicit owner approval.
A mock provider may verify interface compatibility but cannot establish genuine live model functionality.

### S06-006 — Continuous repair loop

Implement the actual autonomous control loop: Discover → analyse → prioritise → reserve → implement → verify → review → complete → continue.
Requirements: resume after interruption; recover safely from failed operations; detect stale plans; prevent endless retries; enforce resource limits; preserve completed work; escalate genuine product decisions; respect pause, cancellation and revocation; continue automatically when independent work remains.
Do not require the owner to repeatedly issue a continue command for routine execution.

### S06-007 — Independent verification

Use the existing external acceptance mechanism to verify repairs separately from the implementation worker.
Demonstrate: failing baseline; passing repaired revision; preservation of unrelated behaviour; no unauthorised changes; correct rollback; correct failure and blocked-state reporting.
Test hostile or misleading repository content that attempts to influence the agent or falsify verification.

### S06-W1 — Platform compatibility

Resolve remaining Windows compatibility failures where technically achievable.
Do not simulate Windows isolation guarantees.
Where equivalent isolation is unavailable, clearly classify Windows as trusted-only or unsupported for the relevant operation.
Linux acceptance must remain mandatory.

### Stage 06 acceptance

Given an incomplete repository with independently defined requirements, Open Source Builder must complete multiple real repair tasks through its own continuous execution loop.
Manual repair generation by the principal coding agent, followed only by OSB verification, is insufficient to demonstrate autonomous OSB functionality.

## STAGE 07 — ORIGINAL PRODUCT END-TO-END ACCEPTANCE

Objective: Demonstrate that Open Source Builder provides genuine engineering value when connected to unfamiliar repositories. This is the first major product milestone.

### S07-001 — Incomplete application
Use an application with deliberately missing core features. The system must discover missing functionality, construct a plan, implement the required functionality and verify complete user journeys.

### S07-002 — Nonfunctional application
Use an application with failing builds, broken imports, incorrect configuration and application defects. Restore working behaviour without unnecessary architectural rewrites.

### S07-003 — Unfamiliar application
Use a repository that the principal implementation agent did not create. Determine its purpose, architecture and defects using repository evidence. Measure discovery accuracy, repair success and human interventions.

### S07-004 — Security and persistence-defective application
Use a realistic application containing missing access controls, cross-user data exposure, incorrect persistence, missing validation and unsafe configuration. Verify the repaired security boundaries using independent positive and negative tests. Include persistence verification across process restarts.

### S07-005 — Greenfield application
Start with an empty repository and a bounded, clearly defined application specification. Generate the required architecture, frontend, backend, persistence, authentication, tests and documentation. Demonstrate a working application through actual execution. Do not count generated screenshots, source files or successful compilation alone as complete application delivery.

### S07-006 — Comparative model evaluation
Compare the same supported model configurations operating independently and operating with Open Source Builder. Use equivalent initial repositories, task requirements and resource budgets. Include at least two supported model configurations where actual authorised access exists, plus deterministic local execution.
Record: correctly completed requirements; defect detection precision and recall; repair success; regression failures; security violations; token usage; wall-clock duration; human interventions; recovery success; unverified claims.
Do not fabricate token savings, intelligence improvements or comparative results.
If live provider access is unavailable, report comparative model evaluation as blocked rather than substituting simulated results.

### S07-007 — Integrated acceptance
Execute the complete workflow: repository discovery → product understanding → completeness analysis → task planning → autonomous implementation → isolated verification → repair iteration → final evidence report.
All five reference-project categories must be exercised.
Use independent frozen acceptance tests and include previously unseen holdout cases.
The final report must distinguish verified functionality, incomplete functionality, unsupported scope and residual risk.

## 4. Non-negotiable engineering rules

* Never report unsupported capabilities as implemented.
* Never report implemented capabilities as verified without evidence.
* Never treat a passing unit suite as comprehensive security assurance.
* Never use repository-controlled output as trusted completion authority.
* Never modify the acceptance criteria to conceal an implementation defect.
* Never expose private evidence, credentials or owner-only intelligence.
* Never perform unauthorised publication, merging, deployment or paid API operations.
* Preserve all existing published history.
* Do not force-push.
* Keep the proprietary TaprConnect repository outside this programme.
* Independently inspect actual code before claiming completion.
* Keep CI green and record every failure honestly.

## 5. Completion and continuation

Continue until Stages 05–07 have been implemented and their individual acceptance gates evaluated.
Do not stop after every task or stage.
If a capability is blocked by an unavailable external service, preserve that blocker and continue independent implementation work.
At a genuine context or usage limit, persist: exact current commit; active branches and worktrees; completed requirement identifiers; outstanding requirements; test and CI evidence; remaining security findings; exact next executable task.
The next session must be able to continue using repository and workspace state alone.
Implement the software now. Do not respond with another proposed roadmap in place of execution.
