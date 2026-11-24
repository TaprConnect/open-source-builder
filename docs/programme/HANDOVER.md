# Handover — Stages 05–07

Read `DIRECTIVE_S05_S07.md` (requirements) and `registry.json` (status per requirement) first.

- Branch: `claude/sleepy-knuth-12w5sr` (session branch; only branch this agent may push).
- Last green CI: run 45355314641 at 4748423. Run 45377568315 at c43419b is red: unit tests pass,
  frozen acceptance fails only on s04_001 line 41 and s04_005 line 19 (blocker B1).
- No worktrees in use. External reference repos are cloned only in the session scratchpad (untrusted).

## Next executable tasks
1. Owner decision on B1. If approved: add revised scripts s04_001v2/s04_005v2 (only the TS
   assertion changes), mark originals `superseded_by` in the manifest, allow that skip reason in CI.
2. S05-ACCEPT: select a blind holdout (one Python, one TypeScript app not inspected before), run
   `osb assure` once without tuning, publish precision/recall with sample sizes under `evidence/s05/`.
3. S05-010: aggregate resource exhaustion tests (file count, bytes, output flooding).
4. Stage 06 in order: product understanding (S06-001) → persistent completeness graph (S06-002)
   → planner (S06-003) → repair pipeline over the existing kernel (S06-004) → provider contract
   with deterministic/mock backends and disabled live backends (S06-005) → loop (S06-006).
