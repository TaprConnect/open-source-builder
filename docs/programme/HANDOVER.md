# Handover — Stages 05–07

Read `DIRECTIVE_S05_S07.md` (requirements) and `registry.json` (status per requirement) first.

- Branch: `claude/sleepy-knuth-12w5sr` (session branch; only branch this agent may push).
- Last green CI: run 45355314641 at 4748423. Run 45377568315 at c43419b is red: unit tests pass,
  frozen acceptance fails only on s04_001 line 41 and s04_005 line 19 (blocker B1).
- No worktrees in use. External reference repos are cloned only in the session scratchpad (untrusted).

## Next executable tasks
1. S05 post-holdout fixes (JS credential literals, child_process-only shell sinks, NoSQL/redirect/XSS taint), then
   a NEW blind holdout (the measured one is spent) and re-publish evidence/s05/report.json.
2. S05-010: aggregate resource exhaustion tests (file count, bytes, output flooding).
3. S06: second and third reference applications (TypeScript/Express; Flask-style routes), S06-W1 Windows classification.
4. S07: reference projects for the five categories under benchmarks/s07 driven by `osb autopilot`; S07-006 stays blocked
   without approved live providers.
