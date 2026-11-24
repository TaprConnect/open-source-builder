# Handover — Stages 05–07

Read `DIRECTIVE_S05_S07.md` (requirements) and `registry.json` (status per requirement) first.

- Branch: `claude/sleepy-knuth-12w5sr` (session branch; only branch this agent may push).
- CI green at f275045 (run 45378954357). Later commits: check the latest run on this branch.
- Blocker B1 resolved by owner-approved v2 scripts (tests/acceptance/manifest.json superseded_by).
- No worktrees in use. External reference repos are cloned only in the session scratchpad (untrusted).

## Next executable tasks
1. S05 precision fixes measured on holdout 2: distinguish MongoDB queries from SQL ORM where-objects (imports of
   mongoose/mongodb vs sequelize/typeorm/prisma); recognise `require('child_process').exec` member aliases; public
   routes like /forgotpw; Identity for unauthenticated read APIs. Then a THIRD blind holdout (both measured ones are spent).
2. S06: a second reference application (TypeScript/Express) through `osb autopilot`; S06-W1: classify Windows as
   trusted-only for isolated analysis/verification (winacl.py covers store ACLs only).
3. S07: create benchmarks/s07/<category>/ (incomplete, nonfunctional, unfamiliar, security+persistence, greenfield)
   with owner-style requirements + external acceptance written before running `osb autopilot`; S07-006 stays blocked
   (no approved live providers); S07-007 integrated report under evidence/s07/.
