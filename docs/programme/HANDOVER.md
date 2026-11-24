# Handover — Stages 05–07

Read `DIRECTIVE_S05_S07.md` (requirements) and `registry.json` (status per requirement) first.

- Branch: `claude/sleepy-knuth-12w5sr` (session branch; only branch this agent may push).
- CI green at 6925e0f (run 45381212027, both Ubuntu jobs incl. frozen suite); 5941ecb green (run 45380646717).
- Blocker B1 resolved by owner-approved v2 scripts (tests/acceptance/manifest.json superseded_by).
- No worktrees in use. External reference repos are cloned only in the session scratchpad (untrusted).

## Next executable tasks
1. S05: holdout 4 (holdouts 1-3 are spent; use a documented vulnerable app not yet cloned, e.g. a Flask or Django
   lab with a published vulnerability list). Freeze ground truth first, run once, record verdicts, run tools/s05_report.py.
   Known remaining gaps: model-layer (interprocedural) taint, fallback secrets (env || 'literal'), XSS/CSRF/ReDoS/
   prototype pollution/mass assignment detectors, Python SSRF/deserialization.
2. S06: second reference application (TypeScript/Express) through `osb autopilot`; S06-W1 Windows classification.
3. S07: five reference categories under benchmarks/s07 with requirements + external acceptance written before running.
