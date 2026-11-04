# Run: poster-candidate-adapters
Instruction: start at medium. Task: ai-tools-alerts#6j8x, plan docs/plan.md Task B1 (Candidate adapters), brief TASK-ai-tools-alerts#6j8x.md in the worktree. Security-shaped: FRESHEYES_GPT_MODEL=gpt-6-astra. Not repoman-managed: non-repoman ending (ff-merge to main from primary checkout).
Stage: code-review:chunk1
Rung: medium (start-floor medium: evaluator BR1 REV0 NOV1 INT1 FC1 = 4, PII-shaped medium floor; no hard trigger; Lens: none)
Spec: docs/superpowers/specs/2026-11-05-poster-candidate-adapters-design.md   Plan: docs/superpowers/plans/2026-11-05-poster-candidate-adapters.md
Agency project: —
Kata: ai-tools-alerts#6j8x
Last reviewed: spec+plan 216d4f10922446e2a6802e3f5169f81853b6ee47
Pre-handoff review: — (not repoman-managed)

## Scorecards
Pass 1 [spec+plan]: 2B/3S/0C/1R · fixed -/- · velocity = (—→6, escalation no)   # fresheyes gpt-6-astra, one combined pass. critical x2 graded BLOCKER: private text through kept fields (paths, kata refs, local versions in fixed/affected), host scrub missing hint/published_at → private-content guard, hint vocabulary, timestamp grammar, heartbeat never fills fixed/affected, whole-candidate backstop. major graded SUBSTANTIVE: forged exploited → KEV-only; sentinel fixed → version grammar; privacy tests on pre-redacted fixtures → per-adapter synthetic tests. Rebutted: snapshot commit message (dangling review snapshot, never on a branch). All B/S fixed; medium rung has no spec delta — the whole-branch code pass reviews the implementation of these fixes.
passes: spec+plan 1 · elapsed ~20 min

## Chunks
- [ ] chunk 1 — fixtures, poster package, adapters, tests, pyproject package list

## Notes
- TDD order: the implementation was written while the spec review ran, before the tests; tests were then written against the spec and run red→green for the review fixes (2 failures found, fixed). Recorded, not hidden.
- Size: 907 added lines before review fixes; 323 are fixture JSON the plan requires. decided on the kata issue: count code+tests against the 600-line rule.
- Agency MCP tools (mcp__agency__*) are not loaded in this session; execution is inline by the executor per the plan. Recorded, not skipped silently.
- aitools_alerts/schema.py (A2, j153) is absent at start: Source is defined in candidates.py; B2 (31x7) reconciles.
