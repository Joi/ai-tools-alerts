# Run: 0dvh-hold-until-complete-and-age-limit
Instruction: start at medium. Task: ai-tools-alerts#0dvh (slice 3 of 9mx8) — poster: hold a high until its fix is read (6h), 7-day age limit to digest notice, affected range and advisory_severity in the block, public ids only in titles/headlines/aliases (fold 6e20). Brief: TASK-ai-tools-alerts#0dvh.md. Unmanaged repo; lands via PR merged by this session with --author-email noreply.
Stage: plan-review
Rung: medium (start-floor medium: evaluator BR1 REV2 NOV1 INT2 FC1 = 7, constraint lens; dispatch floor also medium)
Lens: "Readers at v0.1.4 still parse every post (the thread id stays the root event id)"
Spec: docs/superpowers/specs/2026-11-23-0dvh-hold-until-complete-and-age-limit-design.md   Plan: docs/superpowers/plans/2026-11-23-0dvh-hold-until-complete-and-age-limit.md
Agency project: —
Kata: ai-tools-alerts#0dvh
Last reviewed: spec b23e17323c20a7b4d0a91512ec122de88a0c31ee; plan c95538cf52519f6ae2f1caffde313d8692f64102
Pre-handoff review: —

## Scorecards
Pass 1 [spec]: 8B/0S/1C/0R · fixed -/- · velocity = (—→9, escalation no)   (fresheyes gpt-6.1-sol high; 7 fixed in the spec, 1 rebutted: the backfill floor is a separate earlier rule, now stated; cosmetic: snapshot commit subject)
passes: 1 · elapsed: 12 min
Pass 1 [plan]: 4B/0S/1C/0R · fixed -/- · velocity = (—→5, escalation no)   (fresheyes gpt-6.1-sol high; all 4 fixed in plan and code: test migration order, Japanese range wiring on the update path, age-limit coverage, identity coverage; cosmetic: snapshot commit subject, rebutted: a dangling review snapshot, never on a branch)
passes: 1 · elapsed: 9 min

## Chunks
- [ ] 1 hold and age limit (main.py, inputs.py)
- [ ] 2 block and titles (compose.py)
- [ ] 3 mirror listing once (export_mirror.py, 6e20)
- [ ] 4 replay tests (11-07, 11-18)

## Notes
- Prior work: kata search "hold until complete age limit" finds only 0dvh and 9mx8; the slice-1 spec (2026-11-23-8ke5) is the base this builds on.
- Collector slice amplifier-bundle-joi#pww7 is open: tests use fixtures that carry affected, fixed and severity.
- Agency MCP tools are not loaded in this session (no mcp__agency__* tool); the plan was executed directly, chunk by chunk, with the chunk's tests as its evaluator. Was tempted to skip nothing else.
- Execution overlapped the plan review (code is not a reviewed artifact of that pass); plan-review findings are applied to the code afterwards.
- 6e20 root cause found in the live feed: a critical posts a root in each channel (f7dd5ed6 feed, 1106d821 critical), so the page listed two threads; not an alias update.
