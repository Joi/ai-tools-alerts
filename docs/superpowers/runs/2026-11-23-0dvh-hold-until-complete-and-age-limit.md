# Run: 0dvh-hold-until-complete-and-age-limit
Instruction: start at medium. Task: ai-tools-alerts#0dvh (slice 3 of 9mx8) — poster: hold a high until its fix is read (6h), 7-day age limit to digest notice, affected range and advisory_severity in the block, public ids only in titles/headlines/aliases (fold 6e20). Brief: TASK-ai-tools-alerts#0dvh.md. Unmanaged repo; lands via PR merged by this session with --author-email noreply.
Stage: done (PR open; merge waits on gate ai-tools-alerts#xrx2)
Rung: medium (start-floor medium: evaluator BR1 REV2 NOV1 INT2 FC1 = 7, constraint lens; dispatch floor also medium)
Lens: "Readers at v0.1.4 still parse every post (the thread id stays the root event id)"
Spec: docs/superpowers/specs/2026-11-23-0dvh-hold-until-complete-and-age-limit-design.md   Plan: docs/superpowers/plans/2026-11-23-0dvh-hold-until-complete-and-age-limit.md
Agency project: —
Kata: ai-tools-alerts#0dvh
Last reviewed: spec b23e17323c20a7b4d0a91512ec122de88a0c31ee; plan c95538cf52519f6ae2f1caffde313d8692f64102
Pre-handoff review: 9172f1e9194126ef9e9b345a46834c2fc699ef88 fixed+delta ec47f1fe55c413275d62899058ffd7f6be8482ec +fix 0dbdcf9e305b1059d90e6a83151919967d0642d4

## Scorecards
Pass 1 [spec]: 8B/0S/1C/0R · fixed -/- · velocity = (—→9, escalation no)   (fresheyes gpt-6.1-sol high; 7 fixed in the spec, 1 rebutted: the backfill floor is a separate earlier rule, now stated; cosmetic: snapshot commit subject)
passes: 1 · elapsed: 12 min
Pass 1 [plan]: 4B/0S/1C/0R · fixed -/- · velocity = (—→5, escalation no)   (fresheyes gpt-6.1-sol high; all 4 fixed in plan and code: test migration order, Japanese range wiring on the update path, age-limit coverage, identity coverage; cosmetic: snapshot commit subject, rebutted: a dangling review snapshot, never on a branch)
passes: 1 · elapsed: 9 min
Pass 1 [code:branch]: 6B/2S/1C/1R · fixed -/- · velocity = (—→10, escalation no)   (whole branch at 9172f1e9194126ef9e9b345a46834c2fc699ef88: fresheyes gpt-6.1-sol high, 6 major, all fixed; Stage 1 same-model, 3 substantive (one the same as fresheyes' notice-confirmation finding), all fixed, 1 cosmetic rebutted)
Pass 2 [code:branch]: 2B/0S/0C/0R · fixed 9/9 prior · velocity ↓ (10→2, escalation no)   (delta, fresheyes --since 9172f1e --rebuttals; both fixed in 0dbdcf9 with no further pass, per the review cycle; standing rebuttals not reopened)
passes: 2 · gate: scripts/test-gate.sh exit 0 at 0dbdcf9, 1236 passed, 1 skipped (public scan run against a scratch known list adding main's eb45e6e, see Notes)

## Chunks
- [x] 1 hold and age limit (main.py, inputs.py) — 7ee04b9, review fixes ec47f1f, 0dbdcf9
- [x] 2 block and titles (compose.py) — 7ee04b9
- [x] 3 mirror listing once (export_mirror.py, 6e20) — 9172f1e
- [x] 4 replay tests (11-07, 11-18) — 7ee04b9

## Notes
- Prior work: kata search "hold until complete age limit" finds only 0dvh and 9mx8; the slice-1 spec (2026-11-23-8ke5) is the base this builds on.
- Collector slice amplifier-bundle-joi#pww7 is open: tests use fixtures that carry affected, fixed and severity.
- Agency MCP tools are not loaded in this session (no mcp__agency__* tool); the plan was executed directly, chunk by chunk, with the chunk's tests as its evaluator. Was tempted to skip nothing else.
- Execution overlapped the plan review (code is not a reviewed artifact of that pass); plan-review findings are applied to the code afterwards.
- 6e20 root cause found in the live feed: a critical posts a root in each channel (f7dd5ed6 feed, 1106d821 critical), so the page listed two threads; not an alias update.
- origin/main moved during the run (PR #5, eb45e6e); the branch was rebased onto it before the whole-branch review. eb45e6e itself fails the public scan (a personal author address in the merge commit); notice posted on 0dvh. Nothing on this branch hits.
- Ending changed by the 6d8dds update on 0dvh: no merge while xrx2 is open; PR left open, issue labelled pr-open and blocked by xrx2. No reinstall on the poster machine until it merges.
- Size: 586 changed lines in code and tests (fixture JSON and docs aside).
