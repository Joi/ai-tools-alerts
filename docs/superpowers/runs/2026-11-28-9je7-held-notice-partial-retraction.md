# Run: 9je7-held-notice-partial-retraction
Instruction: Read TASK-ai-tools-alerts#9je7.md in this worktree root, then run `kata show ai-tools-alerts#9je7` and follow the brief and the dispatch rules (do-it, start rung floored at medium; PR landing; one independent review).
Stage: spec
Rung: medium (start-floor medium: dispatch floor; no hard trigger in scope: no secrets, auth or deploy path)
Spec: docs/superpowers/specs/2026-11-28-9je7-held-notice-partial-retraction-design.md   Plan: docs/superpowers/plans/2026-11-28-9je7-held-notice-partial-retraction.md
Agency project: —
Kata: ai-tools-alerts#9je7
Wall clock: 5 hours. Review shape: one independent pass (spec+plan), one whole-branch pass, one delta only for a behaviour-changing BLOCKER fix. Completion check: `scripts/test-gate.sh` passes and the acceptance test (a held notice of A and B, A retracted, B listed by the next digest) is in the suite.

Last reviewed: spec+plan e236800151f0d88d9b4fd00eb5d3b494b2107dbf

## Scorecards
Pass 1 [spec+plan]: 4B/2S/0C/0R · fixed -/- · velocity = (—→6, escalation no)   # fresheyes gpt-6.1-sol high at snapshot e236800, REASON=-; nothing was built yet
spec: passes: 1 · elapsed: ~15 min

## Chunks
- [ ] retire splits a held notice that names a retracted id; the digest waits for it

## Notes
- Start-floor evaluator not dispatched: the dispatch floors the run at medium and no hard trigger is in scope; as z360 and faxq.
- Deviation (as z360, faxq, 9kgk): spec and plan reviewed in one fresheyes pass.
- Agency not used (as every run in this repo): the plan is one chunk executed directly.
- Landed code vs issue text: the issue builds on `Run.retire`, which is on the z360 branch (pull request 67, open when this run started), not on main at v0.4.0. This branch is stacked on `origin/z360-fix-z360`; it lands after z360 does, with main merged before the review and before the merge.
- Spec+plan review dispositions. Fixed: (1, BLOCKER) the digest's `_posted` path acknowledged a struck notice whose group had posted: the wait now comes before `_posted` (test_a_held_group_that_posted_is_not_acknowledged_whole...); (2, BLOCKER) fixed id order within a notice could starve an id behind failing pages: ids rotate by the hour within a notice (test_a_failing_page_never_starves_the_survivor_behind_it); (5, SUBSTANTIVE) z360's `_retract` helper needs posted roots: own helper `_strike`. Found while fixing (2): a released member was merged back into its struck notice by the next sighting of the group: `hold` skips a struck notice (test_a_released_member_is_not_taken_back_by_the_notice_it_left). Rebutted: (3, BLOCKER as raised) two held rows each taking the other's ids when sighted as one group: `Run.hold` does this today for any two notices held apart, no advisory is lost, filed ai-tools-alerts#1e90; (4, BLOCKER as raised) a member past the 20-source cap: the same limit z360 states, more than 20 advisories in one group, the spec now says it can stay undecided, filed ai-tools-alerts#5rra; (6) the snapshot commit's message: the snapshot never lands. The general case behind (1), a notice acknowledged by `_posted` before any retraction, is z360's thread path: filed ai-tools-alerts#1m9f.
- Mutation checks (each fails at least one new test): no digest wait (7); the wait after `_posted` (1); no source union (1); no `digested` write (4); `hold` takes a struck notice (1); no id rotation (1).
- Prior work: z360 (threads; rebutted held notices there and filed this issue), faxq (fix groups, held notices take a group's ids), d3f6 (digest leaves out retracted), 8ke5 (held notices, listable), qwpw (weekly summary lists notices).
