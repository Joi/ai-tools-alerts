# Run: 9je7-held-notice-partial-retraction
Instruction: Read TASK-ai-tools-alerts#9je7.md in this worktree root, then run `kata show ai-tools-alerts#9je7` and follow the brief and the dispatch rules (do-it, start rung floored at medium; PR landing; one independent review).
Stage: done
Rung: medium (start-floor medium: dispatch floor; no hard trigger in scope: no secrets, auth or deploy path)
Spec: docs/superpowers/specs/2026-11-28-9je7-held-notice-partial-retraction-design.md   Plan: docs/superpowers/plans/2026-11-28-9je7-held-notice-partial-retraction.md
Agency project: —
Kata: ai-tools-alerts#9je7
Wall clock: 5 hours. Review shape: one independent pass (spec+plan), one whole-branch pass, one delta only for a behaviour-changing BLOCKER fix. Completion check: `scripts/test-gate.sh` passes and the acceptance test (a held notice of A and B, A retracted, B listed by the next digest) is in the suite.

Last reviewed: spec+plan e236800151f0d88d9b4fd00eb5d3b494b2107dbf
Last reviewed: code 7f30dc0 (whole change), delta at acb5461

## Scorecards
Pass 1 [spec+plan]: 4B/2S/0C/0R · fixed -/- · velocity = (—→6, escalation no)   # fresheyes gpt-6.1-sol high at snapshot e236800, REASON=-; nothing was built yet
spec: passes: 1 · elapsed: ~15 min
Pass 1 [code:branch]: 1B/0S/0C/0R · fixed -/- · velocity = (—→1, escalation no)   # fresheyes gpt-6.1-sol high at 7f30dc0, REASON=-; its "SUBSTANTIVE (major, blocking)" read as BLOCKER (a member lost)
Pass 2 [code:delta]: 1B/0S/0C/0R · fixed 1/1 prior · velocity = (1→1, escalation no)   # fresheyes, scope git diff acb5461^ acb5461 with --rebuttals, REASON=-; the same gap under another host spelling
Pass 1 [code:branch, Stage 1]: 0B/3S/5C/0R · fixed -/- · velocity = (—→8, escalation no)   # same-model subagent at 1bdfd50; the first launch died on the seat's usage limit and was relaunched
code: passes: 2 · elapsed: ~25 min of review

## Chunks
- [x] retire splits a held notice that names a retracted id; the digest waits for it — 7f30dc0; review fix acb5461; delta and Stage 1 fixes in the commit after; main merged 1215f13, 1bdfd50

## Notes
- Start-floor evaluator not dispatched: the dispatch floors the run at medium and no hard trigger is in scope; as z360 and faxq.
- Deviation (as z360, faxq, 9kgk): spec and plan reviewed in one fresheyes pass.
- Agency not used (as every run in this repo): the plan is one chunk executed directly.
- Landed code vs issue text: the issue builds on `Run.retire`, which is on the z360 branch (pull request 67, open when this run started), not on main at v0.4.0. This branch is stacked on `origin/z360-fix-z360`; it lands after z360 does, with main merged before the review and before the merge.
- Spec+plan review dispositions. Fixed: (1, BLOCKER) the digest's `_posted` path acknowledged a struck notice whose group had posted: the wait now comes before `_posted` (test_a_held_group_that_posted_is_not_acknowledged_whole...); (2, BLOCKER) fixed id order within a notice could starve an id behind failing pages: ids rotate by the hour within a notice (test_a_failing_page_never_starves_the_survivor_behind_it); (5, SUBSTANTIVE) z360's `_retract` helper needs posted roots: own helper `_strike`. Found while fixing (2): a released member was merged back into its struck notice by the next sighting of the group: `hold` skips a struck notice (test_a_released_member_is_not_taken_back_by_the_notice_it_left). Rebutted: (3, BLOCKER as raised) two held rows each taking the other's ids when sighted as one group: `Run.hold` does this today for any two notices held apart, no advisory is lost, filed ai-tools-alerts#1e90; (4, BLOCKER as raised) a member past the 20-source cap: the same limit z360 states, more than 20 advisories in one group, the spec now says it can stay undecided, filed ai-tools-alerts#5rra; (6) the snapshot commit's message: the snapshot never lands. The general case behind (1), a notice acknowledged by `_posted` before any retraction, is z360's thread path: filed ai-tools-alerts#1m9f.
- Mutation checks (each fails at least one new test): no digest wait (7); the wait after `_posted` (1); no source union (1); no `digested` write (4); `hold` takes a struck notice (1); no id rotation (1).
- Whole-change review (7f30dc0), fixed in acb5461: a notice held by the earlier version keeps no source for a member that joined later, so after a retraction the member was judged by the wrong page and dropped as counted. Such a GHSA id is read at its page in each repository the notice names (test_a_member_a_notice_kept_no_source_for_is_read_beside_the_others; mutation-checked).
- Delta (acb5461), fixed without a further pass per the Review Cycle: the fix compared the literal host; it now reads it as `rules.host_of` does (the test's `github.com./` case; mutation-checked). The delta ran with explicit scope text, not `--since`: `--since 7f30dc0` would have taken in the z360 merge and two merges of main.
- Stage 1 dispositions. Fixed: (1) an id no page confirms stayed undecided run after run once the notice kept nine or more sources (the per-candidate page budget): each id is judged over at most MAX_PAGES sources chosen for it (`_pages_for`; test_a_held_survivor_whose_page_is_gone_is_dropped_with_the_notice, not mutation-checked); (2) the guessed page URL carried a thread key's slug: built from the bare id (test_a_scoped_id_with_no_source_is_read_at_its_bare_ids_page); (3) test gaps: the lead id released while another waits, with a reload (test_a_notice_whose_lead_id_is_released_is_led_by_the_next_and_loads) and a kept id that is no CVE; (4) and (7) spec wording; (5) one notice's failure no longer stops the others, and a failed state write stops the run as any save does; (6) an expired struck notice is left to the digest. Rebutted: (8) rotation by the hour does nothing for runs spaced a multiple of the list length apart: the poster runs hourly, and z360's thread rotation has the same property; (3, rest) no test for the journaled-digest skip or for `_part_retracted` on an expired or synthetic notice: read, not tested.
- These Stage 1 fixes and the delta fix landed after the last independently reviewed sha acb5461 without a further pass: the commit after it holds them.
- Gate: the run on 1215f13 is void (the fix was edited while it ran; its one failure, tests/test_never_supported_cli.py::test_for_48_hours_after_a_rebuilt_record_nothing_shows_at_notice, passes alone, 61 passed in the file); the run on 1bdfd50 was stopped for the Stage 1 fixes; the run on 38c9a19 failed the same one test (1 failed, 3858 passed), which is the known flaky test of ai-tools-alerts#gecm: it passed alone, with every non-poster test, and after each poster test file singly, and a whole-suite run on clean main passed. `scripts/test-gate.sh` passed on 90dd9d5 (main merged: 3909 passed) and on 5827492 (main merged again, yd1y, which changes the same file: 3933 passed).
- The session lost about 80 minutes to the seat's usage limit (01:03 to 02:23 UTC).
- Prior work: z360 (threads; rebutted held notices there and filed this issue), faxq (fix groups, held notices take a group's ids), d3f6 (digest leaves out retracted), 8ke5 (held notices, listable), qwpw (weekly summary lists notices).
