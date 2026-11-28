# Run: yd1y-fix-group-outlives-first-id
Instruction: Read TASK-ai-tools-alerts#yd1y.md in this worktree root, then run `kata show ai-tools-alerts#yd1y` and follow the brief and the dispatch rules (do-it, start rung floored at medium; pull-request landing; one independent review).
Stage: verifying
Rung: medium (start-floor medium: dispatch floor; no hard trigger in scope: no secrets, auth or deploy path)
Spec: docs/superpowers/specs/2026-11-28-yd1y-fix-group-outlives-first-id-design.md   Plan: docs/superpowers/plans/2026-11-28-yd1y-fix-group-outlives-first-id.md
Agency project: —
Kata: ai-tools-alerts#yd1y
Limits (recorded before any review): wall clock 5 hours from 2026-11-28T00:35Z; review shape one independent pass per artifact, one delta only after a behaviour-changing BLOCKER fix; completion check: the acceptance test of the issue passes and the pull request is merged or its blocker is named.

Last reviewed: spec+plan 10b535560342a5b52fc2179e2bbe120a3b36662f
Last reviewed: code df86283a4afe49a8a98e2ab1958123f0c6f3d1b6 (git diff 1d2e616 df86283: the whole change on top of z360); delta --since df86283 at 59a55f8df130d43c6eb674de1a8f3428d36752a0

## Scorecards
Pass 1 [spec+plan]: 4B/1S/0C/0R · fixed -/- · velocity = (—→5, escalation no)   # fresheyes gpt-6.1-sol high at 10b5355, REASON=-
spec+plan: passes: 1 · elapsed: ~15 min
Pass 1 [code:release-and-repost]: 5B/1S/0C/0R · fixed -/- · velocity = (—→6, escalation no)   # fresheyes gpt-6.1-sol high at df86283, REASON=-
Pass 1 [code:release-and-repost, Stage 1]: 0B/5S/3C/0R · fixed -/- · velocity = (—→8, escalation no)   # same-model subagent; stopped once on the seat's usage limit and resumed on the working tree with the fresheyes fixes

Pass 2 [code:delta]: 1B/1S/0C/0R · fixed 6/6 prior · velocity ↓ (6→2, escalation no)   # fresheyes --since df86283 --rebuttals at 59a55f8, REASON=-; its two 'major': the wrong keep read as BLOCKER, the missing tests as SUBSTANTIVE; no standing rebuttal overturned
code: passes: 2 · elapsed: ~40 min

## Chunks
- [x] release and repost the members of a fix group whose first id fell — df86283; review fixes 59a55f8; delta fixes 2a-commit below; main merged (z360, changelog under Unreleased)

## Notes
- Start-floor evaluator not dispatched: the dispatch floors the run at medium and no hard trigger is in scope; as z360, faxq.
- Deviation (as z360, faxq, 9kgk): spec and plan reviewed in one fresheyes pass.
- Agency not used (as every run in this repo): the plan is one chunk executed directly.
- Prior work: kata search "fix group": z360 (partial retraction; its release mechanism is reused), 9je7 (held notices, open), btqg (join by fix; this issue was filed from its spec review), 3qyq (first-id rule), faxq (fix groups). No experiment issue on the subject.
- Dependency: the branch merges origin/z360-fix-z360 at 46ebb37 (pull request 67, open, mergeable). Decision and rejected options: the `decided:` comment on the issue.
- Landed code vs issue text: "steps down at renewal time" is the 44-day step of `Run._renew`.
- Spec+plan review dispositions, all fixed, each with a test: (B1) member reads starved by other threads' reads: each thread is judged and then parted in its own turn, members read in its lane (test_members_are_read_though_other_threads_spend_the_lane; mutation-checked); (B2) a thread already stepped down to notice could not release: the rule compares the member's level with what the first id's sources state, not with the thread's level (test_a_thread_already_stepped_down_to_notice_still_releases_its_member); (B3) a pointer replayed after a stopped run could raise the old thread's prose floor and block the split: the rule reads fields only, no prose floor (test_a_member_whose_title_raised_the_prose_floor_still_leaves; mutation-checked); (B4) a released id the first id's response comes to name was still left out: support leaves out a released id only while no source ties it (test_a_released_id_the_first_id_comes_to_name_counts_again; mutation-checked); (S5) the bare_ids mutation check proved nothing: bare_ids is unchanged and the mutation is of support's loop. No rebuttal.
- Consequence of B2, said in the changelog: a member that comes to support more than a first id that still supports the thread's level now leaves and posts its own root (before: "lends no level", nothing posted). tests/poster/test_advisory_recompute.py passes unchanged.
- Mutation checks: no join condition in _fix_thread fails test_a_released_member_does_not_join_the_thread_it_left; no released ids in support's loop fails the acceptance test and the counts-again test; parting after all judging fails the lane test; the prose floor in lead fails the prose-floor test.
- Follow-up filed: ai-tools-alerts#759h (a group whose members all support no more than its first id still lowers only by the 44-day step).
- Gate at df86283 (clone of the branch alone): 2 failed, 3860 passed. Both failures were real and are fixed: test_two_advisories_that_joined_together_leave_one_at_a_time (fresheyes B5) and test_a_candidate_on_the_run_a_lowering_falls_due_is_seen_before_anything_is_lowered (a vendor's GHSA beside its CVE was released as if another advisory: now kept; mutation-checked).
- Code review dispositions, fresheyes, all fixed: (B1) a member retracted after it left stranded the first advisory: retire judges a thread whose released ids hold a retracted one, Ledger.release(back=) (test_a_member_retracted_after_it_left_does_not_strand_the_first_advisory; mutation-checked twice); (B2) lead never recorded the KEV listing: it does (test_the_listing_of_a_first_cve_is_remembered_for_a_thread_with_members; mutation-checked); (B3) fixed member order: rotation (test_a_member_past_the_lanes_share_is_read_in_a_later_turn; mutation-checked); (B4) a member supporting nothing was released with no pointer: only members that support more leave, each with a pointer; (B5) the btqg test and contract: same narrowing, the test passes unchanged; (S6) page budget checked before a call that can fetch eight: Run.page_cap at each fetch (no test).
- Code review dispositions, Stage 1: fixed (1) an exploited mark lent by merge to a released id's candidate: dropped in one() when no KEV reading stands behind it (no test); (2) member rotation aliased with the thread rotation: the turn is the hour divided by the lane's size; (3) docs said every read member leaves: changelog and spec corrected; (4) the stopped-run test caught its own error: it now raises through the run; (5) missing tests: added, with a mixed group and a group whose advisories each have a CVE. Rebutted: (6) two threads holding one retracted id after a take-back: both are hidden and a candidate naming a retracted id is never planned; (7) a z360 retired thread can now be judged known: it is hidden on every reader and z360 already leaves its replies as they are. Cosmetic 8: page_cap set in __init__, unused variable dropped; the other two noted, unchanged.
- Delta dispositions (fixed in the commit after 59a55f8, no further pass per the Review Cycle): (B) an id released in an earlier run, still named by the root, made a later member whose page assigns it "kept" for good: ids the thread released are not its own ids (test_an_id_released_before_does_not_keep_a_later_member; mutation-checked); (S) no test for the page cap or for the exploited mark: test_a_members_pages_stop_at_the_release_budget, test_a_released_ids_candidate_keeps_only_a_kev_mark_of_its_own (the mark's rule moved into Run._own_mark to be testable).
- Unreviewed after the delta's head 59a55f8: the delta-fix commit and the merge of origin/main (z360's own merge, changelog moved under Unreleased; conflict in CHANGELOG.md resolved by moving the yd1y entry there). `git diff 59a55f8..HEAD -- aitools_alerts tests` shows the code part.
- Rung: stayed medium by the dispatch's rule (no surviving unfixed finding, no hard trigger); the one delta is the Review Cycle's for a behaviour-changing BLOCKER fix.
- Review rounds used: spec+plan 1, code 1, delta 1 (limit three).
- The acceptance test and the code were drafted before the spec review, to find out what the release mechanism needed; the review's findings apply to both.
