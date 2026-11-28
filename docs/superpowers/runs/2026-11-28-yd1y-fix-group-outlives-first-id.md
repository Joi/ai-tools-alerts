# Run: yd1y-fix-group-outlives-first-id
Instruction: Read TASK-ai-tools-alerts#yd1y.md in this worktree root, then run `kata show ai-tools-alerts#yd1y` and follow the brief and the dispatch rules (do-it, start rung floored at medium; pull-request landing; one independent review).
Stage: code-review:release-and-repost
Rung: medium (start-floor medium: dispatch floor; no hard trigger in scope: no secrets, auth or deploy path)
Spec: docs/superpowers/specs/2026-11-28-yd1y-fix-group-outlives-first-id-design.md   Plan: docs/superpowers/plans/2026-11-28-yd1y-fix-group-outlives-first-id.md
Agency project: —
Kata: ai-tools-alerts#yd1y
Limits (recorded before any review): wall clock 5 hours from 2026-11-28T00:35Z; review shape one independent pass per artifact, one delta only after a behaviour-changing BLOCKER fix; completion check: the acceptance test of the issue passes and the pull request is merged or its blocker is named.

Last reviewed: spec+plan 10b535560342a5b52fc2179e2bbe120a3b36662f

## Scorecards
Pass 1 [spec+plan]: 4B/1S/0C/0R · fixed -/- · velocity = (—→5, escalation no)   # fresheyes gpt-6.1-sol high at 10b5355, REASON=-
spec+plan: passes: 1 · elapsed: ~15 min

## Chunks
- [ ] release and repost the members of a fix group whose first id fell

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
- The acceptance test and the code were drafted before the spec review, to find out what the release mechanism needed; the review's findings apply to both.
