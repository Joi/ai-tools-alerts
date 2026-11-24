# Run: tavj-apply-source-check-result
Instruction: Read TASK-ai-tools-alerts#tavj.md in this worktree root, then run `kata show ai-tools-alerts#tavj` and follow the brief and the dispatch rules pasted after this sentence. (Run as /do-it, starting rung floored at medium.)
Stage: plan-review
Rung: medium (start-floor medium: constraint-lens, BR1 REV1 NOV1 INT1 FC1 = 5; no hard trigger; the dispatch brief floors it at medium too)
Lens: "Nothing you build may wait for a person to act." / "No rollout." / no host, tailnet, VM or home-path names and no personal email in any commit, PR text or run record / "`tests/test_wire_compat.py` still passes (a released reader keeps the higher level)".
Spec: docs/superpowers/specs/2026-11-25-tavj-apply-source-check-result-design.md   Plan: docs/superpowers/plans/2026-11-25-tavj-apply-source-check-result.md
Agency project: — (no agency tools in this session; the plan is executed in-session)
Kata: ai-tools-alerts#tavj
Limits: wall clock 5 hours from 2026-11-24T20:51Z; one independent pass per artifact, one delta only after a behaviour-changing BLOCKER fix, three review rounds at most; completion check: the five acceptance tests of the issue pass in `scripts/test-gate.sh`, `tests/test_wire_compat.py` among the suite.

Last reviewed: spec 2360315ef9cb4d493c2e4cbf05e55e77e661bec7

## Scorecards
Pass 1 [spec]: 3B/1S/0C/0R · fixed -/- · velocity = (—→4, escalation no)
passes: 1 · elapsed: 11 min

Spec pass 1 findings and what was done (reviewer: fresheyes, gpt-6.1-sol, high):
- BLOCKER: a wait that had run out survived a change of the thread that discarded a known refusal (the results are keyed by the published state, the wait by the reply). Fixed: a refusal is remembered by the reply's id (`State.refused`) and the wait does not run while it is; it ends only on a confirmation or on whole reads that give no more. And the alias a refusal came through is read first (`verify._Run.thread`, `weight`).
- BLOCKER: an old confirmation exempted every later post with the same published state from the cap. Fixed: the exemption needs a result read within 48 hours, a confirmed state gives one slot per 24 hours, and `run` reads a critical match's source again daily.
- BLOCKER: with every channel failing, or none configured, no slot was used, while `run` still exits 2 and the hook interrupts. Fixed: the slot is taken when the interrupt is reported (`_notify` records the grants before it tries a channel); an alert that holds a slot is retried without a second one.
- SUBSTANTIVE: a damaged `unverified.json` raised `StateError` and stopped every later run until a person mended it. Fixed: the record is rebuilt (`cli._mend`), waits start again, and no unverified slot is given for 24 hours.

Pass 1 [plan]: 5B/1S/0C/1R · fixed -/- · velocity = (—→7, escalation no)
passes: 1 · elapsed: 14 min (the first launch ended `FRESHEYES_STALLED REASON=CHILD_EXIT`: the reviewer's model was at capacity, an environment failure; the one retry gave the review)

Plan pass 1 findings and what was done (same reviewer, on cb5e6087298f2a0e2c020ef6dfb8d069ce5b757f):
- BLOCKER: chunk 1 changed how a check is called while the CLI's check changed in chunk 3, so the tests between could not pass; `cmd_verify` called it with two arguments. Fixed in the plan: every caller moves in chunk 1. The code already passed `stated` everywhere.
- BLOCKER: `cmd_notify` was not routed through the slots. The code already did; the plan now says so, and `test_the_notify_command_is_capped_too` holds it.
- BLOCKER: a grant refused under the lock was still reported (exit 2, `unseen_critical`), because the report was built before the lock. Fixed: `cli._reserve` records the grants first and returns what stands; `cmd_run` and `cmd_notify` report from it; `test_a_slot_a_concurrent_run_took_is_not_reported_as_an_interrupt`.
- BLOCKER: the spec said every accepted result needs every source an authority, and `match` does not. Fixed in the spec, not in the code: the sentence was wrong. `match` is an authority's positive word for exactly the level; a record that is no authority sets notice at most by the ruleset, so it cannot hold support above a lowered level, and requiring it would make an advisory that names a CVE the catalog does not list (most of them) unconfirmable. `test_a_matching_authority_beside_a_source_that_is_none_still_confirms` states both sides.
- BLOCKER: the loader's limit (5000) had no matching bound on what is written. Fixed: `refused` is keyed by thread root and cut to the threads that exist; the limit is the store's limit on events, 20000; `test_the_record_holds_as_many_entries_as_the_store_holds_events`.
- SUBSTANTIVE: no plan step appended `Not verified from this machine`. The code did; the plan now has the step, and the tests assert it for unknown, contradicted and `verify = "off"`.
- Not taken (restatement, as in the c1g2 run): the message of the review snapshot commit. It is a dangling object made for the reviewer and lands nowhere.

## Chunks
- [ ] reader: what a thread stated and who offered a lowering; the 72-hour rule (aitools_alerts/pull.py, aitools_alerts/state.py)
- [ ] member check: a lowering below the reading cap, a withdrawal, a delisting (aitools_alerts/verify.py)
- [ ] CLI: the wait record, the two-interrupts cap, the lines and JSON keys (aitools_alerts/cli.py)
- [ ] docs: README, spec/wire.md, CHANGELOG.md

## Notes
- The repo has no repoman marker: the ending is a pull request this session merges (TASK brief), not a repoman handoff.
- Seat rule: nothing outside the worktree is read, except the pipeline's own evaluator prompt. The review tools are run, not read.
- Split before building (decided, in the kata comment): "the source never supported it: show at notice" with its 48-hour rule, and the comparison of narrowings, are separate issues. This run builds the 72-hour rule, the claim-based confirmation, the unverified mark and the two-interrupts cap.
