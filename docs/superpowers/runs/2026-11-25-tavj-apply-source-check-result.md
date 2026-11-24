# Run: tavj-apply-source-check-result
Instruction: Read TASK-ai-tools-alerts#tavj.md in this worktree root, then run `kata show ai-tools-alerts#tavj` and follow the brief and the dispatch rules pasted after this sentence. (Run as /do-it, starting rung floored at medium.)
Stage: code-review:all (the delta)
Rung: medium (start-floor medium: constraint-lens, BR1 REV1 NOV1 INT1 FC1 = 5; no hard trigger; the dispatch brief floors it at medium too)
Lens: "Nothing you build may wait for a person to act." / "No rollout." / no host, tailnet, VM or home-path names and no personal email in any commit, PR text or run record / "`tests/test_wire_compat.py` still passes (a released reader keeps the higher level)".
Spec: docs/superpowers/specs/2026-11-25-tavj-apply-source-check-result-design.md   Plan: docs/superpowers/plans/2026-11-25-tavj-apply-source-check-result.md
Agency project: — (no agency tools in this session; the plan is executed in-session)
Kata: ai-tools-alerts#tavj
Limits: wall clock 5 hours from 2026-11-24T20:51Z; one independent pass per artifact, one delta only after a behaviour-changing BLOCKER fix, three review rounds at most; completion check: the five acceptance tests of the issue pass in `scripts/test-gate.sh`, `tests/test_wire_compat.py` among the suite.

Last reviewed: spec 2360315ef9cb4d493c2e4cbf05e55e77e661bec7
Last reviewed: plan cb5e6087298f2a0e2c020ef6dfb8d069ce5b757f
Last reviewed: code 8cc1d2d08596f1fca399d8165ea462b92e0dd5ed (whole branch)

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

Pass 1 [code:all]: 3B/3S/2C/0R · fixed -/- · velocity = (—→8, escalation no)
passes: 1 · elapsed: 16 min (Stage 1, a same-model subagent, and Stage 2, fresheyes gpt-6.1-sol high on the whole branch `git diff origin/main...HEAD` at 8cc1d2d08596f1fca399d8165ea462b92e0dd5ed, in parallel)
Rung: climbs medium -> heavy here. Cause: BLOCKER fixes after the code pass change behaviour, so they get the one delta pass (fresheyes `--since 8cc1d2d`).

Code pass 1, Stage 2 (fresheyes), both fixed:
- BLOCKER: `_note_offers` computed the record before taking the lock and wrote it after, so a command that started earlier erased a refusal saved since. Fixed: under the lock the record is recomputed from the reloaded state and a freshly loaded check; `test_a_command_that_started_earlier_does_not_write_over_a_newer_refusal`.
- BLOCKER: when a run's requests ran out partway through a thread, support already read for more was stored as unread; with the 72-hour rule that lowers a true alert. Fixed: a `below-source` found before the budget ran out is kept (`verify.run`); `test_support_read_before_the_request_budget_ran_out_still_refuses`.

Code pass 1, Stage 1 (same model; it also replayed 1500 random threads through origin/main's reader and this one with no check and no record: 0 differences in 112500 comparisons, so the poster, exporter and curator paths are unchanged):
- BLOCKER: a held alert could be kept out for good, by undelivered alerts taking their slots again each day or by posts dated before it. Fixed: `State.held` records since when an alert is held and a free slot goes to the one held longest; `test_a_held_alert_gets_the_next_free_slot_before_an_earlier_dated_or_an_undelivered_one`. What stays (spec, Known limits): a queue filled with false alerts delays an unverifiable true one.
- SUBSTANTIVE: the verified slot was keyed by the published state, which includes aliases nobody reads, so copies with other aliases were each "confirmed". Fixed: the bucket is the first id and the matched product; `test_copies_of_a_confirmed_advisory_with_other_aliases_share_its_one_slot`.
- SUBSTANTIVE, twice: the two Stage 2 findings, found independently.
- COSMETIC, fixed: an alert matched through a confirmed and an unconfirmed product was both pending and held (it is decided once now); the waiting line was printed where no wait runs.

Pass 2 [code:all]: 0B/4S/0C/0R · fixed 6/6 prior · velocity ↓ (8→4, escalation no)
passes: 2 · elapsed: 34 min (the one delta, fresheyes `--since 8cc1d2d`, over the fixes at ccd1da88b3e04f2f89b245abd9caa589620a5fde; no rebuttals file: every finding of pass 1 was fixed)

Delta findings (the reviewer wrote "major" on each and failed the review; none was a finding of pass 1 left open). All four are fixed in the commit after ccd1da8, which no review saw; the gate ran on it. No further pass (review cycle: one review, one delta).
- The second pass of `run` passed no held alerts to `_reserve`, which then emptied the queue's ages. Fixed: it passes them; `test_an_hourly_run_with_failing_source_reads_keeps_the_held_queue`.
- `_reserve` replaced the held record with the caller's own view, dropping an alert another command had queued since. Fixed: entries for alerts the command did not look at are kept, unless seen or no longer stored; `test_reserving_keeps_a_held_alert_this_command_did_not_look_at`.
- Only the first confirmed product was tried for a verified slot. Fixed: each confirmed match is tried; `test_a_second_confirmed_product_s_slot_is_tried_when_the_first_is_taken`.
- A notification could describe an unconfirmed product of an alert that took its slot through another. Fixed: the confirming match goes first; `test_the_notification_describes_the_product_the_source_confirmed`.

Gate: `scripts/test-gate.sh` in a clone holding only this branch passed at 8cc1d2d (2738 passed, 1 skipped); the result at the final head is in the kata comment.

## Chunks
- [x] reader: what a thread stated and who offered a lowering; the 72-hour rule (aitools_alerts/pull.py, aitools_alerts/state.py)
- [x] member check: a lowering below the reading cap, a withdrawal, a delisting (aitools_alerts/verify.py)
- [x] CLI: the wait record, the two-interrupts cap, the lines and JSON keys (aitools_alerts/cli.py)
- [x] docs: README, spec/wire.md, CHANGELOG.md

## Notes
- The repo has no repoman marker: the ending is a pull request this session merges (TASK brief), not a repoman handoff.
- Seat rule: nothing outside the worktree is read, except the pipeline's own evaluator prompt. The review tools are run, not read.
- Split before building (decided, in the kata comment): "the source never supported it: show at notice" with its 48-hour rule, and the comparison of narrowings, are separate issues. This run builds the 72-hour rule, the claim-based confirmation, the unverified mark and the two-interrupts cap.
