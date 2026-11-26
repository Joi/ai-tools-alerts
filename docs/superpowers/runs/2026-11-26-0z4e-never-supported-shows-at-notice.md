# Run: 0z4e-never-supported-shows-at-notice
Instruction: Read TASK-ai-tools-alerts#0z4e.md in this worktree root, then run `kata show ai-tools-alerts#0z4e` and follow the brief and the dispatch rules pasted after this sentence. (Run as /do-it, starting rung floored at medium.)
Stage: done (the pull request and its merge commit are in the kata close-out comment)
Rung: medium (start-floor medium: constraint-lens, BR1 REV1 NOV1 INT2 FC1 = 6; no hard trigger; the dispatch brief floors it at medium too)
Lens: "Nothing you build may wait for a person to act."; the per-thread memory "must not live in `verify.json`"; "a failed read changes nothing"; "`tests/test_wire_compat.py` is untouched"; "No host, tailnet, VM or home-path names and no personal email in any commit, PR text or run record."
Last reviewed: spec 70993958521672300864f312b619e9a82f4fb937
Spec: docs/superpowers/specs/2026-11-26-0z4e-never-supported-shows-at-notice-design.md   Plan: docs/superpowers/plans/2026-11-26-0z4e-never-supported-shows-at-notice.md
Agency project: — (no agency tools in this session; the plan is executed in-session)
Kata: ai-tools-alerts#0z4e
Limits: wall clock 5 hours from 2026-11-26T01:48Z; one independent pass per artifact (spec, plan, code), one delta only after a behaviour-changing BLOCKER fix, three review rounds at most; completion check: the three acceptance cases of the issue pass as tests in `scripts/test-gate.sh`.

Last reviewed: plan c566f55b784d3e797fc198cedbb10a106eaabaff
Last reviewed: code 34bf5f061d617940e9c265cdfd39dadb552e79f8 (whole branch)

## Scorecards
Pass 1 [spec]: 5B/3S/0C/0R · fixed -/- · velocity = (—→8, escalation no)
passes: 1 · elapsed: 5 min

Spec pass 1 (fresheyes, gpt-6.1-sol, high, on 7099395; the reviewer rated all eight "major"; the split into BLOCKER and SUBSTANTIVE is this run's). What was done is in the spec's "Review dispositions":
- BLOCKER, fixed: a "no support" finding outlived the ruleset it was made under (the record carries the digest).
- BLOCKER, fixed: a concurrent command could overwrite a completed read before the memory saw it (a command hands over its own results under the lock; the rules order by read time).
- BLOCKER, fixed: a `gone` dated ahead of the clock never mended (times are cut to the clock).
- BLOCKER, fixed: a confirmed `high` was never read again (every relay-bot match here is read again daily).
- BLOCKER, fixed: a failed read removed the 48-hour line (the line comes from the memory, `seen - gone`).
- SUBSTANTIVE, fixed in part, rebutted in part: aliases. Support read beside a failing alias now ends a demotion (`verify.judge` reports it). That a post can make itself unreadable with aliases is how the source check has read aliases since fv4g; it leaves the alert as it is today. Follow-up ai-tools-alerts#2mgd.
- SUBSTANTIVE, rebutted: a respelled product is matched and never judged. The same: fv4g judges exact scope names for every row of the table. Follow-up ai-tools-alerts#2mgd.
- SUBSTANTIVE, fixed: three existing tests contradict the design (named in the spec, with a fourth).
Rung stays medium: every BLOCKER fixed, every SUBSTANTIVE fixed or rebutted.

Pass 1 [plan]: 4B/0S/0C/0R · fixed -/- · velocity = (—→4, escalation no)
passes: 1 · elapsed: 6 min

Plan pass 1 (same reviewer, on c566f55; four "major", taken as BLOCKERs, all fixed; the spec's "Review dispositions (plan)" names the test for each):
- the first copy's widest state stood for every root of a merged entry;
- the record was cut to this command's own thread list, also under the lock;
- budget exhaustion in `verify.run` discarded support already read and re-dated an old "unsupported";
- a read whose cache could not be written never reached the memory.
Rung stays medium.

Pass 1 [code:all]: 3B/2S/4C/0R · fixed -/- · velocity = (—→9, escalation no)
passes: 1 · elapsed: 11 min (Stage 2, fresheyes gpt-6.1-sol high on `git diff origin/main...34bf5f0`, and Stage 1, a same-model subagent, in parallel)
Rung: climbs medium -> heavy here. Cause (do-it's evidence rule): the three BLOCKER fixes change behaviour, so they get the one delta pass (fresheyes `--since 34bf5f0`). No hard trigger.

Code pass 1, what was found and done: the spec's "Review dispositions (code)". Stage 2: 3 BLOCKER (support read through a lowering's question; a result dated ahead of the clock never read again; `_settled` re-dating old "no support"), all fixed. Stage 1: 2 SUBSTANTIVE (a later thread inherited an older thread's read; the whole-thread demotion untested) and 4 COSMETIC, all fixed.

Pass 2 [code:all]: 3B/0S/0C/0R · fixed 5/5 prior · velocity ↓ (9→3, escalation no)
passes: 2 · elapsed: 30 min (the one delta, fresheyes `--since 34bf5f0`, over the fixes at 59ecdfdbcb0eaaa8bb85144b2e1d1c11ac5d707d; no rebuttals file: every finding of pass 1 was fixed)

Delta findings (three "major", none a finding of pass 1 left open), all fixed in the commit after 59ecdfd, which no review saw; the gate ran on it. The spec's "Review dispositions (code, the delta)" names the test for each: a kept refusal read as fresh support; a result dated ahead of the clock sorted behind failing threads; a record found damaged under the lock. No further pass (review cycle: one review, one delta).

Mutations (scratch copies, against tests/test_never_supported_cli.py, at the tree of 59ecdfd): 17 run, 17 fail a named test. Among them: no whole-thread demotion; the record cut by the stale event set; no first-seen rule; lowered states not read for support; the judged state replaced by the current one; demotion from the cache instead of the memory; the hand-over ignored; copies merged whatever their history; the digest ignored.

Gate: `scripts/test-gate.sh` in a clone holding only this branch passed at 34bf5f0 (2939 passed, 1 skipped); the result at the final head is in the kata comment.

Existing tests edited (the issue changes what they expect): `tests/test_unverified_cli.py::test_an_alert_the_source_contradicts_is_unverified_and_says_so` (now about `above-source`; the unsupported case is acceptance 1), `::test_a_copy_of_a_post_confirmed_earlier_is_not_confirmed_with_it` (the flag comes past 48 hours), `tests/test_unchecked_lowering.py::test_a_damaged_record_is_flagged_and_never_an_error` (the key set), `tests/test_verify.py::test_judge` (one row), `tests/test_verify_cli.py::test_an_alert_the_source_does_not_support_is_flagged_per_product` (a substring count). One existing test failed for a real defect and was not edited: `test_the_source_withdraws_and_the_lowering_is_accepted` (a `confirmed` result now clears a remembered "none").

## Chunks
- [x] verify: an incomplete read reports the support it read; budget exhaustion; `Unsaved` (aitools_alerts/verify.py)
- [x] state: the support memory in `unverified.json` (aitools_alerts/state.py)
- [x] CLI: the memory is kept, a never-supported match shows at notice, the 48-hour flag (aitools_alerts/cli.py)
- [x] docs: README, CHANGELOG.md

## Notes
- The repo has no repoman marker: the ending is a pull request this session merges (TASK brief), not a repoman handoff.
- Seat rule: nothing outside the worktree is read, except the pipeline's own evaluator prompt. The review tools are run, not read.
- Size: about 350 lines of code and 700 of tests, past the 600-line guideline. Not split: one deliverable; the `verify.py` changes exist only for this rule (decided, in the kata comment).
- Follow-up filed: ai-tools-alerts#2mgd (a post can keep the source check from judging it). A note on ai-tools-alerts#m729 says where a strike can be counted.
- A lapse, corrected: the first revision of the spec after its review was made with a script, not the edit tool. Each replacement was then checked to have landed; later artifact edits used the edit tool.
- No fresheyes stall or retry in this run.
- Prior work searched: the issue and its links (tavj, m729, h29n, 3qyq, jsje), `docs/superpowers/specs/2026-11-25-tavj-apply-source-check-result-design.md` and its run record. No other issue covers this row of the D8 table.
