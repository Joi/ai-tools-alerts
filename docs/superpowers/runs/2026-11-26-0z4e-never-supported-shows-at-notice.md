# Run: 0z4e-never-supported-shows-at-notice
Instruction: Read TASK-ai-tools-alerts#0z4e.md in this worktree root, then run `kata show ai-tools-alerts#0z4e` and follow the brief and the dispatch rules pasted after this sentence. (Run as /do-it, starting rung floored at medium.)
Stage: spec-review
Rung: medium (start-floor medium: constraint-lens, BR1 REV1 NOV1 INT2 FC1 = 6; no hard trigger; the dispatch brief floors it at medium too)
Lens: "Nothing you build may wait for a person to act."; the per-thread memory "must not live in `verify.json`"; "a failed read changes nothing"; "`tests/test_wire_compat.py` is untouched"; "No host, tailnet, VM or home-path names and no personal email in any commit, PR text or run record."
Last reviewed: spec 70993958521672300864f312b619e9a82f4fb937
Spec: docs/superpowers/specs/2026-11-26-0z4e-never-supported-shows-at-notice-design.md   Plan: docs/superpowers/plans/2026-11-26-0z4e-never-supported-shows-at-notice.md
Agency project: — (no agency tools in this session; the plan is executed in-session)
Kata: ai-tools-alerts#0z4e
Limits: wall clock 5 hours from 2026-11-26T01:48Z; one independent pass per artifact (spec, plan, code), one delta only after a behaviour-changing BLOCKER fix, three review rounds at most; completion check: the three acceptance cases of the issue pass as tests in `scripts/test-gate.sh`.

Last reviewed: plan c566f55b784d3e797fc198cedbb10a106eaabaff

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

Existing tests edited (the issue changes what they expect): `tests/test_unverified_cli.py::test_an_alert_the_source_contradicts_is_unverified_and_says_so` (now about `above-source`; the unsupported case is acceptance 1), `::test_a_copy_of_a_post_confirmed_earlier_is_not_confirmed_with_it` (the flag comes past 48 hours), `tests/test_unchecked_lowering.py::test_a_damaged_record_is_flagged_and_never_an_error` (the key set), `tests/test_verify.py::test_judge` (one row), `tests/test_verify_cli.py::test_an_alert_the_source_does_not_support_is_flagged_per_product` (a substring count). One existing test failed for a real defect and was not edited: `test_the_source_withdraws_and_the_lowering_is_accepted` (a `confirmed` result now clears a remembered "none").

## Chunks
- [ ] state: the support memory in `unverified.json` (aitools_alerts/state.py)
- [ ] CLI: the memory is kept, a never-supported match shows at notice, the 48-hour flag (aitools_alerts/cli.py)
- [ ] docs: README, CHANGELOG.md

## Notes
- The repo has no repoman marker: the ending is a pull request this session merges (TASK brief), not a repoman handoff.
- Seat rule: nothing outside the worktree is read, except the pipeline's own evaluator prompt. The review tools are run, not read.
- Prior work searched: the issue and its links (tavj, m729, h29n, 3qyq, jsje), `docs/superpowers/specs/2026-11-25-tavj-apply-source-check-result-design.md` and its run record. No other issue covers this row of the D8 table.
