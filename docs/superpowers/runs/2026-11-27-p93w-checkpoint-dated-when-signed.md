# Run: p93w-checkpoint-dated-when-signed
Instruction: Read TASK-ai-tools-alerts#p93w.md in this worktree root, then run `kata show ai-tools-alerts#p93w` and follow the brief and the dispatch rules pasted after this sentence. (Run as /do-it, starting rung floored at medium. The task file was empty; the issue text is the brief.)
Stage: done (the gate at the final head, the pull request and the merge are on the kata issue: a commit after the gated head would not have been gated)
Rung: heavy (start-floor heavy: hard-trigger, BR1 REV1 NOV1 INT2 FC2 = 7; the dispatch brief floors at medium). The evaluator's cause: the diff edits `signer.run_checkpoint`, which reads the checkpoint key and checks its certificate, and changes the time that certificate check is judged by. It called the reading literal, not clear-cut; the rung is not the executor's to lower. Lens: "No wire format, schema, manifest, ruleset or state file shape changes."
Last reviewed: spec 0e4db468139b09a1189ec60463da2a75d0d480e3 (whole), 7fad14f418c0bc3c8d03e95d4fb993d471c0fdad (delta)
Last reviewed: code 36359b31e720275f6a9a94cf74efda8ce4c66641 (whole branch, after the merge of main), 786d2d85376a148995beba665a1f5711dd5f22a1 (delta)
Review: 36359b31e720275f6a9a94cf74efda8ce4c66641 fixed+delta 786d2d85376a148995beba665a1f5711dd5f22a1 +fix (this commit: one test assertion and this record)
Last reviewed: plan 44ee3275c31788b2dba12f1306c772504493395b (whole), 8088a0c137beb09775c681a49a478a5e6d3169ee (delta)
Spec: docs/superpowers/specs/2026-11-27-p93w-checkpoint-dated-when-signed-design.md   Plan: docs/superpowers/plans/2026-11-27-p93w-checkpoint-dated-when-signed.md
Agency project: none (the agency tools are not available in this session; the plan is executed directly)
Kata: ai-tools-alerts#p93w
Limits: wall clock 5 hours from the 12:09Z dispatch (17:09Z); one independent pass per artifact, one delta only after a behaviour-changing BLOCKER fix; done when scripts/test-gate.sh is green in a clone of this branch alone and the pull request is merged with the no-reply author.

## Scorecards
Pass 1 [spec]: 3B/1S/0C/0R · fixed -/- · velocity = (—→4, escalation no)
Pass 2 [spec]: 2B/0S/1C/0R · fixed 3/3 prior · velocity ↓ (4→3, escalation no)

Pass 1 [plan]: 2B/0S/0C/0R · fixed -/- · velocity = (—→2, escalation no)
Pass 2 [plan]: 0B/0S/0C/0R · fixed 2/2 prior · velocity ↓ (2→0, escalation no)
Pass 1 [code:whole-branch]: 3B/2S/3C/0R · fixed -/- · velocity = (—→8, escalation no)
Pass 2 [code:whole-branch]: 1B/0S/0C/0R · fixed 5/5 prior · velocity ↓ (8→1, escalation no)

## Chunks
- [x] signer: the checkpoint is dated at the signing time; level changes from before a lost state file
- [x] main: the clock reaches the signer; the ledger's level changes after a loss
- [x] reader statement: spec/wire.md, docstrings, tests/test_wire_compat.py from v0.1.8 to v0.3.0, changelog

## Spec review (fresheyes, gpt-6.1-sol high, run 20261127-211738-72aa7e): 3 BLOCKER, 1 SUBSTANTIVE
1. BLOCKER. Settling a post of this run at once (it is dated before the signing time and the mirror shows it) takes it off the must-list; a crowded window would then be signed without it, where today the signer answers `too-large`. Fixed: settlement stays judged by the run's start.
2. BLOCKER. The ledger's `changed` is the attempt's time, not the reply's date, and a reply's own claim is confirmed at exactly that time: an unconfirmed renewal repeating it would pass a pair test against `(t, t)` without the reply. And a clock set back dates the reply before `t`. Fixed: `signer.answered` asks for the level reply itself (dated from `t - 600`) or a renewal confirmed strictly after `t`.
3. BLOCKER. "A clock fault costs one claim one run" was true only of a small step. Fixed in the text: the reader's existing limits are stated by the size of the step; no reader test is added for checks this change does not touch (the tests that cover them are named).
4. SUBSTANTIVE. The snapshot commit's message. Rebutted: a review snapshot is a dangling commit that never lands.

## Spec delta (fresheyes, gpt-6.1-sol high, run 20261127-212517-145b4f): 2 BLOCKER, 1 minor. The last pass on the spec; what it raised is fixed and not reviewed again.
1. BLOCKER. The 600-second allowance for a reply dated before `t` could take an earlier level reply for the missing one (two runs can be seconds apart). Fixed: no allowance; a level reply counts only when dated at or after `t`.
2. BLOCKER. After a send whose outcome was unknown, the ledger keeps the first attempt's time while the reply is dated in a later run, and a renewal made by that later run is confirmed after `t` and before the reply. Fixed: a confirmation counts only when later than `Entry.last_change`, the start of the run that recorded the reply.
3. minor. The rollback cases were stated by the size of the step, not by what each check compares. Rewritten.

## Plan review (fresheyes, gpt-6.1-sol high, run 20261127-212616-76bc16): 2 BLOCKER
1. A level reply of this run is owed with the run's time as its renewal; with the copy read up to the signing time, its own date would make it redundant and settle it, off the must-list. Fixed: the renewals `settle_owed` compares with are also taken up to the run's start; a crowded-window test with an owed level reply.
2. The compatibility test could not tell a held claim from one counted at once (the renewal held critical either way). Fixed: a third case whose late claim does not hold critical: critical under the earlier checkpoint, high under the next.

Plan delta (fresheyes, run 20261127-213057-232bc7): passed, no findings.

## Code review, whole branch at 36359b31 (round 1 of the brief's three)
Fresheyes (gpt-6.1-sol high, run 20261127-214501-e8bc95): 3 BLOCKER.
1. BLOCKER. `answered` took any well-formed claim confirmed after `u`, also one about an advisory the thread never held, which a reader does not count. Fixed: the renewals are the reader's own (`pull.threads_from`); test with a claim of another id.
2. BLOCKER as raised; fixed in the statements, not in the code. A level reply dated before `t` (a clock set back before the send) is never recognised, so a thread at notice whose source never confirms stays out of checkpoints although its reply is served. The spec's delta review had the opposite finding (an allowance before `t` can take an earlier reply for the missing one), and listing a root without its reply is the worse error. `spec/wire.md` and the changelog now say what is recognised.
3. BLOCKER. Stamps are whole seconds: a post sent in the second the run began was settled at once and left the must-list. Fixed: what may be settled is dated strictly before the run's start; tests for a root and a level reply sent in that second.

Same-model reviewer beside it: 2 SUBSTANTIVE, 3 COSMETIC.
4. SUBSTANTIVE. A raise to critical copies the root into the critical channel; no level reply exists under that copy, so after a loss it waited for a confirmation that a blocked source never gives. Fixed: a relay-bot root dated at or after `t` states the level itself (`answered`); test.
5. SUBSTANTIVE. `spec/wire.md` and the changelog said "confirmed after it was sent"; the code asks for a confirmation after the run that last recorded any reply of the thread. Fixed in the text; the design's "at most its level's life" corrected.
6. COSMETIC, not fixed: `changed` is written by the first channel recorded, so a first channel's reply settled late from the mirror can be dated before `t` with no clock fault (an unknown send, then a refused repeat). Same safe side as finding 2.
7. COSMETIC. Docstrings: fixed. Test gaps: a ledger failure gives `checkpoint=error` (test added); a curator's level reply does not count (test added).

## Code delta, `--since 36359b31` at 786d2d85 (fresheyes, run 20261127-215349-3bfb33; round 2 of three): 1 BLOCKER
1. A new test compared the owed ids in insertion order; the signer saves them sorted by id, and the ids come from random keys, so the test failed about half the time. Fixed: compared sorted. Not reviewed again. The two standing rebuttals (a reply dated before `t`; `u` moving with ordinary replies) were not re-raised.

Gate: `scripts/test-gate.sh` exit 0 at 36359b31 in a clone holding this branch alone (public scan clean, 3426 passed, 1 skipped). The run at the final head is on the kata issue.

## Second merge of main, before the pull request (ai-tools-alerts#kk2q had landed: the poster sends the withdrawal)
Conflicts: `tests/test_wire_compat.py` (main keeps v0.3.0 in `WITHDRAWAL_READERS`; the new test runs on both lists) and one paragraph of `spec/wire.md` (both sentences kept). One change of behaviour made in the merge and reviewed by no pass: `Run.level_changes` does not pass a thread in the state `withdrawn`. Since kk2q a withdrawal writes `Entry.changed`; it names no level, so `signer.answered` would never find its reply, and the poster renews nothing there, so the thread would have stayed out of checkpoints, against kk2q's own rule that such a thread is listed. Test: `tests/poster/test_renew.py::test_a_withdrawn_thread_is_not_passed`.

## Notes
- Skip-temptations: none acted on. The evaluator's heavy floor cost two extra passes (spec and plan deltas); both found or confirmed something.
- A directive arrived mid-run with the brief the empty task file should have carried (kata comments on the issue): main was merged before the code review, the limit is three review rounds, the rollout note is on ai-tools-alerts#5fry.
- The tests were drafted while the spec and plan reviews ran, and the plan's whole review was launched beside the spec's delta, to keep inside the wall-clock limit; no code under `aitools_alerts/` changed before the plan's first pass returned. The code was written while the plan's delta ran, to the plan as fixed.
- The repository has no `.repoman-managed` marker and no row in the repoman registry: the ending is a pull request this session merges (global rule for unmanaged repos), and the gate is `scripts/test-gate.sh` in a clone that holds this branch alone (the shared clone's public scan reads other sessions' refs).
- Prior work read: ai-tools-alerts#r0ra (both decided comments), ai-tools-alerts#gtw9 (the decided comment, the close-out, its spec lines 88 to 92 and its run record's "left open").
