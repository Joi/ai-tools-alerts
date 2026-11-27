# Run: p93w-checkpoint-dated-when-signed
Instruction: Read TASK-ai-tools-alerts#p93w.md in this worktree root, then run `kata show ai-tools-alerts#p93w` and follow the brief and the dispatch rules pasted after this sentence. (Run as /do-it, starting rung floored at medium. The task file was empty; the issue text is the brief.)
Stage: code-review:whole-branch
Rung: heavy (start-floor heavy: hard-trigger, BR1 REV1 NOV1 INT2 FC2 = 7; the dispatch brief floors at medium). The evaluator's cause: the diff edits `signer.run_checkpoint`, which reads the checkpoint key and checks its certificate, and changes the time that certificate check is judged by. It called the reading literal, not clear-cut; the rung is not the executor's to lower. Lens: "No wire format, schema, manifest, ruleset or state file shape changes."
Last reviewed: spec 0e4db468139b09a1189ec60463da2a75d0d480e3 (whole), 7fad14f418c0bc3c8d03e95d4fb993d471c0fdad (delta)
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

## Notes
- The tests were drafted while the spec and plan reviews ran, and the plan's whole review was launched beside the spec's delta, to keep inside the wall-clock limit; no code under `aitools_alerts/` changed before the plan's first pass returned. The code was written while the plan's delta ran, to the plan as fixed.
- The repository has no `.repoman-managed` marker and no row in the repoman registry: the ending is a pull request this session merges (global rule for unmanaged repos), and the gate is `scripts/test-gate.sh` in a clone that holds this branch alone (the shared clone's public scan reads other sessions' refs).
- Prior work read: ai-tools-alerts#r0ra (both decided comments), ai-tools-alerts#gtw9 (the decided comment, the close-out, its spec lines 88 to 92 and its run record's "left open").
