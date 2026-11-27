# Run: kk2q-poster-withdrawn-state
Instruction: Read TASK-ai-tools-alerts#kk2q.md in this worktree root, then run `kata show ai-tools-alerts#kk2q` and follow the brief and the dispatch rules pasted after this sentence. (The brief: ai-tools-alerts#kk2q, the poster reaches, sends and leaves the withdrawn state, D4 and D13; run as /do-it, starting rung medium.)
Stage: code-review:poster
Rung: medium (start-floor medium: constraint-lens, BR2 REV2 NOV1 INT2 FC2 = 9; no hard trigger; the dispatch floors it at medium too)
Lens: "every released reader still shows the alert"; "Nothing you build may wait for a person to act"; "No rollout in this task: no install, signing step or release" (in every review pass)
Last reviewed: spec f31d14cb13bb18a4c8376a2df230565282d7afca
Last reviewed: plan 70fb531e80e1eb0f96f8db62149c80cfb86f8d05
Spec: docs/superpowers/specs/2026-11-27-kk2q-poster-withdrawn-state-design.md   Plan: docs/superpowers/plans/2026-11-27-kk2q-poster-withdrawn-state.md
Agency project: — (no Agency tools in this session; the tasks are executed here, test first)
Kata: ai-tools-alerts#kk2q
Limits: wall clock 5 hours from the 2026-11-26T20:25Z dispatch of working time; review shape one independent pass per artifact on gpt-6-astra (the issue calls it security-shaped), one delta only after a behaviour-changing BLOCKER fix; completion check `scripts/test-gate.sh` green and the pull request merged with the no-reply author.
Landing: the repository has no `.repoman-managed` marker, so the ending is the brief's: gate, one independent review, a pull request this session merges, the issue closed on the merge commit.

## Scorecards
Pass 1 [spec]: 6B/1S/0C/0R · fixed -/- · velocity = (—→7, escalation no)
spec: passes 1 · gpt-6-astra through fresheyes on snapshot f31d14c

Spec findings and what was done (the reviewer called six of them BLOCKER):
1. A channel can miss the withdrawal or the reply that ends it for good (the journal gives up a reply refused twice). Fixed for the reply that ends the state, the side that could leave an alert hidden: the ledger keeps the state by channel and the recompute keeps sending to the channels still listed. Rebutted for a missed withdrawal: that channel shows the alert, the higher side, as a channel that missed any lowering does today.
2. A replayed withdrawal and the reply that ends it can carry the same second and read in either order. Fixed: no reply that ends the state in the run that recorded the withdrawal.
3. The return to notice when the advisory no longer names the product carries no claim of notice, so a later withdrawal of that thread is never confirmed. Taken as SUBSTANTIVE and rebutted: the issue asks for this exit, no claim can state a level no source gives, and the result errs high (a lowering to notice after 72 hours instead of a hiding). Stated in the spec and in `spec/wire.md`.
4. `settle_gone`, `settle_owed` and `window` can still unlist the withdrawal reply. Taken as SUBSTANTIVE and rebutted: those are the fault paths (a mirror that hides an event, a thread too large for a checkpoint), built to fail high, and they treat a lowering's reply the same way. The spec now says the `lapsed` change covers the passing of time only.
5. Criterion 2 promised a level `pull.advisories` does not show when the thread returns below its widest level. Fixed: the criterion says what the reply does on the reader.
6. No test section; v0.3.0 is not in the released list. Fixed: a Tests section; v0.3.0 joins `tests/test_wire_compat.py`.
7. SUBSTANTIVE, rebutted: the snapshot commit's message. It is a dangling review snapshot and never lands.
Rung after the pass: medium. Every finding is fixed or rebutted above.

Pass 1 [plan]: 3B/3S/0C/0R · fixed -/- · velocity = (—→6, escalation no)
plan: passes 1 · gpt-6-astra through fresheyes on snapshot 70fb531 · all six fixed in the plan

Plan findings and what was done:
1. BLOCKER: Task 1's tests build `Entry(withdrawn=...)`, which Task 2 adds. Fixed: the order is 2, 1, 3, 4, 5, 6.
2. BLOCKER: two existing tests expect notice after a withdrawn malware advisory (`test_copy_on_raise.py`, `test_claims.py`), and `level_claims` would not see the withdrawal. Fixed: Task 4b names both and the collector.
3. SUBSTANTIVE: the catalog lane would post a withdrawn thread's block at its kept level. Fixed: `catalog.snapshot` and `remember` take the thread out of the inventory; a test with the lane on.
4. BLOCKER: the ordering test asked the fake relay for a clock it has not. Fixed: the run is the clock in the poster test, and `tests/test_wire_compat.py` reads signed events in both orders through `pull.threads_from`.
5. SUBSTANTIVE: the toggle count used a collector that misses the withdrawal. Fixed: one collector of every level-only block, and the first two replies are asserted.
6. SUBSTANTIVE: v0.3.0 was optional. Fixed: required.
Rung after the pass: medium.

## Chunks
- [ ] poster: the withdrawn state in `recompute`, the ledger, `compose`, `main`, `signer`, with tests and `spec/wire.md`

## Notes
- The session stood at its usage limit from about 2026-11-26T20:50Z to 2026-11-27T12:00Z; working time before it was about 25 minutes.
- Order of work: the code and tests were begun while the spec and plan reviews ran, to use the wait; both reviews' findings were then applied to the code (the state by channel, no reply that ends the state in the run that recorded the withdrawal, the catalog). No review was skipped.
- Size: about 400 changed lines in existing files and a new test file of about 400. Above the 600-line mark with its tests; not split, because the state has no half that lands alone: reaching it without leaving it would hide alerts with no way back.
- Agency tools are not present in this session; tasks were executed here.
