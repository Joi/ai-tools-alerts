# Run: aqtf-per-channel-level
Instruction: Read TASK-ai-tools-alerts#aqtf.md in this worktree root, then run `kata show ai-tools-alerts#aqtf` and follow the brief and the dispatch rules pasted after this sentence. (The brief: ai-tools-alerts#aqtf, a channel that refused a level reply twice is sent the thread's standing level again; run as /do-it, starting rung floored at medium.)
Stage: done
Rung: medium (start-floor medium: constraint-lens, BR1 REV2 NOV1 INT1 FC1 = 6; no hard trigger; the dispatch floors it at medium too)
Lens: "Nothing you build may wait for a person to act"; "no reply is sent twice to a channel that has it"; "Stay inside this issue"; "No rollout" (in every review pass)
Last reviewed: spec 1cda4d00d6f44c4284b69a4eba7ba1ff84d406fd
Spec: docs/superpowers/specs/2026-11-28-aqtf-per-channel-level-design.md   Plan: docs/superpowers/plans/2026-11-28-aqtf-per-channel-level.md
Agency project: 01a21f27-09b4-7b96-bab0-3c0de239347c (two tasks: chunk 1, chunk 2; both evaluated)
Kata: ai-tools-alerts#aqtf
Limits: wall clock 5 hours from 2026-11-27T22:10Z; one independent review per artifact (spec, plan, code), one delta only after a behaviour-changing BLOCKER fix at heavy; completion check: the five acceptance cases of the issue pass as tests in `scripts/test-gate.sh` and the pull request is merged with the no-reply author.
Landing: this repo has no `.repoman-managed` marker, so the brief's ending applies: `scripts/test-gate.sh`, one independent whole-branch review, a pull request this session merges, the issue closed on the merge commit.

## Scorecards
Pass 1 [spec]: 4B/2S/0C/0R · fixed -/- · velocity = (—→6, escalation no)
spec: passes 1 · gpt-6.1-sol through fresheyes on snapshot 1cda4d0 (watchdog FRESHEYES_DONE REASON=-) · elapsed about 15 min

Spec findings and what was done:
1. BLOCKER: a channel at the same word as a new standing reply was taken to have it; a channel left at an older notice when the thread is lowered to notice would lose the thread before the poster's count says so. Fixed: `lacks` is possession of the reply, not of the word. A new standing reply names every other channel, whatever it stands at (a withdrawn channel under a new withdrawal excepted: a withdrawal renews nothing).
2. BLOCKER: `plan_known` posts the copy in the critical channel before the feed's reply, so that root is ahead of the ledger and the reply's record would name the critical channel as lacking. Fixed: `add_channel` takes the level the root states and keeps it in `copied` until the next level reply is recorded.
3. BLOCKER: the mark of a reply the reconciliation planned had no form on disk, and the journal's validator refuses an unknown key. Fixed: `again: true` on the journal item, accepted by `inputs._item_ok` on a reply only; criterion 10 and its tests.
4. BLOCKER as raised, taken as SUBSTANTIVE and rebutted in part: an unknown send that the mirror never shows is sent again after one to three days, which can leave two copies. That is jsje's rule for every send (m729 settles by id), not something this issue changes; a durable send identity is its own work. Fixed in the spec: criterion 5 now says "a channel the ledger records as having it", and the section says what an unknown outcome does.
5. SUBSTANTIVE, rebutted: the journal drains before the reconciliation, so a journaled lowering can go before a missed raise. Kept: moving the reconciliation ahead of the drain would put a raise missed three days ago in front of today's new roots, and a failed send stops the run for everything behind it. Criterion 6 now says "within what a run newly plans".
6. SUBSTANTIVE, rebutted: the snapshot commit's message. It is a dangling review snapshot and never lands.
Rung after the pass: medium. Every BLOCKER is fixed, every SUBSTANTIVE finding fixed or rebutted above.

Last reviewed: plan b78a00a66a574cee52158ef295962ece0749e116
Pass 1 [plan]: 3B/2S/0C/0R · fixed -/- · velocity = (—→5, escalation no)
plan: passes 1 · gpt-6.1-sol through fresheyes on snapshot b78a00a (watchdog FRESHEYES_DONE REASON=-) · elapsed about 12 min · all five fixed

Plan findings and what was done:
1. BLOCKER: a reply the reconciliation sends to a withdrawn channel was still counted as a level change (`left`), adding its time to `changed`. Fixed: `left` is false for `again`; a test for both cases.
2. BLOCKER: `tests/poster/test_catalog.py` builds its entry as a namespace with `withdrawn`, which `catalog.snapshot` no longer reads. Fixed: the fixture sets `gone`; named in the plan.
3. BLOCKER: the renewal test as planned would repair the channel before the renewal pass. Fixed: the relay refuses the reconciliation's reply, so the thread is still partly withdrawn when the pass runs.
4. SUBSTANTIVE: the checkpoint test passed without the new ledger scan (the withheld item already kept the root out). Fixed: it asserts the run in which the reply is given up and nothing is in flight.
5. SUBSTANTIVE: no regression test for `uneven`. Fixed: a ledger test with equal reply counts and an alias, asserted through `Run._stated`.
Rung after the pass: medium.

Last reviewed: code d664e67 (whole branch, `git diff origin/main...d664e67`, main at fd36ba6 merged)
Pass 1 [code:whole-branch]: 1B/3S/3C/0R · fixed -/- · velocity = (—→7, escalation no)
code: passes 1 · Stage 2 gpt-6.1-sol through fresheyes on d664e67 (watchdog FRESHEYES_DONE REASON=-): one BLOCKER. Stage 1 a same-model reviewer on the same commit, in parallel: no BLOCKER, three SUBSTANTIVE (one the same defect as Stage 2's), three COSMETIC.

Code findings and what was done (the same defect counted once):
1. BLOCKER (Stage 2; Stage 1 S3): leaving the withdrawn state was not counted in `changed` when the channel that never took the withdrawal acknowledged the return first, so another lowering could follow within seven days. Fixed: the return counts when the thread was withdrawn before the reply, whichever channel takes it first; a test with that order and the quiet-days assertion.
2. SUBSTANTIVE (Stage 1 S1): a thread due a lowering in this run could be sent its missed raise first, the two replies in one second. Fixed: `reconcile(up=True)` skips the threads this run lowers; the step down skips a thread the reconciliation sent a reply for in this run; a test.
3. SUBSTANTIVE (Stage 1 S2): two threads lacking in a channel that refuses for good took two refusals in one run, which stops the run, every three days. Fixed: the reconciliation plans nothing more once the relay has refused a reply in the run; a test.
4. COSMETIC (Stage 1 C1): the copy test ended before the journal gave the reply up. Fixed: it runs past that hour.
5. COSMETIC (Stage 1 C2): a sentence of the module docstring had lost its subject. Fixed.
6. COSMETIC (Stage 1 C3), rebutted: an entry kk2q wrote with one channel withdrawn and the other channel's withdrawal still in the journal at the upgrade counts the entering twice. Once per such thread, and it lengthens the quiet days. kk2q is unreleased.
Rung after the pass: medium. Finding 1 changed behaviour: the fixes are committed and get the one delta pass (`fresheyes --since d664e67`).

Pass 2 [code:whole-branch]: 0B/2S/0C/0R · fixed 6/7 prior · velocity ↓ (7→2, escalation no)
code: passes 2 · the delta, gpt-6.1-sol through `fresheyes --since d664e67 --rebuttals` at head b5577f544368ce191cd73820f8f546b671caa15a (watchdog FRESHEYES_DONE REASON=-). Six of seven fixed, one rebutted and carried; no rebuttal overturned. Two findings, both called major, both fixed in the commit after b5577f5 with no further pass:
1. Stopping the reconciliation after any refusal in the run let a backlog of refused replies keep a later thread untried for good. Fixed: that guard is gone; a refusal of a reply sent again does not count toward the two that stop a run, so every lacking thread is tried. The test runs through the journal's whole cycle.
2. The step-down guard had no test. Fixed: a thread 44 days unconfirmed with a lacking channel is sent the reply in one run and stepped down in the next; without the guard the test fails.
Not reviewed again: the review cycle allows one delta. `git diff b5577f5..HEAD` shows what landed after it.

## Chunks
- [x] ledger: `lacks`, `copied` and `uneven`, the thread's standing by channel; the journal item's `again`
- [x] poster: `Run.reconcile`, the state read from the standing reply, tests, `spec/wire.md`, changelog

## Gate
`scripts/test-gate.sh`, each time in a clone holding this branch alone:
- exit 0 at ffedc27 (the delta fixes, main at 30ab415 merged): the public scan, then 3739 passed.
- exit 0 at 8a69772 (main at 4b4aea9 merged, btqg): 3776 passed.
- exit 0 at 6f71da7 (main at 862b497 merged, 65xv and 1qy4): 3876 passed.
Main then moved once more, to the 0.4.0 release commit (version strings, README, the changelog's heading, the mirror exporter; no file of the poster). On that merge the public scan and every test outside `tests/poster` were run, not the whole gate; the result is in the close-out comment on the issue.

Reviewed shas: the whole branch at d664e67, the delta at b5577f5. Not reviewed by a second model: 2587e6d (the two fixes the delta asked for), and the four merges of main. In those merges, by hand: both changelog entries kept each time; `Entry.joined` and `Entry.ended` beside this branch's fields in the ledger and its validator; btqg's join by fix and 65xv's `plan_known` guard read the thread's state from `Entry.gone`; the aqtf changelog entry moved back under a new Unreleased heading after 0.4.0 was cut without it.

## Notes
- Prior work read: the issue; the kk2q run record and its code finding 5 (which filed this issue); jsje's retry (`Run._withhold`, `Run.expire_withheld`); `spec/wire.md` "A withdrawal". `kata search "per-channel reconciliation level reply refused"` returns this issue only: no earlier attempt, no dead end.
- Main is at 3d376b8 (m729 merged). The issue text matches the landed code: kk2q keeps `Entry.withdrawn` by channel and the recompute sends the reply that ends the state to the channels still listed.
- Order of work: the code and its tests were begun while the spec and plan reviews ran, to use the wait; both reviews' findings were then applied to the code before anything was committed. No review was skipped.
- I edited the spec once with a script after its review (one replaced section and four exact-match replacements, each asserted to occur once), not with the Edit tool the skill names.
- Mutation checks, each against `tests/poster/test_reconcile.py`: `reconcile` made to do nothing fails the four acceptance tests; possession by word alone fails the older-notice test; without the ledger scan in `renew` the checkpoint test fails; `_stated` without `uneven` fails its test.
- `tests/poster` before the commit: 1286 passed, 1 failed; the failure was the kk2q expectation this change replaces (`test_a_reply_that_ends_the_state_passes_the_withdrawal_one_channel_still_lacks`), corrected and passing since.
- 65xv on main added the `ended` state after this branch's reviews. A reply sent again to a channel of an ended thread names the thread's level, as its step downs do; that pairing has had no review of its own. Follow-up filed (see the issue).
- Wall clock: about five hours of work, a third of it in five gate runs of 19 to 25 minutes; main moved four times while the branch was being landed.
- Skip temptations: running only part of the gate after the last merge of main (taken, for the reason and with the scope stated under Gate); nothing else.
