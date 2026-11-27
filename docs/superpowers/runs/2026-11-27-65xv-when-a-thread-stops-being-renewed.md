# Run: 65xv-when-a-thread-stops-being-renewed
Instruction: Read TASK-ai-tools-alerts#65xv.md in this worktree root, then run `kata show ai-tools-alerts#65xv` and follow the brief and the dispatch rules (run as /do-it, starting rung floored at medium).
Stage: done
Review: 89d33f0c7e0876dddb49255bfdbf086f601b49e7 fixed+delta d05c891f63c4d300d712e45a9739357a38be645b +fix aeccd5a2e1dcf6a6d5fd3310578d3f8d6fb163a1
Rung: medium (start-floor medium: dispatch brief)
Spec: docs/superpowers/specs/2026-11-27-65xv-when-a-thread-stops-being-renewed-design.md   Plan: docs/superpowers/plans/2026-11-27-65xv-when-a-thread-stops-being-renewed.md
Agency project: —
Kata: ai-tools-alerts#65xv
Limits: wall clock 5 hours from the 20:26Z dispatch (01:26Z); one independent pass per artifact, one delta only after a behaviour-changing BLOCKER fix; done when scripts/test-gate.sh is green and the pull request is merged with the no-reply author.

## Scorecards
Pass 1 [spec]: 5B/1S/0C/0R · fixed -/- · velocity = (—→6, escalation no)
Pass 1 [plan]: 6B/0S/0C/0R · fixed -/- · velocity = (—→6, escalation no)
Pass 1 [code:whole-branch]: 2B/0S/0C/0R · fixed -/- · velocity = (—→2, escalation no)
Pass 2 [code:delta]: 0B/2S/0C/0R · fixed 2/2 prior · velocity = (2→2, escalation no)

## Chunks
- [x] signer: a checkpoint lists a thread without its superseded renewals
- [x] ledger, recompute, compose, main: a thread ends 90 days after its level last changed; raises on an ended or unconfirmed thread
- [x] the simulated year, spec/wire.md, changelog

## Notes
- Prior work searched: `kata search "renewal end thread feed caps"` gives this issue and ai-tools-alerts#h29n only. The gtw9 design (docs/superpowers/specs/2026-11-26-gtw9-renewals-and-step-down-design.md) names this follow-up in "Not in this change".
- The repository has no `.repoman-managed` marker: the ending is a pull request this session merges, as the brief says.
- The run stalled on the seat's usage limit from about 20:46Z on 2026-11-26 to 12:00Z on 2026-11-27, so the 5-hour wall clock passed with the pane idle. Resumed on Joi's word (kata comment xcgjx8); main had not moved.

- Agency was not used: the agency tools are not available in this session, as in the gtw9 run. The plan was executed directly, tests first in each chunk.
- Amended while building (plan, chunk 1): the must-list keeps a minimal set (`signer._core`: root, curator replies, replies that name a level, frontier) checked by the reader's code, with the slim thread as the fallback. Listing the slim thread alone there made a curator's retraction in an oversized thread unlistable, which three existing tests pin.
- The simulated year at one poster run a day stepped threads down unconfirmed: a lane reads ten advisories a run, so by the end a thread was read every 36 days. The test gives the daily run the reads of 24 runs. The limit itself is the follow-up issue on judging threads that are off readers.
- The whole year takes 8.6 minutes (passed 2026-11-27, `AITOOLS_ALERTS_SIM_DAYS=365`); the suite runs 200 days.

## Spec review (fresheyes, gpt-6-astra, run 20261127-053600-a042f4, snapshot 4eea962506517e5781a47f48b40c42665a64c59b): 5 BLOCKER, 1 SUBSTANTIVE
1. BLOCKER. The must-list of `window` uses the raw `_frontier`, so a bot-key reply whose claim names another id stands for a renewal the reader counts, and `slim`'s check never sees that selection. Fixed, in the form the plan review left it (plan findings 1 and 2): the must-list lists `slim(thread)`, and `slim` returns a thread whole unless the reader's code builds the same thread from the kept events.
2. BLOCKER. A reader's retention sees only listed events; dropping a renewal alone that is the thread's newest event lets `_retain` age the thread out. Fixed: `slim` always keeps the newest event.
3. BLOCKER. After a lost checkpoint state, a renewal with the old confirmation does not cover an acknowledged renewal the ledger never recorded, and an ended thread is never confirmed again. Fixed: such a thread, inside its life, gets one renewal confirmed now; until then its roots are out of the checkpoint.
4. BLOCKER. `_clears` would pass over an ended thread's unsent step for a raise `plan_known` then refuses. Fixed: `_clears` asks `_may_rise` first.
5. BLOCKER. The capacity test as worded (400 threads of four events) cannot fit 990. Fixed: 400 threads of a root and twelve renewals, exactly 800 ids listed.
6. SUBSTANTIVE. The snapshot commit's message is vague. Rebutted: a review snapshot is a dangling commit that never lands.

## Plan review (fresheyes, gpt-6-astra, run 20261127-210152-a3b64b, snapshot 337424a971a8208549be71902e636142a73bb8ed): 6 BLOCKER
1. The must-list's subset (root, curator replies, frontier) can leave out a raise that a later renewal makes redundant by date; a new reader then shows the level before it. This is gtw9's listing, and no check sees it. Fixed: the must-list lists `slim(thread)`, which the reader's code has compared with the whole thread.
2. Filtering the frontier by the reader's `(confirmed_at, checked_at, created_at)` triples does not say which event the reader counted: a claim about another id with the same three times passes. Fixed: the filter is gone; `slim`'s comparison through `pull.threads_from` is the only judge, and it returns the thread whole when the kept events give another thread.
3. An ended notice in its last day, after a lost checkpoint state and a read that did not confirm, left `_renew` by the step test's `continue` and stayed listed. Fixed: it is passed to `lapsing(anyway=True)` before the step test.
4. The test expected renewals to day 90 and a step on day 119; the steps end the thread on day 90 before that day's renewal. Fixed in the test and the spec: no renewal on or after day 90, last renewal day 75 in a daily run, step on day 104.
5. The end-to-end fixture's certificate lasts 90 days. Fixed: the year test writes a new one every 60 days.
6. The summary does not end with `checkpoint=sent` in a run that renewed. Fixed: the test looks for the field.

## Code review, whole branch (fresheyes, gpt-6-astra, run 20261127-215749-0ba102, head 89d33f0c7e0876dddb49255bfdbf086f601b49e7): 2 BLOCKER
The gate at that head, in a clone of the branch alone: 3369 passed, 1 skipped. The same-model Stage 1 reviewer stopped on the seat's usage limit before reporting; nothing of its is counted.
1. `_core` compared only what decides a thread's level, so the must-list could list a thread without a reply that widens its affected range, and a new reader on a version only that reply covers was not matched. Fixed: `_core` uses its set only when the reader builds the very thread from it (`_reads_alike`, every field), else the slim thread.
2. After a lost checkpoint state an ended thread past its life by the ledger was neither renewed nor left out, though an acknowledged renewal the ledger never recorded could still keep it on readers. Fixed: its roots are left out for the longest TTL after the loss; nothing is sent to it.

## Code review, delta (fresheyes, gpt-6-astra, run 20261128-070912-f3cfb3, `--since 89d33f0c7e0876dddb49255bfdbf086f601b49e7` at d05c891f63c4d300d712e45a9739357a38be645b): 2 SUBSTANTIVE
1. Leaving the roots of an ended thread past its life out of the checkpoint (the second half of the fix to whole-branch finding 2) shows the expired thread again on every reader that still stores it: a reader does not judge an unlisted thread. Fixed: that suppression is removed. An ended thread inside its life is still renewed once, confirmed now, and left out until then; one past its life is sent nothing and stays listed. What whole-branch finding 2 described for a thread past its life is now rebutted: it needs an acknowledged renewal the ledger never recorded, a lost checkpoint state and a mirror that withholds that renewal, all found after the ledger's life has run out, and it loses up to one TTL of a notice the poster had stopped renewing; covering it by suppression resurrects every expired alert after any lost state. The spec says so.
2. The recovery test asserts the `suppress` argument and the sends, not a published checkpoint read by a reader, and its certificate lasts 120 days. Fixed in part: the test that ran past day 120 is replaced by one whose claim is about `suppress` and sends only (days 251 and 300), and the in-life test runs on day 111, inside the certificate. Rebutted in part: what a checkpoint does with `suppress`, and what a reader does with an unlisted root, are gtw9's and pinned by its tests (`tests/poster/test_signer.py`, `tests/test_pull.py`); the year simulation reads published checkpoints through a reader.
No further pass (review cycle: one review, one delta).

## After the reviews
- Gate at aeccd5a2e1dcf6a6d5fd3310578d3f8d6fb163a1, in a clone of the branch alone: 3370 passed, 1 skipped.
- `origin/main` had moved (kk2q the withdrawn state, m729 the record of what the poster signed, p93w the checkpoint's date, 53fy, aabw): merged at 3d376b8. Seven files conflicted. Resolved by keeping both sides; where they meet: a withdrawn thread leaves the renewal pass before the ending rule; `plan_known` and `_clears` refuse a withdrawn thread first, then ask `_may_rise`; `recompute.judge` and `raised` take the way out of the withdrawn state before `_rises`; `record_reply` removes `ended` on any level change that is not a lowering or a withdrawal, the reply that ends a withdrawal among them (a test in `tests/poster/test_ledger.py`). One test from main expected a thread listed with every renewal after a lost state; it now expects the root and the standing renewal. Not reviewed again: the review cycle allows one review and one delta.
- Gate at 4d5d4288410d33d10f1b53456a20ab9a81c9fc2a: 3640 passed, 1 skipped.
- Follow-up filed: ai-tools-alerts#0kze (a slow turn for threads that are off readers).
- Size: about 700 changed lines of code, tests, wire rules and changelog, over the 600-line guide. The listing rule and the ending rule are safe only together: listing alone still fills the checkpoint in under two years, ending alone leaves room for 60 days of renewals. The tests are over half of it.
- Skip temptations: none acted on. The same-model Stage 1 review was launched and stopped on the seat's usage limit; it was not relaunched after the independent pass had reported.
- Gate at c2a13d3014de03781e7deb6072c43f5de17cf560 (main merged at fd36ba6): 3656 passed, 1 skipped. At ca52232ec06e3167538f7ebb594488693253e24f (main at 30ab415): 3718 passed, 1 skipped.
- `origin/main` moved again (btqg: a new advisory joins the open thread of its fix), merged at 4b4aea9 with two conflicts, both sides kept. Where they meet: `_fix_thread` does not offer a thread that has ended (a test in `tests/poster/test_renew.py`), and the simulated year gives each day's advisory a fix of its own, since advisories that share a fix now share a thread. Not reviewed again.
