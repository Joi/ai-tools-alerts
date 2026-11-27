# Run: 65xv-when-a-thread-stops-being-renewed
Instruction: Read TASK-ai-tools-alerts#65xv.md in this worktree root, then run `kata show ai-tools-alerts#65xv` and follow the brief and the dispatch rules (run as /do-it, starting rung floored at medium).
Stage: executing
Rung: medium (start-floor medium: dispatch brief)
Spec: docs/superpowers/specs/2026-11-27-65xv-when-a-thread-stops-being-renewed-design.md   Plan: docs/superpowers/plans/2026-11-27-65xv-when-a-thread-stops-being-renewed.md
Agency project: —
Kata: ai-tools-alerts#65xv
Limits: wall clock 5 hours from the 20:26Z dispatch (01:26Z); one independent pass per artifact, one delta only after a behaviour-changing BLOCKER fix; done when scripts/test-gate.sh is green and the pull request is merged with the no-reply author.

## Scorecards
Pass 1 [spec]: 5B/1S/0C/0R · fixed -/- · velocity = (—→6, escalation no)
Pass 1 [plan]: 6B/0S/0C/0R · fixed -/- · velocity = (—→6, escalation no)

## Chunks
- [ ] signer: a checkpoint lists a thread without its superseded renewals
- [ ] ledger, recompute, compose, main: a thread ends 90 days after its level last changed; raises on an ended or unconfirmed thread
- [ ] the simulated year, spec/wire.md, changelog

## Notes
- Prior work searched: `kata search "renewal end thread feed caps"` gives this issue and ai-tools-alerts#h29n only. The gtw9 design (docs/superpowers/specs/2026-11-26-gtw9-renewals-and-step-down-design.md) names this follow-up in "Not in this change".
- The repository has no `.repoman-managed` marker: the ending is a pull request this session merges, as the brief says.
- The run stalled on the seat's usage limit from about 20:46Z on 2026-11-26 to 12:00Z on 2026-11-27, so the 5-hour wall clock passed with the pane idle. Resumed on Joi's word (kata comment xcgjx8); main had not moved.

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
