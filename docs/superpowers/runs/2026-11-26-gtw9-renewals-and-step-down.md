# Run: gtw9-renewals-and-step-down
Instruction: Read TASK-ai-tools-alerts#gtw9.md in this worktree root, then run `kata show ai-tools-alerts#gtw9` and follow the brief and the dispatch rules (run as /do-it, starting rung floored at medium).
Stage: code-review:all
Rung: medium (start-floor medium: dispatch brief)
Spec: docs/superpowers/specs/2026-11-26-gtw9-renewals-and-step-down-design.md   Plan: docs/superpowers/plans/2026-11-26-gtw9-renewals-and-step-down.md
Agency project: none (the agency tools are not available in this session; the plan was executed directly)
Kata: ai-tools-alerts#gtw9
Limits: wall clock 5 hours from the 05:12Z dispatch; one independent pass per artifact, one delta only after a behaviour-changing BLOCKER fix; done when scripts/test-gate.sh is green and the pull request is merged with the no-reply author.
Last reviewed: spec c2683882c54863f9576168f89b5ae3c510de2a84
Last reviewed: plan (see plan.snap in Notes)

## Scorecards
Pass 1 [spec]: 10B/1S/0C/0R · fixed -/- · velocity = (—→11, escalation no)
Pass 1 [plan]: 7B/0S/0C/0R · fixed -/- · velocity = (—→7, escalation no)

## Chunks
- [x] ledger and compose: the standing claim, the root's ids, the renewal line, the step-down reason
- [x] signer: a missing renewal is not given up; the must-list carries the renewals; suppress from the caller
- [x] main: root claims on, the renewal pass, the step down, copies, what the checkpoint leaves out
- [x] wire compat, wire.md, changelog

## Spec review (fresheyes, gpt-6-astra, run 20261126-154652-b257b9): 10 BLOCKER, 1 SUBSTANTIVE
1. BLOCKER. A must-listed thread that does not fit whole is listed as root and corrections, without its renewals. Fixed: `signer.window` lists the renewals no other makes redundant (`_frontier`).
2. BLOCKER. The signer protected only claim renewals; a reader also counts a reply that names a level, by its own date. Fixed: `signer.renewals_of` returns both.
3. BLOCKER. A lost checkpoint state forgets a renewal that is now never given up. Fixed: every enrolled thread is renewed after the loss (see plan finding 3 for the part this first fix missed).
4. BLOCKER. One failing renewal first in line each run starves the others while checkpoints go out. Fixed: the order rotates by the hour, the pass goes on after a failure (three end it), and a thread whose due renewal is undelivered near the end of its life is left out of the checkpoint.
5. BLOCKER. The step could fire after 13 days when a stopped poster resumed. The code already used the life a renewal sent now would give (`best`); the spec said `life`. Spec fixed; test added.
6. BLOCKER. A reading too large for a tag read as "not confirmed". Fixed: confirmation is judged on the claim whatever its size; the renewal then carries the standing fields, confirmed now.
7. BLOCKER. After a step, confirmation still asked for the old higher level. Fixed: it asks for the lower of the standing claim's level and the ledger's.
8. BLOCKER. The spec said poster and reader share one timeline; a reader applies a step as an offer and may hold the higher level. Fixed in the spec: the reader shows the ledger's level or higher; the wire-compat test checks it.
9. BLOCKER. A copy planned for a thread posted before this change would have enrolled it. Fixed: only a thread's first root enrols; a later copy of an unenrolled thread carries no claim.
10. BLOCKER. No tests in the spec's commit, and tests that pin unclaimed roots. Fixed: the spec lists the tests; they are on the branch.
11. SUBSTANTIVE. The snapshot commit's message is vague. Rebutted: a review snapshot is a dangling commit that never lands.

## Plan review (fresheyes, gpt-6-astra, run 20261126-160050-5c917d): 7 BLOCKER
1. A level change recorded by a later run (replay, settled unknown send) dated the level's life from the recording. Fixed: `record_reply(changed_at=)` with the attempt's time.
2. A step down that failed, or that one channel took and another did not, was not covered by the checkpoint rule. Fixed: the channel root of every unsent level reply of an enrolled thread is left out; a due step that was not journaled too.
3. Recovery after a lost state ended with the 72-hour hold. Fixed: the loss time stays in the record (`hold_until`), the renewal is due until sent, and the roots are left out until then.
4. A renewal naming an alias a later reply brought is ignored by a reader that lacks that reply. Fixed: `Entry.root_ids`; the standing claim and every renewal name an id of the first root.
5. Two replies with equal renewal times removed each other from the must-list. Already handled by `_frontier` (one reply per pair); test added.
6. Chunk 2's verification needed chunk 3's signer interfaces. Fixed in the plan's order.
7. Tests asked for days 7 and 44 while the predicates were strict. Fixed: inclusive comparisons.

## Notes
- The session stopped on a usage limit one minute after dispatch and resumed at 06:40Z with nothing on the branch.
- Prior work read: ai-tools-alerts#r0ra, #ny5g, #hh5s close-outs and specs; #h29n D5.
- The start-floor evaluator subagent was not run: the dispatch brief fixes the floor at medium and names the only two ways it climbs. No hard trigger is in the diff (no secrets, auth or credential handling, no deploy path); every BLOCKER of the spec and plan passes was fixed, so the rung stays medium.
- Size: about 900 changed lines of code and tests, over the 600-line guide. What could leave did (two follow-up issues); root claims, renewals, the step down and the signer's protection are safe only together (the note from ai-tools-alerts#hh5s), and the two reviews added the rest.
- The spec was edited once with a script instead of the Edit tool; later edits used Edit.
- Left open, in the spec: a level reply acknowledged in the 72 hours before a lost state file and hidden by the mirror; a run that ends in a LedgerError renews nothing and still signs.
