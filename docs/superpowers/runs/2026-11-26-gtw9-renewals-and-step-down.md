# Run: gtw9-renewals-and-step-down
Instruction: Read TASK-ai-tools-alerts#gtw9.md in this worktree root, then run `kata show ai-tools-alerts#gtw9` and follow the brief and the dispatch rules (run as /do-it, starting rung floored at medium).
Stage: done
Rung: medium (start-floor medium: dispatch brief)
Spec: docs/superpowers/specs/2026-11-26-gtw9-renewals-and-step-down-design.md   Plan: docs/superpowers/plans/2026-11-26-gtw9-renewals-and-step-down.md
Agency project: none (the agency tools are not available in this session; the plan was executed directly)
Kata: ai-tools-alerts#gtw9
Limits: wall clock 5 hours from the 05:12Z dispatch; one independent pass per artifact, one delta only after a behaviour-changing BLOCKER fix; done when scripts/test-gate.sh is green and the pull request is merged with the no-reply author.
Last reviewed: spec c2683882c54863f9576168f89b5ae3c510de2a84
Last reviewed: plan (snapshot of the spec and plan, a dangling commit)
Last reviewed: code 9455f5a24c925ef28ef6f5a6a760f2de583fb4aa (whole branch), 2515bff487933eddde0db704f3c96bd6c0b28461 (delta)
Review: 9455f5a24c925ef28ef6f5a6a760f2de583fb4aa fixed+delta 2515bff487933eddde0db704f3c96bd6c0b28461 +fix dd51a5c5491130a720b37dfa588ed3a1b2f473d0

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

## Code review, whole branch at 9455f5a24c925ef28ef6f5a6a760f2de583fb4aa (fresheyes, gpt-6-astra, run 20261126-162331-453faa): 11 BLOCKER
Findings 1 to 8 are one class: a checkpoint lists a root whose delivered renewals no longer hold its level, in a case the poster's own bookkeeping misses. One fix answers the class: `signer.lapsed` reads the poster's copy of the mirror as a reader would and leaves such a root out, per channel, whatever the ledger says.
1. A mirror hides a root and its renewals, the root is given up, the renewals lose their protection, the root comes back alone. Fixed: `lapsed`; and `settle_gone` keeps the renewals of a root it no longer holds.
2. A later copy renews the ledger's shared claim while the first root's channel got nothing. Fixed: `lapsed` (the first root is left out when its own renewals run out; the next renewal goes to both channels).
3. A step down one channel refused twice leaves the journal, and the suppression with it. Fixed: `lapsed`.
4. A blocked step judged whether listing was safe by the life a renewal would give, not by what was delivered. Fixed: `lapsed` judges delivered events only.
5. A step whose send stops the pass leaves later due threads unlooked at. Fixed: `lapsed`.
6. After a lost checkpoint state a hidden level reply is not replaced by the recovery renewal. Fixed: `lapsed` (the thread is left out once the events held no longer keep its level).
7. A lost ledger knows no thread; checkpoints go on. Fixed: `lapsed`.
8. A run that ends in a LedgerError skips the renewal pass and still signs. Fixed: `lapsed`.
9. A confirming read between two renewals was kept nowhere, so the 45 days ran from the older confirmation. Fixed: a read that confirms a claim last sent unconfirmed is sent at once.
10. The root-id test brought no later alias. Fixed: `test_a_claim_about_an_alias_a_later_reply_brought_never_becomes_the_standing_claim`.
11. The equal-times test built the same event twice. Fixed: two events with different text, asserted distinct.
Pass 1 [code:all]: 11B/0S/0C/0R · fixed -/- · velocity = (—→11, escalation no)

## Delta review, `--since 9455f5a` at 2515bff487933eddde0db704f3c96bd6c0b28461 (fresheyes, gpt-6-astra, run 20261126-165114-7f1911): 5 BLOCKER, all in `signer.lapsed` and its tests
1. Any curator reply exempted a thread for good; a reader decays again once a hold runs out, and a note is no hold. Fixed: the rule takes each thread as `pull.standing` gives it at the checkpoint's time.
2. A claim about an id the thread never held counted as a renewal, and a root whose claim names another id counted as enrolled. Fixed: the threads are built by `pull.threads_from`, which filters both.
3. A block the reader refuses that names a lower level set the level the rule judged. Fixed: the level is the reader's, or the lower one it holds as the bot's offer.
4. A ruleset that could not be loaded turned the rule off and signing went on. Fixed: it raises, and the run signs nothing (`checkpoint=error`).
5. No test for the renewal pass raising, nor for `settle_gone` keeping the renewals of a root no longer held. Fixed: both added, with one for each of 1 to 4.
Pass 2 [code:all]: 5B/0S/0C/0R · fixed 11/11 prior · velocity ↓ (11→5, escalation no)
These fixes are not reviewed again: the review cycle allows one delta. They are in the commit after 2515bff.

## Notes
- The rung: the whole-branch pass left no finding unfixed, so the run stayed at medium; the one delta was run because BLOCKER fixes changed behaviour, as the review cycle asks at any rung.
- The second, same-model reviewer (Stage 1) had not reported when the branch was merged: it ended its turns waiting on its own test runs. Nothing of its is counted.
- Main was merged in twice (swfe and 0z4e at 9455f5a; y484 at 31ef49ad8c597147907ff0b5da0978d2dc940290), each with one conflict, in the changelog. The gate ran in a clone holding this branch alone: at 9455f5a (3284 passed, 1 skipped) and at 31ef49a (see the close-out comment on the issue).
- Follow-ups filed: ai-tools-alerts#p93w, #byzq, #65xv.
- The session stopped on a usage limit one minute after dispatch and resumed at 06:40Z with nothing on the branch.
- Prior work read: ai-tools-alerts#r0ra, #ny5g, #hh5s close-outs and specs; #h29n D5.
- The start-floor evaluator subagent was not run: the dispatch brief fixes the floor at medium and names the only two ways it climbs. No hard trigger is in the diff (no secrets, auth or credential handling, no deploy path); every BLOCKER of the spec and plan passes was fixed, so the rung stays medium.
- Size: about 900 changed lines of code and tests, over the 600-line guide. What could leave did (two follow-up issues); root claims, renewals, the step down and the signer's protection are safe only together (the note from ai-tools-alerts#hh5s), and the two reviews added the rest.
- The spec was edited once with a script instead of the Edit tool; later edits used Edit.
- Left open, in the spec: a level reply acknowledged in the 72 hours before a lost state file and hidden by the mirror; a run that ends in a LedgerError renews nothing and still signs.
