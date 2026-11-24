# Run: jsje-settle-without-a-person
Instruction: Read TASK-ai-tools-alerts#jsje.md in this worktree root, then run `kata show ai-tools-alerts#jsje` and follow the brief and the dispatch rules (do-it, start rung floored at medium; PR landing; one independent review).
Stage: verifying (gate on the final head, then the pull request)
Rung: heavy (start-floor medium: dispatch floor; no hard trigger in scope) + escalation medium→heavy: the whole-branch pass left three critical findings (do-it's evidence rule)
Spec: docs/superpowers/specs/2026-11-25-jsje-settle-without-a-person-design.md   Plan: docs/superpowers/plans/2026-11-25-jsje-settle-without-a-person.md
Agency project: — (no agency MCP tools in this session; executed directly)
Kata: ai-tools-alerts#jsje
Limits: wall clock 5 hours; review shape one independent pass per artifact, one delta only after a behaviour-changing BLOCKER fix; completion check: the four acceptance tests of the issue pass in `scripts/test-gate.sh`.
Last reviewed: spec+plan bbae5a1a1e03829dd6fd383e7754afe4d692c885
Last reviewed: code e63d9908875c305a2f0b57582bd1c69c48df779b (whole branch), delta --since e63d990 at 947f154006e5582a45d7011a7f7fb857455f56f8; two fix commits follow the delta unreviewed by a further pass: b9c25fef75e5a7018beb1968c157adbd0dc46db5 (the delta's two findings) and the commit that carries this record (the same-model pass's remaining points)

## Scorecards
Pass 1 [spec+plan]: 2B/4S/0C/0R · fixed -/- · velocity = (—→6, escalation no)   # fresheyes, gpt-6-astra high, REASON=-; its 'critical' read as BLOCKER, its 'major' as SUBSTANTIVE; 4 fixed, 1 fixed in part and rebutted in part, 1 rebutted
spec: passes: 1 · elapsed: ~20 min
Pass 1 [code:branch]: 3B/3S/0C/0R · fixed -/- · velocity = (—→6, escalation no)   # fresheyes whole branch at e63d990, gpt-6-astra high, REASON=-; 'critical' read as BLOCKER, 'major' as SUBSTANTIVE; all 6 fixed in 947f154
Pass 1 [code:branch, Stage 1]: 1B/4S/2C/0R · fixed -/- · velocity = (—→7, escalation no)   # same-model subagent at e63d990; its blocker and two substantive findings are three of the six above
Pass 2 [code:delta]: 1B/1S/0C/0R · fixed 6/6 prior · velocity ↓ (6→2, escalation no)   # fresheyes --since e63d990 --rebuttals at 947f154, REASON=-; both fixed in b9c25fe; no rebuttal overturned
code: passes: 2 · elapsed: ~55 min

## Chunks
- [x] settle unknown sends from the mirror; drop refused items by age; a raise supersedes lower-priority work

## Notes
- Start-floor evaluator not dispatched: the dispatch floors the run at medium and no hard trigger is in scope; it could only raise to heavy on one (as faxq, 9kgk, qwpw).
- Spec and plan reviewed in one fresheyes pass (one artifact pair, one look), as faxq, 9kgk and qwpw did.
- The issue calls the work security-shaped: the review runs on gpt-6-astra (`DO_IT_REVIEW_GPT_MODEL`).
- The repo has no `.repoman-managed` marker: the ending is a pull request this session merges (TASK file), not a repoman handoff.
- Prior work: `kata search "unknown send settle mirror withheld drop supersede raise"` (0 hits); the issue's own search (0 hits); m729 (events under the poster's key its ledger did not send, the other direction); 8acj (withheld, `resolve --requeue|--drop`); ny5g (`drop_unsent_lowerings`, the level-only reply); nfm3 (the checkpoint's owed list, given up after 72 hours); qwpw's rebuttal of the unknown or refused digest wedge, which names this issue.
- Spec+plan dispositions: in the spec's "Review dispositions" section. The two blockers were design holes, found before the code was reviewed: an expired unknown lowering was dropped (fixed: `tried`), and a refused reply another channel had was dropped (fixed: sent once more; the remainder, refused twice, rebutted). Medium takes no delta pass; the whole-branch review sees the fixes.
- Code was written while the spec review ran, then changed to the reviewed design; nothing was committed before the dispositions.
- One existing test changed: `test_recompute.py::test_a_thread_whose_lowering_finishes_in_this_run_is_still_raised_in_it` asserted that the unsent lowering goes out before the raise. The issue's acceptance says it does not; the test is now `test_a_thread_whose_lowering_one_channel_lacks_is_raised_without_it`.
- Where the landed code differs from the issue text: "a raise planned while a lowering of the same thread is unsent" was already half true (`drop_unsent_lowerings` drops a lowering no channel has, before the drain). What this slice adds is the lowering one channel has, and the refused one.
- Mutations, each failing the named test in `tests/poster/test_settle.py`: no `created_at` floor (`…settles_nothing[early]`); the floor is the attempt in flight (`…after_the_send_was_repeated…`); expiry without the `generated_at` test (`…proves_no_absence_until_72_hours`); `yields` ignores pending (`…waits_while_a_send_of_its_thread_is_unknown`); `yields` takes any reply (`…does_not_supersede_a_reply_with_a_fix_or_a_root`); a `tried` lowering is dropped (`…expired_is_sent_again_not_dropped`); a source-only reply another channel has is superseded (`…only_when_no_channel_can_have_it`); a partial reply is dropped at expiry (`…sent_once_more_then_given_up[ok]`); any poster's key settles (`…settles_nothing[key]`).
- The rollback `jq` line was run by hand on a state holding `dropped`, a digest snapshot's `dropped` and two items' `tried`: all three gone, nothing else changed.
- Skip-temptation: the plan's step boxes were ticked with a script, not the Edit tool; the content is unchanged.
- Whole-branch dispositions (independent pass): in the spec's second "Review dispositions" section; all six fixed in 947f154. Mutations for them, each failing a named test: the drain sends passed work; `yields` removes at once; a second refusal is withheld again; retry only when the ledger equals the snapshot; refused repeats not settled; a timed-out pull returns nothing; the `retried` mark not written.
- Delta dispositions: the spec's third section; both fixed in b9c25fe (mutations: the snapshot is recorded; the mark is cleared twice). No further pass (Review Cycle).
- Same-model pass, remaining points, fixed after the delta with no further pass (substantive, not blockers): `resolve --not-delivered` now writes `tried` as `settle` does; tests for a repeat that failed and never shows, a candidate that does not raise, and `resolve`'s `tried`; four comments that still said a person settles a send. Not done: a test for each smaller branch it listed (the sort for the oldest event, the `outbox sent == eid` clause of `_unrecordable`, a Japanese reply settled); its mutation of the `RANK` test in `_clears` survives because `yields` refuses a reply at the raise's own level by itself. Its cosmetic 7 (a dropped retried item's pending mark is cleared after the state save) is left: `settle` clears such a mark at 24 hours, and the same window exists for a dropped Japanese reply.
- Gate, `scripts/test-gate.sh` on a clone holding only this branch (the shared clone fails the public scan on other sessions' refs, a373): exit 0 at e63d990 (2689 passed, 1 skipped). The final head's run is in the pull request and the close-out comment.
- origin/main merged at 6b6db43 (release 0.2.0; no conflict; the merge put the CHANGELOG entry under the 0.2.0 heading, moved back to Unreleased in e63d990).
- Existing tests changed: the recompute test named above, and the test double of `Run.busy` in `test_a_thread_that_became_busy_after_it_was_judged…`, which now takes the `passing` keyword.
