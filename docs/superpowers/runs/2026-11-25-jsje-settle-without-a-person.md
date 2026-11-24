# Run: jsje-settle-without-a-person
Instruction: Read TASK-ai-tools-alerts#jsje.md in this worktree root, then run `kata show ai-tools-alerts#jsje` and follow the brief and the dispatch rules (do-it, start rung floored at medium; PR landing; one independent review).
Stage: code-review:branch
Rung: medium (start-floor medium: dispatch floor; no hard trigger in scope: no secrets, auth or deploy path)
Spec: docs/superpowers/specs/2026-11-25-jsje-settle-without-a-person-design.md   Plan: docs/superpowers/plans/2026-11-25-jsje-settle-without-a-person.md
Agency project: — (no agency MCP tools in this session; executed directly)
Kata: ai-tools-alerts#jsje
Limits: wall clock 5 hours; review shape one independent pass per artifact, one delta only after a behaviour-changing BLOCKER fix; completion check: the four acceptance tests of the issue pass in `scripts/test-gate.sh`.
Last reviewed: spec+plan bbae5a1a1e03829dd6fd383e7754afe4d692c885

## Scorecards
Pass 1 [spec+plan]: 2B/4S/0C/0R · fixed -/- · velocity = (—→6, escalation no)   # fresheyes, gpt-6-astra high, REASON=-; its 'critical' read as BLOCKER, its 'major' as SUBSTANTIVE; 4 fixed, 1 fixed in part and rebutted in part, 1 rebutted
spec: passes: 1 · elapsed: ~20 min

## Chunks
- [ ] settle unknown sends from the mirror; drop refused items by age; a raise supersedes lower-priority work

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
