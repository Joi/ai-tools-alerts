# Run: 3t4p-copy-on-recompute-raise
Instruction: Read TASK-ai-tools-alerts#3t4p.md in this worktree root, then run `kata show ai-tools-alerts#3t4p` and follow the brief and the dispatch rules (do-it, start rung floored at medium; PR landing; one independent review).
Stage: spec-review
Rung: medium (start-floor medium: dispatch floor; no hard trigger in scope)
Spec: docs/superpowers/specs/2026-11-26-3t4p-copy-on-recompute-raise-design.md   Plan: docs/superpowers/plans/2026-11-26-3t4p-copy-on-recompute-raise.md
Agency project: — (no agency MCP tools in this session; executed directly)
Kata: ai-tools-alerts#3t4p
Limits: wall clock 5 hours from the 2026-11-26T01:47Z dispatch; review shape one independent pass per artifact, one delta only after a behaviour-changing BLOCKER fix; completion check: `scripts/test-gate.sh` green and the pull request merged with the no-reply author.

Last reviewed: spec+plan b8cd08106ac0d81a124afd454201d5fcb0fbd88d

## Scorecards
Pass 1 [spec+plan]: 3B/1S/0C/0R · fixed -/- · velocity = (—→4, escalation no)   # fresheyes, gpt-6.1-sol high, REASON=-; 2 fixed, 1 fixed in part and rebutted in part, 1 rebutted (the spec's "Review dispositions")
spec: passes: 1 · elapsed: ~15 min

## Chunks
- [ ] the recompute posts the copy a thread's level lacks

## Notes
- Start-floor evaluator not dispatched: the dispatch floors the run at medium and no hard trigger is in scope (no secret, credential or deploy path in the diff); as jsje, faxq, 9kgk and qwpw.
- Spec and plan reviewed in one fresheyes pass (one artifact pair, one look), as those runs did.
- Review model: the fleet default (`gpt-6.1-sol`, high). Neither the issue nor the brief calls this slice security-shaped.
- The repo has no `.repoman-managed` marker: the ending is a pull request this session merges (TASK file), not a repoman handoff.
- Rung after the spec pass: medium. Nothing survived it unfixed that the code could fix; the rebutted remainder of finding 2 (a journaled copy sent after a retraction) is the journal's property for every kind and is ai-tools-alerts#n1fc.
- Code was written while the spec review ran, then changed to the reviewed design (scope by stored name, the withdrawal check); nothing was committed before the dispositions.
- Follow-up filed from the spec review: ai-tools-alerts#zmg2 (the recompute's own judging resolves a thread's scope with `rules.scope_of`, so Codex, Cursor, Hermes, git, Python, Go and mcp threads are never judged). Not this issue: it changes what the recompute raises and lowers.
- Skip-temptation: the spec's and plan's review amendments were applied with a script that asserts each needle occurs once (it fails loudly on a stale one), not the Edit tool; the content is as reviewed plus the dispositions.
- One existing test changed: `tests/poster/test_main.py::test_compose_value_error_sends_nothing` asserted `copies=0` and one send after the recompute's raise of a KEV-listed thread. That is the missing copy this issue fixes; it now expects the copy in `critical`.
- Found by that test, before any review: `Run.recompute` has a loop variable named `root` (the threads KEV listed), which shadowed the trust-root argument first given the same name, so `copies` pulled the mirror with a thread id whenever a thread was KEV-listed and planned nothing. The argument is `trust_root`; the test above and the mutation "pulls the mirror with another root" pin it.
- Mutations, each failing a named test: `copies` not called, `copies` pulls with another root, and `copies` posts to every channel of the level (`test_a_feed_only_thread_raised_to_critical_gets_its_copy_in_the_critical_channel`); `copies` ignores `busy` (`test_a_copy_whose_outcome_is_unknown_is_not_planned_twice`); the scope by `rules.scope_of` (`test_a_thread_is_found_by_the_name_it_was_posted_under[Cursor]`); no withdrawal check (`test_a_withdrawn_advisory_gets_no_copy`); a failed pull plans anyway (`test_no_copy_is_planned_while_the_mirror_cannot_be_read`); `copy_post` without the 9kgk check, and without the product check (`test_copy_post_refuses_what_must_not_post`). One survives and is equivalent: without the explicit synthetic test in `copies`, `compose.withdrawn` still skips a synthetic id; the explicit test only saves the mirror pull.
- `compose.copy_post` adds no parse-back check of its own: `schema.render_post` raises when the text does not parse back to the advisory, and the compose test holds it to that.
- Prior work: `kata search "recompute raise critical channel copy"` (3t4p itself, jsje, h29n, ny5g, 3qyq; no other hit). jsje: a refused copy is dropped after three days and "its advisory planned anew", which for a copy with no candidate only the recompute can do. 3qyq's close-out names this issue as the gap.
