# Run: faxq-group-by-fix-wording
Instruction: Read TASK-ai-tools-alerts#faxq.md in this worktree root, then run `kata show ai-tools-alerts#faxq` and follow the brief and the dispatch rules (do-it, start rung floored at medium; PR landing; one independent review).
Stage: code-review
Rung: medium (start-floor medium: dispatch floor; no hard trigger in scope: no secrets, auth or deploy path)
Spec: docs/superpowers/specs/2026-11-24-faxq-group-by-fix-wording-design.md   Plan: docs/superpowers/plans/2026-11-24-faxq-group-by-fix-wording.md
Agency project: —
Kata: ai-tools-alerts#faxq
Last reviewed: spec+plan 1b78b719a42b3828306f1951174363983a96a7e5

## Scorecards
Pass 1 [spec+plan]: 0B/8S/1C/0R · fixed -/- · velocity = (—→9, escalation no)   # fresheyes, gpt-6.1-sol high, REASON=-; it marked its 'major' findings, read here as SUBSTANTIVE (none blocks a landed behaviour: nothing was built yet)
spec: passes: 1 · elapsed: ~15 min

## Chunks
- [ ] group by fix, root and reply wording, one-line block, Japanese templates, golden test

## Notes
- Start-floor evaluator not dispatched: the dispatch floors the run at medium and no hard trigger is in scope (no secrets, auth, credential or deploy path); it could only raise to heavy on one.
- Deviation: spec and plan reviewed in one fresheyes pass (one artifact pair, one look), as 9kgk did.
- Spec+plan review dispositions. Fixed: cross-run join removed (busy bypass, retracted thread, joined member's range; follow-up ai-tools-alerts#btqg); a fix group's range covers every member (ledger._fix_group); a run never lowers a thread's fix (plan_known, versions.parse); a deferred fix group is kept as its members (Run.groups, Run.defer); a held notice takes the group's ids (Run.hold); test_recompute and test_main fixtures give each thread its own fix where the test is not about grouping; the Japanese reply rendering gets the source title and package. Rebutted: the snapshot commit's message (the snapshot never lands).
- Test migration in test_main.py was done by a same-model helper (wording and distinct fixes only; it reported no product bug).
- Mutation checks: removing member deferral fails test_a_fix_group_that_must_wait_is_kept_as_its_members; removing the never-lower guard fails test_a_run_never_lowers_a_threads_fix.
- Notes left on q03f (a root covers several ids), c6ak (the headline hook), c1g2 (curator blocks are one line too).
- Prior work: 0dvh (hold until complete; the 11-18 batch posts together), 8ke5 (no source-only or alias-only reply), 9kgk (critical needs a complete action), h340 (ids are bare CVE/GHSA; ledger key never published), wa6n (scope v6: products named by package, `package` field), t8jr (wire: block keys unchanged, new data never in the block), tyje, ny5g. kata search "ai-tools alerts wording group fix": only this issue and its siblings (q03f, 0xq6, ed7n, c1g2, c6ak, qwpw).
- xrx2 (no-reply merge author) is closed: the PR may be merged with --author-email.
