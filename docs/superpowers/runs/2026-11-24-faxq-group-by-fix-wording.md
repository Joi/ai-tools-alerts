# Run: faxq-group-by-fix-wording
Instruction: Read TASK-ai-tools-alerts#faxq.md in this worktree root, then run `kata show ai-tools-alerts#faxq` and follow the brief and the dispatch rules (do-it, start rung floored at medium; PR landing; one independent review).
Stage: code-review
Rung: medium (start-floor medium: dispatch floor; no hard trigger in scope: no secrets, auth or deploy path)
Spec: docs/superpowers/specs/2026-11-24-faxq-group-by-fix-wording-design.md   Plan: docs/superpowers/plans/2026-11-24-faxq-group-by-fix-wording.md
Agency project: —
Kata: ai-tools-alerts#faxq
Last reviewed: spec+plan 1b78b719a42b3828306f1951174363983a96a7e5
Last reviewed: code 7d99e8db97e393bd87d2732e7e846da30884ff4c (whole branch), delta --since 7d99e8d at 1b1c4fbf905f69498005ca320fdf3dae62bdd330

## Scorecards
Pass 1 [spec+plan]: 0B/8S/1C/0R · fixed -/- · velocity = (—→9, escalation no)   # fresheyes, gpt-6.1-sol high, REASON=-; it marked its 'major' findings, read here as SUBSTANTIVE (none blocks a landed behaviour: nothing was built yet)
spec: passes: 1 · elapsed: ~15 min
Pass 1 [code:branch, Stage 1]: 3B/3S/6C/0R · fixed -/- · velocity = (—→12, escalation no)   # same-model subagent, at 7d99e8d
Pass 1 [code:branch]: 8B/0S/1C/0R · fixed -/- · velocity = (—→9, escalation no)   # fresheyes whole branch, gpt-6.1-sol high, REASON=-; its 'major' read as BLOCKER (behaviour defects)
Pass 2 [code:delta]: 4B/0S/0C/0R · fixed 8/8 prior (7 fixed, 1 rebutted: z360) · velocity ↓ (9→4, escalation no)   # fresheyes --since 7d99e8d at 1b1c4fb

## Chunks
- [x] group by fix, root and reply wording, one-line block, Japanese templates, golden test — 4e8fd49; main merged 6763271 (q03f catalog; import conflict only); docs 7d99e8d; review fixes 1b1c4fb

## Notes
- Start-floor evaluator not dispatched: the dispatch floors the run at medium and no hard trigger is in scope (no secrets, auth, credential or deploy path); it could only raise to heavy on one.
- Deviation: spec and plan reviewed in one fresheyes pass (one artifact pair, one look), as 9kgk did.
- Spec+plan review dispositions. Fixed: cross-run join removed (busy bypass, retracted thread, joined member's range; follow-up ai-tools-alerts#btqg); a fix group's range covers every member (ledger._fix_group); a run never lowers a thread's fix (plan_known, versions.parse); a deferred fix group is kept as its members (Run.groups, Run.defer); a held notice takes the group's ids (Run.hold); test_recompute and test_main fixtures give each thread its own fix where the test is not about grouping; the Japanese reply rendering gets the source title and package. Rebutted: the snapshot commit's message (the snapshot never lands).
- Test migration in test_main.py was done by a same-model helper (wording and distinct fixes only; it reported no product bug).
- Mutation checks: removing member deferral fails test_a_fix_group_that_must_wait_is_kept_as_its_members; removing the never-lower guard fails test_a_run_never_lowers_a_threads_fix.
- Notes left on q03f (a root covers several ids), c6ak (the headline hook), c1g2 (curator blocks are one line too).
- Prior work: 0dvh (hold until complete; the 11-18 batch posts together), 8ke5 (no source-only or alias-only reply), 9kgk (critical needs a complete action), h340 (ids are bare CVE/GHSA; ledger key never published), wa6n (scope v6: products named by package, `package` field), t8jr (wire: block keys unchanged, new data never in the block), tyje, ny5g. kata search "ai-tools alerts wording group fix": only this issue and its siblings (q03f, 0xq6, ed7n, c1g2, c6ak, qwpw).
- xrx2 (no-reply merge author) is closed: the PR may be merged with --author-email.
- Whole-branch dispositions. Fixed in 1b1c4fb: a member's sighting narrowing the group's range (both reviews); an old member aging a fresh group (both; the newest member leads); a digested member dropping new notices (both; the unlisted members are held under their own ids; excluding digested ids from grouping broke the 11-18 case, whose three notices were listed before their fix arrived); an in-flight send recording another advisory's ids (fresheyes); a held notice keeping a range that excludes a member (fresheyes); former scope names bypassing the thread check (both); the 50-alias cap (fresheyes); mention wrapping past 90 characters (both); a title-only reply with no line (Stage 1); covers undercounting a mixed group (Stage 1); fallback headline doubling marks, product substring, copy headline from a raw title, v-prefix (Stage 1 cosmetics). Rebutted, in the delta's rebuttals file: partial retraction (filed ai-tools-alerts#z360), a vendor's downward fix correction not posted (spec accepts), the reply products line without the package (cosmetic).
- Delta (fresheyes --since 7d99e8d --rebuttals, at 1b1c4fb, REASON=-): 4 findings, all fixed with tests, no further pass (Review Cycle). (1) a group thread froze its range and dropped a real widening: now a differing range widens to everything before the fix (_group_range); (2) the deferred-group fallback by id alone could take another product's group: merge keys a group under the scope's former names instead, no fallback; (3) an id new to a listed advisory (a CVE assigned later) was held as news: only members with no listed id are held; (4) publication dates sorted as strings: parsed to UTC instants. None of the standing rebuttals was overturned.
- Golden file regenerated: the newest member now leads, so the headline and Source are GHSA-8wv7's (the design's example led with 87qg).
- Mutation checks for the review fixes: the range guard and the in-flight exclusion each fail their test when removed.
- Gate before the delta: 2392 tests pass.
