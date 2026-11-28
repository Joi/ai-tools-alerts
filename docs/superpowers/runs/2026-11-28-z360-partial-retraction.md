# Run: z360-partial-retraction
Instruction: Read TASK-ai-tools-alerts#z360.md in this worktree root, then run `kata show ai-tools-alerts#z360` and follow the brief and the dispatch rules (do-it, start rung floored at medium; PR landing; one independent review).
Stage: committing
Rung: medium (start-floor medium: dispatch floor; no hard trigger in scope: no secrets, auth or deploy path)
Spec: docs/superpowers/specs/2026-11-28-z360-partial-retraction-design.md   Plan: docs/superpowers/plans/2026-11-28-z360-partial-retraction.md
Agency project: —
Kata: ai-tools-alerts#z360
Last reviewed: spec+plan 1ad07b7eccec3232083ce0bb66c21b84a3c088ad
Last reviewed: code 25f72436717fdd35b8df637b725c18c835d20eda (whole branch), delta --since 25f7243 at 44eec31f1efe8f1bdd63bb714b400500ac3a723f

## Scorecards
Pass 1 [spec+plan]: 0B/13S/0C/0R · fixed -/- · velocity = (—→13, escalation no)   # fresheyes gpt-6.1-sol high at snapshot 1ad07b7, REASON=-; its 'major' read as SUBSTANTIVE (nothing built yet)
spec: passes: 1 · elapsed: ~20 min
Pass 1 [code:branch, Stage 1]: 1B/3S/3C/0R · fixed -/- · velocity = (—→7, escalation no)   # same-model subagent at 25f7243
Pass 1 [code:branch]: 6B/0S/0C/0R · fixed -/- · velocity = (—→6, escalation no)   # fresheyes whole branch, gpt-6.1-sol high, REASON=-; 'critical' and 'major' read as BLOCKER (behaviour defects); two overlap Stage 1 (curator alias, its 'BLOCKER')
Pass 2 [code:delta]: 2B/0S/0C/0R · fixed 6/6 prior · velocity ↓ (6→2, escalation no)   # fresheyes --since 25f7243 --rebuttals at 44eec31, REASON=-; no standing rebuttal overturned

## Chunks
- [x] poster reposts the survivors of a retracted fix group — 25f7243; review fixes 44eec31; delta fixes 8175703; main merged b979285 (btqg, cftg, 9cch) and 5c4d964 (65xv)

## Notes
- Start-floor evaluator not dispatched: the dispatch floors the run at medium and no hard trigger is in scope; as faxq.
- Deviation (as faxq, 9kgk): spec and plan reviewed in one fresheyes pass.
- Agency not used (as every run in this repo): the plan is one chunk executed directly.
- Prior work: faxq (fix groups; z360 rebutted there and filed), d3f6 (digest leaves out retracted), c1g2 (curator hold), h340 (admit), 0dvh (age limit). kata search "partial retraction fix group": only z360 and faxq.
- Spec+plan review dispositions (design rewritten from "lookup skips a retired thread" to "release proven ids"). Fixed by the redesign: (1) crash consumes the split: pointers are saved to state deferred before the ledger release, and the ledger split record is the marker; (2) settle before retirement and (3) _record idempotence: no lookup is filtered any more, so settle and _record see what they saw; (5) survivors busy behind the retired thread: released ids leave its identity, so its work never names them; (7) the retracted advisory's CVE returning on a prose page: only a structured page releases an id, and a kept id still maps to the hidden thread; (9) mixed-age survivors: the 0dvh demotion does not apply to a released id; (10) the 3qyq retry clock: first sight is unchanged; (11) former names: every entry listing the former name is tried, the pointer is under the current one; (12) the predicate: the reader's own threads_from, with and without the manifest's retracted ids. Rebutted: (4) journaled work and digests of a retired thread, (5, rest) recompute, renewal and catalog of a retired thread: unchanged from any manifest-retracted thread today, and readers hide them; (6) a survivor whose page is past the 20-source cap stays kept (spec, out of scope; rare: more than 20 advisories in one group); (8) held fix-group notices: not threads a member's CLI holds; filed ai-tools-alerts#9je7; (13) the snapshot commit's message: the snapshot never lands.
- Mutation checks: removing the age exemption fails test_an_old_survivor_still_posts_a_root; removing the retracted filter fails test_an_advisory_already_retracted_is_never_planned.
- Test helper: a FakeRelay event id is not the mirror event's id; _on_mirror rewrites the ledger to the mirror ids, as a real relay's are.
- Landed code vs issue text: the issue says the poster "finds them in the existing ledger entry and posts no replacement"; true at 3d376b8 (ledger.lookup has no notion of retraction).
- Whole-branch dispositions (fixed in 44eec31, each with a test unless noted): scoped retraction released the bare ids (fresheyes critical; base comparison; mutation-checked); scoped survivor kept (fresheyes; same fix, same test); failing pages starve later threads (fresheyes; hourly rotation; mutation-checked); curator-only alias wedges every run (both; skip a thread whose ledger ids hold no retracted id, and catch one thread's LedgerError; mutation-checked); an older deferred row drops the proven pointer (fresheyes; the pointer replaces the row; no test); an expired curator hold masks the manifest's retraction (fresheyes; pull.standing at now, as _withdrawn; no test); learned ids left behind (Stage 1 S; mutation-checked); one CVE retried forever (Stage 1 S; GHSA first, retracted id's page first, per-candidate cap is an answer); test gaps (Stage 1 S; stop-before-ledger-write and idempotence tests added); age exemption spreads (Stage 1 C; lead id only, read once a run). Rebutted (rebuttals file of the delta): a 404 or capped source keeps an id; two threads after an un-retraction; journaled work of a retired thread; held notices (9je7); former-name path untested.
- The first gate run (gate1) overlapped the review-fix edits and is void; the gate is run on 44eec31.
- Delta dispositions (fixed in 8175703, no further pass per the Review Cycle): (1) a fetch failure past the per-candidate cap kept an id for good: any retry is a retry again (test_a_survivors_page_that_fails_once_is_retried_in_a_large_group; mutation-checked); (2) the hourly rotation could put a CVE ahead of its GHSA: threads rotate, ids within a thread keep GHSA first.
- Merge of main (b979285): btqg joins later advisories into a thread unpublished; retirement now judges joined ids too, reading the thread's learned_sources, and a release drops them from joined (test_an_advisory_that_joined_a_retired_thread_is_posted; mutation-checked). 9cch: the mirror copy is read through Run._own. These integration changes and the delta fixes landed after the last reviewed sha 44eec31 without a further pass: git diff 44eec31..8175703 and the merge commit b979285 hold them.
- Gate: scripts/test-gate.sh at 8175703: 3632 passed; at b979285: 3747 passed; at the final head: see the close-out comment.
- Release note posted on ai-tools-alerts#5fry. Follow-up filed: ai-tools-alerts#9je7.
