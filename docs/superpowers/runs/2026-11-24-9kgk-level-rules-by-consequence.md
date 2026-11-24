# Run: 9kgk-level-rules-by-consequence
Instruction: Read TASK-ai-tools-alerts#9kgk.md in this worktree root, then run `kata show ai-tools-alerts#9kgk` and follow the brief and the dispatch rules (do-it, start rung floored at medium; PR landing; one independent review).
Stage: executing
Rung: medium (start-floor medium: dispatch floor; evaluator agrees, BR2 REV2 NOV1 INT2 FC1 = 8, no lens)
Spec: docs/superpowers/specs/2026-11-24-9kgk-level-rules-by-consequence-design.md   Plan: docs/superpowers/plans/2026-11-24-9kgk-level-rules-by-consequence.md
Agency project: 01a20c73-16b2-76c9-9e91-0aa26b6b06e6 (three tasks; Agency composes prompts only, the work was done in this session)
Kata: ai-tools-alerts#9kgk
Last reviewed: spec 6e9cd54036a1958e3e67e6ca08c4353cc6d1dd16

## Scorecards
Pass 1 [spec]: 4B/4S/0C/0R · fixed -/- · velocity = (—→8, escalation no)   # fresheyes, gpt-6.1-sol high
spec: passes: 1 · elapsed: ~12 min
Pass 1 [code:branch, Stage 1]: 0B/2S/2C/0R · fixed -/- · velocity = (—→4, escalation no)   # same-model subagent, at 7974dde
Pass 1 [code:branch]: 5B/2S/0C/0R · fixed -/- · velocity = (—→7, escalation no)   # fresheyes whole branch, gpt-6.1-sol high, at 7974dde
Pass 2 [code:delta]: 4B/0S/0C/0R · fixed 7/7 prior · velocity ↓ (7→4, escalation no)   # fresheyes --since 7974dde at 313f1af
code: passes: 2 (+ stage 1) · elapsed: ~70 min

## Chunks
- [x] ruleset v3, poster level and action, replay of the live alerts, tests — 531d414; verify after the fv4g merge 7974dde; stage-1 fixes bc79074; whole-branch fixes 313f1af; delta fixes d4f4bc0; ny5g merge with the recompute cap f8b9173

## Notes
- Prior work: s6mt (level function, ruleset v1), wa6n (ruleset v2, scope classes; closed), t8jr (wire rule 3: no relay-bot expiry in the block), r0ra (computed expiry from claims, ttl_days; closed), tyje (bot patch cannot narrow), 0dvh (hold until complete). Open siblings: ny5g (reads api.github.com: CWE, CVSS, type), fv4g (member source check), h29n (re-evaluation and lowering of open threads), ed7n (root pins the ruleset digest). kata search "level critical action" and capability-search: see the spec.
- xrx2 (no-reply merge author) is closed: the PR may be merged with --author-email.
- capability-search "level rule critical action": no tool overlaps (hits were unrelated skills).
- Spec pass 1 dispositions. Fixed: B1 (upgrade completeness keyed on products[].fixed, which the member planner uses), B2 (a stop_using critical never raises a known thread: plan_known holds it at action_cap), B3 (deliver drops an unsent journaled critical with no complete action, with its copies), B4 (test migration done; a v2-claim compatibility test; critical paths tested by unit and poster tests since no replay row is critical), S1 (channel rows lose cvss_av), S2 (h2g3 wording now high), S3 (expiry: stated as gtw9's dependency). Rebutted: S4 (the snapshot commit's message; the snapshot never lands), CWE-15 (not code execution in most products; prose covers the item).
- Found in the build: a KEV listing of a thread that already states its fix was held at high (level computed on the candidate alone). Fixed in Run.one: the thread's fix counts. Test added.
- Deviation: the plan got no separate review pass; its independent look is the whole-branch review (the brief allows three review rounds; spec, branch, and a possible delta use them).
- fv4g landed on main during the build: merged at cd7d9d2; verify.judge now holds the source's level with Ruleset.action_level (7974dde). Note left on fv4g and ny5g.
- Whole-branch review dispositions (all fixed): reader merge holds a reply's fix (a raise now needs the root's fix, ledger root_fixed); journaled copies checked from their text; standing criticals keep taking updates; curator post/amend refuse an actionless critical; stop_using survives non-fix replies; stop-using re-levels with the thread's fix; plan API text. Stage 1 also: three prose patterns narrowed; an unexpressible fix never yields stop_using.
- Delta dispositions (all fixed, no further pass): a journaled reply raising a non-critical thread is checked; a legacy entry's root fix is kept before its first reply; the copy test takes the text-only path (mutation-checked); curator amend tests.
- Delta launch notes: one launch had a mistyped sha (stopped); one was refused by fresheyes ("--since builds the scope itself; give no scope text", watchdog REASON=LOG_WAIT, a caller error, not a stall); the third ran, REASON=-.
- ny5g landed on main after the delta pass. Merged at f8b9173 with conflicts in ledger.py, main.py, test_ledger.py (both sides kept). Semantic conflict: ny5g's recompute raised from KEV fields alone, which would raise a no-fix thread to critical; recompute.held caps it. ny5g's tests give an admitted KEV candidate its fix through an autouse fixture in that file (they test timing, written with KEV criticals); two no_fix tests cover the rule there. This integration commit had no independent-model pass (the review cycle allows one review and one delta); a same-model look ran on it, below. It is named here so an auditor can read git diff d4f4bc0 f8b9173.
- Size: about 1,000 changed lines of code and tests beyond the vectors, most of it test migration the rule forces (the old suite encoded KEV-alone critical and the severity word alone as high) plus the fv4g/ny5g integration. Not split: the rule and the tests that encode the old rule cannot land apart.
- Follow-up filed: ai-tools-alerts#a3xh (the synthetic check cannot reach the critical channel).
- Test migration: the old suite encoded KEV-alone critical and the severity word alone as high. KEV-critical tests now give the vendor's fix (kev_fixed); no-fix highs use a verified trojanized flag (bare_high), the only no-fix, non-exploited high left; vendor pages state the consequence in their title.
