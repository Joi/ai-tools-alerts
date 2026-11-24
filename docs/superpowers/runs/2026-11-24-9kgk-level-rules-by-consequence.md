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

## Chunks
- [ ] ruleset v3, poster level and action, replay of the live alerts, tests

## Notes
- Prior work: s6mt (level function, ruleset v1), wa6n (ruleset v2, scope classes; closed), t8jr (wire rule 3: no relay-bot expiry in the block), r0ra (computed expiry from claims, ttl_days; closed), tyje (bot patch cannot narrow), 0dvh (hold until complete). Open siblings: ny5g (reads api.github.com: CWE, CVSS, type), fv4g (member source check), h29n (re-evaluation and lowering of open threads), ed7n (root pins the ruleset digest). kata search "level critical action" and capability-search: see the spec.
- xrx2 (no-reply merge author) is closed: the PR may be merged with --author-email.
- capability-search "level rule critical action": no tool overlaps (hits were unrelated skills).
- Spec pass 1 dispositions. Fixed: B1 (upgrade completeness keyed on products[].fixed, which the member planner uses), B2 (a stop_using critical never raises a known thread: plan_known holds it at action_cap), B3 (deliver drops an unsent journaled critical with no complete action, with its copies), B4 (test migration done; a v2-claim compatibility test; critical paths tested by unit and poster tests since no replay row is critical), S1 (channel rows lose cvss_av), S2 (h2g3 wording now high), S3 (expiry: stated as gtw9's dependency). Rebutted: S4 (the snapshot commit's message; the snapshot never lands), CWE-15 (not code execution in most products; prose covers the item).
- Found in the build: a KEV listing of a thread that already states its fix was held at high (level computed on the candidate alone). Fixed in Run.one: the thread's fix counts. Test added.
- Deviation: the plan got no separate review pass; its independent look is the whole-branch review (the brief allows three review rounds; spec, branch, and a possible delta use them).
- Test migration: the old suite encoded KEV-alone critical and the severity word alone as high. KEV-critical tests now give the vendor's fix (kev_fixed); no-fix highs use a verified trojanized flag (bare_high), the only no-fix, non-exploited high left; vendor pages state the consequence in their title.
