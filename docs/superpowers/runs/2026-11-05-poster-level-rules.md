# Run: poster-level-rules
Instruction: ai-tools-alerts#31x7 B2: level rules and scope matching — brief at TASK-ai-tools-alerts#31x7.md in the worktree. Start at medium (dispatched; never light). Non-repoman repo: ff-merge ending per the brief. Security-shaped: FRESHEYES_GPT_MODEL=gpt-6-astra.
Stage: code-review:chunk1
Rung: medium (start-floor medium: evaluator BR1 REV1 NOV1 INT1 FC1 = 5, prod-shaped medium floor, no hard trigger; Lens: none beyond the dispatch floor)
Spec: docs/superpowers/specs/2026-11-05-poster-level-rules-design.md   Plan: docs/superpowers/plans/2026-11-05-poster-level-rules.md
Agency project: —
Kata: ai-tools-alerts#31x7
Last reviewed: spec+plan 7a5d406c1dce6379eed30b7e32d3a21163317cf1
Pre-handoff review: — (not repoman-managed)

## Scorecards
Pass 1 [spec+plan]: 0B/9S/0C/0R · fixed -/- · velocity = (—→9, escalation no)   # fresheyes gpt-6-astra, one combined pass on snapshot 7a5d406c. All "major", graded SUBSTANTIVE. Fixed: one overall fetch deadline, own redirect loop (urllib drains bodies and counts distinct URLs), offline tests through a fake opener (HEAD/GET fallback, refused redirect targets never reach transport, hop bound incl. alternating URLs, deadline, bodies never read), tier-2 cap per critical clause with source_ok True and False, google/nous vendor words, additions-only leak check. Rebutted: KEV clause without source_ok (design line 47: mechanical; plan interface), tier-1 precedence in mixed text (plan interface), snapshot commit message (dangling review snapshot).
passes: spec+plan 1 · elapsed ~15 min

## Chunks
- [x] chunk 1 — rules.py, test_rules.py, Source reconciliation, no-network guard

## Notes
- Order: tests and rules.py were written while the spec+plan review ran (new files only; the reviewed snapshot is a dangling commit). Tests ran red (module missing) before the implementation. Recorded, not hidden.
- Agency: project 01a1a95e-dac7-771a-aba9-213213076665, task 01a1a95e-edb5-7088-bb7d-835508e4e64c; execution inline by the executor under the composed prompt.
- Size: 774 added lines with docs; code + tests ~500 (B1 precedent: count code+tests against the 600-line rule).
