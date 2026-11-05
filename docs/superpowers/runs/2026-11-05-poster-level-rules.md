# Run: poster-level-rules
Instruction: ai-tools-alerts#31x7 B2: level rules and scope matching — brief at TASK-ai-tools-alerts#31x7.md in the worktree. Start at medium (dispatched; never light). Non-repoman repo: ff-merge ending per the brief. Security-shaped: FRESHEYES_GPT_MODEL=gpt-6-astra.
Stage: done
Rung: medium (start-floor medium: evaluator BR1 REV1 NOV1 INT1 FC1 = 5, prod-shaped medium floor, no hard trigger; Lens: none beyond the dispatch floor)
Spec: docs/superpowers/specs/2026-11-05-poster-level-rules-design.md   Plan: docs/superpowers/plans/2026-11-05-poster-level-rules.md
Agency project: 01a1a95e-dac7-771a-aba9-213213076665
Kata: ai-tools-alerts#31x7
Last reviewed: spec+plan 7a5d406c1dce6379eed30b7e32d3a21163317cf1; code:branch f0d5fc1d2869ff033ac31b5097196d50f65ef171 (whole branch origin/main...HEAD); delta b7f312a8ff7deed610946abd5e25f1833a2614a3 (--since f0d5fc1)
Pre-handoff review: — (not repoman-managed)

## Scorecards
Pass 1 [spec+plan]: 0B/9S/0C/0R · fixed -/- · velocity = (—→9, escalation no)   # fresheyes gpt-6-astra, one combined pass on snapshot 7a5d406c. All "major", graded SUBSTANTIVE. Fixed: one overall fetch deadline, own redirect loop (urllib drains bodies and counts distinct URLs), offline tests through a fake opener (HEAD/GET fallback, refused redirect targets never reach transport, hop bound incl. alternating URLs, deadline, bodies never read), tier-2 cap per critical clause with source_ok True and False, google/nous vendor words, additions-only leak check. Rebutted: KEV clause without source_ok (design line 47: mechanical; plan interface), tier-1 precedence in mixed text (plan interface), snapshot commit message (dangling review snapshot).
passes: spec+plan 1 · elapsed ~15 min
Pass 1 [code:branch]: 1B/6S/5C/0R · fixed 6/6 prior (spec+plan: 6 fixed, 3 rebutted) · velocity ↓ (9→12 counted with cosmetics; B+S 9→7, escalation yes)   # Stage 1 (same-model subagent) ∥ Stage 2 fresheyes gpt-6-astra on origin/main...f0d5fc1. BLOCKER (fresheyes major, graded BLOCKER because it can qualify a critical): a 200 completing after the deadline counted, and socket timeouts do not bound the whole fetch → fetch runs in a daemon thread joined for the time left, late answers count 0, tests for late 200 on HEAD and GET and a hung transport. SUBSTANTIVE fixed: success-path responses not asserted closed/unread (every fake response asserted, body read fails), plan steps contradicting the redirect design (rewritten), severity regex missed "code-execution"/"arbitrary commands"/full-width (NFKC + wider regex), root page of a primary host passed source_ok (refused). SUBSTANTIVE decided: tier-2 fixed RCE stays notice (plan interface over design's "in scope"; spec Review decisions). Cosmetic fixed: "_" splits vendor tokens, conftest blocks gethostbyname(_ex), tests for 3xx without Location and HEAD error then GET 200, deadline docstring. Cosmetic filed: scope.json substring over/under-match → ai-tools-alerts#x838. BLOCKER fix changed behaviour → one delta pass (fresheyes --since f0d5fc1 --rebuttals).
Pass 2 [code:delta]: 0B/2S/0C/0R · fixed 7/7 prior (6 fixed, 1 decided) · velocity ↓ (7→2, escalation no)   # fresheyes gpt-6-astra --since f0d5fc1 --rebuttals (6 standing). major, graded SUBSTANTIVE, both fixed: a redirect to a primary host's root bypassed the root-page refusal (one _countable check now guards the source, http_status and every redirect target); a body read inside the fetch thread only warned (read is recorded and asserted in the test thread; pytest turns unhandled thread exceptions into errors). Mutation check: injecting a body read and the old redirect check fails 4 tests. No standing rebuttal overturned. Last pass per ruling jibot-code#41e2.
passes: code 2 (one whole-branch, one delta)

## Chunks
- [x] chunk 1 — rules.py, test_rules.py, Source reconciliation, no-network guard

## Notes
- Order: tests and rules.py were written while the spec+plan review ran (new files only; the reviewed snapshot is a dangling commit). Tests ran red (module missing) before the implementation. Recorded, not hidden.
- Agency: project 01a1a95e-dac7-771a-aba9-213213076665, task 01a1a95e-edb5-7088-bb7d-835508e4e64c; execution inline by the executor under the composed prompt.
- Size: 774 added lines with docs; code + tests ~500 (B1 precedent: count code+tests against the 600-line rule).
- Rebased onto origin/main 3dd0387 (A3/A4 landed meanwhile); pre-rebase heads f0d5fc1, b7f312a, 00e56c0 are 72f7f88, 6ba9dce, cd1e7ba. Gate on the rebased head: 341 passed. Acceptance one-liner: 1 2 None. Leak check (added lines, docs excluded): 0.
- The delta's two SUBSTANTIVE findings are fixed in cd1e7ba with no further pass, per ruling jibot-code#41e2; a mutation check shows the new tests catch both.
- roborev: ai-tools-alerts is not enrolled; post-push check skipped. The behaviour-changing BLOCKER fix had its fresheyes delta before the push.
- Follow-up filed: ai-tools-alerts#x838 (scope.json substring patterns over/under-match tier 1).
- Size: 594 changed lines of code, tests and pyproject (under 600); 889 with the run docs.
