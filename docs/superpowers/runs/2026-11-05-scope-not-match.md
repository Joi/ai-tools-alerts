# Run: scope-not-match
Instruction: ai-tools-alerts#3r9h: add per-entry not_match to spec/scope.json (version 3); both matchers read it; tests, fixture — brief at TASK-ai-tools-alerts#3r9h.md in the worktree. Start at medium (dispatched; never light). Non-repoman repo: ff-merge ending per the brief. Security-shaped: FRESHEYES_GPT_MODEL=gpt-6-astra.
Stage: done
Rung: medium (start-floor medium: evaluator BR2 REV1 NOV1 INT2 FC1 = 7, no hard trigger; medium by the instruction's constraints and the brief's floor; Lens: "Under 200 changed lines." / "No trust manifest change.")
Spec: docs/superpowers/specs/2026-11-05-scope-not-match-design.md   Plan: docs/superpowers/plans/2026-11-05-scope-not-match.md
Agency project: —
Kata: ai-tools-alerts#3r9h
Last reviewed: spec+plan 07cb21797cf89221f5f9e1a9c29aafe20c8ca1fc; code:branch f95f8a310814b20f3700f31fdf6d0857681d9ca7 (origin/main...HEAD); code:delta 9ead3ca123bac9c17588571c00c4c1b295d050c3 (--since f95f8a31)
Pre-handoff review: — (not repoman-managed)

## Scorecards
Pass 1 [spec+plan]: 0B/5S/0C/0R · fixed -/- · velocity = (—→5, escalation no)   # fresheyes gpt-6-astra, one combined pass on snapshot 07cb2179 (FRESHEYES_DONE REASON=-). All "major", graded SUBSTANTIVE. Fixed: "docker plugin" drops Docker Engine's own `docker plugin install` (GHSA-pxq6-2prw-chj9) → removed, preservation test added; existing test refused version 3 → now version 4; deferred candidates excluded by not_match vanished unlogged → main.py deferred loop passes log=review, test added. Rebutted: the 200-line limit counted with the mandatory run artifacts (the brief's limit is the change; code+tests are 177 lines; earlier runs counted the same way), plan now asserts an empty trust/ diff; the snapshot commit message (a dangling review snapshot, never on the branch).
passes: spec+plan 1
Pass 1 [code:branch]: 1B/1S/4C/0R · fixed 3/5 prior (2 rebutted) · velocity ↑ (5→6, escalation yes)   # Stage 1 (same-model subagent) ∥ Stage 2 fresheyes gpt-6-astra on origin/main...f95f8a31 (FRESHEYES_DONE REASON=-). Both stages, same defect: an exclusion phrase the vendor's own advisory can carry vetoes the runtime ("Security update for Node.js" by `for node.js`, "Node.js runtime (npm package manager included)" by `npm package`, "Google Chrome Extensions API" by `chrome extension`). Fresheyes called it blocking → graded BLOCKER (Stage 1 graded the npm half SUBSTANTIVE). Fixed: every list narrowed to third-party product phrases (library for / extension for / add-on for), preservation tests through scope_of and from_kev. Cosmetics rebutted: tier-1 exclusion then tier-2 hit is not logged (the text still posts, as tier 2; the log is for texts that post nothing); loader does not refuse a not_match that cancels its own match (the shipped-file test pins it; a hand-built file is the editor's error, and it fails safe toward a logged miss); no v3 substring-mode file test (substring + not_match is covered with constructed entries; the loader path is mode-independent); browser extension subsystem (fixed by the narrowing).
Escalation: none. The BLOCKER was fixed inside the pass; the rung stays medium and the fix gets the one delta (ruling jibot-code#41e2).
passes: code 1 (one whole-branch)
Pass 2 [code:delta]: 0B/1S/0C/0R · fixed 1/1 prior · velocity ↓ (2→1, escalation no)   # fresheyes gpt-6-astra --since f95f8a31 --rebuttals (5 standing) on 9ead3ca (FRESHEYES_DONE REASON=-). No runtime defect; no rebuttal overturned. One finding, called blocking by the reviewer, graded SUBSTANTIVE (doc only): the plan still named "Example Chrome extension" as excluded → plan updated. No further pass (ruling jibot-code#41e2).
passes: code 2 (whole-branch + delta)

## Chunks
- [x] chunk 1 — scope.json v3 not_match, load_scope, scope_of, deferred review log, tests (f95f8a3, review fix 9ead3ca, plan fix after the delta)

## Notes
- Evidence: live KEV catalog fetched 2026-11-05; 141 entries match today, tier-1 hits Docker Desktop, Git Git, and the Node.js library (wrong). Summarised in the spec.
- The brief names compose.py and match.py as matchers; match.py does not exist and compose.py has no matcher. The readers are schema.load_scope (member and poster) and rules.scope_of (poster). Decided on kata.
- Agency: the agency MCP tools are not loaded in this session; execution inline, as in the earlier runs.
- Red first: the six new test_rules tests failed on the base tree (30 passed); the deferred-review test failed with the base main.py. Gate (scripts/test-gate.sh): 764 passed on 9ead3ca. Code, data and tests: 185 changed lines; trust/ diff empty; leak grep over added lines 0.
- Live KEV (2026-11-05): 141 entries in scope before, 140 after; only CVE-2021-21315 (the Node.js library) drops.
- The coordinator's Node.js list was narrowed after code review; notice: posted on the issue.
- roborev: ai-tools-alerts is not enrolled; post-push check skipped. The behaviour-changing BLOCKER fix had its fresheyes delta before the push.
