# Run: scope-not-match
Instruction: ai-tools-alerts#3r9h: add per-entry not_match to spec/scope.json (version 3); both matchers read it; tests, fixture — brief at TASK-ai-tools-alerts#3r9h.md in the worktree. Start at medium (dispatched; never light). Non-repoman repo: ff-merge ending per the brief. Security-shaped: FRESHEYES_GPT_MODEL=gpt-6-astra.
Stage: code-review:branch
Rung: medium (start-floor medium: evaluator BR2 REV1 NOV1 INT2 FC1 = 7, no hard trigger; medium by the instruction's constraints and the brief's floor; Lens: "Under 200 changed lines." / "No trust manifest change.")
Spec: docs/superpowers/specs/2026-11-05-scope-not-match-design.md   Plan: docs/superpowers/plans/2026-11-05-scope-not-match.md
Agency project: —
Kata: ai-tools-alerts#3r9h
Last reviewed: spec+plan 07cb21797cf89221f5f9e1a9c29aafe20c8ca1fc
Pre-handoff review: — (not repoman-managed)

## Scorecards
Pass 1 [spec+plan]: 0B/5S/0C/0R · fixed -/- · velocity = (—→5, escalation no)   # fresheyes gpt-6-astra, one combined pass on snapshot 07cb2179 (FRESHEYES_DONE REASON=-). All "major", graded SUBSTANTIVE. Fixed: "docker plugin" drops Docker Engine's own `docker plugin install` (GHSA-pxq6-2prw-chj9) → removed, preservation test added; existing test refused version 3 → now version 4; deferred candidates excluded by not_match vanished unlogged → main.py deferred loop passes log=review, test added. Rebutted: the 200-line limit counted with the mandatory run artifacts (the brief's limit is the change; code+tests are 177 lines; earlier runs counted the same way), plan now asserts an empty trust/ diff; the snapshot commit message (a dangling review snapshot, never on the branch).
passes: spec+plan 1
Pass 1 [code:branch]: 1B/1S/4C/0R · fixed 3/5 prior (2 rebutted) · velocity ↑ (5→6, escalation yes)   # Stage 1 (same-model subagent) ∥ Stage 2 fresheyes gpt-6-astra on origin/main...f95f8a31 (FRESHEYES_DONE REASON=-). Both stages, same defect: an exclusion phrase the vendor's own advisory can carry vetoes the runtime ("Security update for Node.js" by `for node.js`, "Node.js runtime (npm package manager included)" by `npm package`, "Google Chrome Extensions API" by `chrome extension`). Fresheyes called it blocking → graded BLOCKER (Stage 1 graded the npm half SUBSTANTIVE). Fixed: every list narrowed to third-party product phrases (library for / extension for / add-on for), preservation tests through scope_of and from_kev. Cosmetics rebutted: tier-1 exclusion then tier-2 hit is not logged (the text still posts, as tier 2; the log is for texts that post nothing); loader does not refuse a not_match that cancels its own match (the shipped-file test pins it; a hand-built file is the editor's error, and it fails safe toward a logged miss); no v3 substring-mode file test (substring + not_match is covered with constructed entries; the loader path is mode-independent); browser extension subsystem (fixed by the narrowing).
Escalation: none. The BLOCKER was fixed inside the pass; the rung stays medium and the fix gets the one delta (ruling jibot-code#41e2).
passes: code 1 (one whole-branch)

## Chunks
- [ ] chunk 1 — scope.json v3 not_match, load_scope, scope_of, tests

## Notes
- Evidence: live KEV catalog fetched 2026-11-05; 141 entries match today, tier-1 hits Docker Desktop, Git Git, and the Node.js library (wrong). Summarised in the spec.
- The brief names compose.py and match.py as matchers; match.py does not exist and compose.py has no matcher. The readers are schema.load_scope (member and poster) and rules.scope_of (poster). Decided on kata.
- Agency: the agency MCP tools are not loaded in this session; execution inline, as in the earlier runs.
