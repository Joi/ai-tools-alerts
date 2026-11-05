# Run: scope-bounded-match
Instruction: ai-tools-alerts#x838: scope.json patterns bounded match + missing forms — brief at TASK-ai-tools-alerts#x838.md in the worktree. Start at medium (dispatched; never light). Non-repoman repo: ff-merge ending per the brief. Security-shaped: FRESHEYES_GPT_MODEL=gpt-6-astra.
Stage: code-review:chunk1
Rung: medium (start-floor medium: evaluator BR1 REV1 NOV1 INT1 FC1 = 5, no hard trigger, medium by the instruction's constraints; Lens: existing test_rules.py tests stay green; schema change versioned, old files still read; vendor-only text stays unmatched and logged; brief's file list (schema.py departure decided on kata); qme5 not folded in; trust/ untouched)
Spec: docs/superpowers/specs/2026-11-05-scope-bounded-match-design.md   Plan: docs/superpowers/plans/2026-11-05-scope-bounded-match.md
Agency project: —
Kata: ai-tools-alerts#x838
Last reviewed: spec+plan 44ef1b3a6a29d4a46ed816dcb6e03eac97a98d67
Pre-handoff review: — (not repoman-managed)

## Scorecards
Pass 1 [spec+plan]: 0B/4S/0C/0R · fixed -/- · velocity = (—→4, escalation no)   # fresheyes gpt-6-astra, one combined pass on snapshot 44ef1b3a (FRESHEYES_DONE REASON=-). All "major", graded SUBSTANTIVE. Fixed: word rule dropped plural forms (MCP servers, Agent Skills; the entry name itself) → one optional plural s at a word-final edge, with tests; source-form table contradicted the vendor-only exclusions → spec splits the two tables; no left-boundary tests → notdocker, 2docker, Unicode letter, foo_docker, later bounded hit. Rebutted: snapshot commit message (a dangling review snapshot, never on the branch).
passes: spec+plan 1

## Chunks
- [x] chunk 1 — scope.json v2, word rule in rules.scope_of, load_scope version check, tests

## Notes
- scope.json is not signed: aitools_alerts/manifest.py covers the poster list (pubkey, role, name) only. No trust/ change.
- Evidence for the pattern list: live KEV catalog (1,768 entries) and GitHub repository/global advisories, fetched 2026-11-05; summarised in the spec.
- Order: tests and code were written while the spec+plan review of snapshot 44ef1b3a ran (the snapshot is a dangling commit; the reviewer's view is fixed). Tests ran red first: 6 failed, 24 passed. After the change: test_rules + test_schema 73 passed; scripts/test-gate.sh 535 passed, 1 skipped. Leak grep over added lines: 0.
- Agency: the agency MCP tools are not loaded in this session; execution inline by the executor, as in the B2 run.
- Follow-up filed: ai-tools-alerts#3r9h (node.js pattern matches third-party Node libraries named in KEV).
- schema.py is touched although the brief lists three files: load_scope is the reader that must check the version field. B4 owns transport.py and main.py only.
