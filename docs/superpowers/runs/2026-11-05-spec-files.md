# Run: spec-files
Instruction: start at medium. Task: ai-tools-alerts#j153 — Plan Task A2 in docs/plan.md exactly (spec files, schema.py, tests, fixtures). Brief: TASK-ai-tools-alerts#j153.md in the worktree. Non-repoman repo: ending is push branch, ff-merge to main from primary checkout, close with evidence. Security-shaped: FRESHEYES_GPT_MODEL=gpt-6-astra.
Stage: committing
Rung: medium (start-floor medium: constraint-lens + instruction "start at medium"; BR1 REV0 NOV1 INT2 FC1 = 5; Lens: "Plan Task A2 in docs/plan.md exactly")
Spec: docs/superpowers/specs/2026-11-05-spec-files-design.md   Plan: docs/superpowers/plans/2026-11-05-spec-files.md
Agency project: —
Kata: ai-tools-alerts#j153
Last reviewed: spec+plan e03feef3; code (whole branch) 6b78558b
Agency: project 01a1a8f3-78e2-72af-9bf7-876f269468f9, task 01a1a8f3-8e70-7967-b634-f0b1519f4a29 (one task = chunk 1; executed inline)
Pre-handoff review: — (not repoman-managed)

## Scorecards
Pass 1 [spec+plan]: 1B/8S/0C/2R · fixed -/- · velocity = (—→11, escalation no)   # fresheyes gpt-6-astra on snapshot e03feef3 (REASON=-). Reported 3 critical / 8 major. BLOCKER: allowlist admitted repo-owner-published GitHub advisories and go.dev playground pages → owners list + go.dev path prefixes. SUBSTANTIVE fixed: RecursionError containment stated + tested; surrogates (Cs) rejected; unfinished last block returns None; tilde/indented fences tracked; action target/value restricted charset; version grammar aligned with A4; schema-vs-parser-only rules distinguished + tested; size check made non-vacuous (git add -N). Rebutted: partial-amendment contract (outside A2's Interfaces block, lens "Plan Task A2 exactly"; noted on 0xrc and h2gf); snapshot commit message (dangling review snapshot, never on a branch).
passes: spec+plan 1 · medium rung: no delta; the code pass reviews the fixed contract whole
Pass 1 [code:chunk1]: 1B/8S/6C/1R · fixed 9/9 prior · velocity ↑ (11→16, escalation no)   # Stage 1 (same-model subagent): 0B/4S/6C: line splitting beyond CR/LF/CRLF, action args too loose per verb, scope patterns runc/rustc/cargo hit common words, unbounded timestamps; cosmetic: HTTPS scheme parity, zero-width in URLs, render_post error types, hashability note, domains cache, test gaps. All fixed (hashability recorded as a note for A4/A5). Stage 2 fresheyes gpt-6-astra on 6b78558b (REASON=-): critical python.org job listings pass as primary → BLOCKER, fixed with path restriction; majors: line splitting (dup of Stage 1), parser memory not bounded (fixed: single candidate, 64 KiB drop, 1 MiB post cap), HTTPS parity (dup), deep-nesting test never reached the decoder (fixed: under-limit payload + monkeypatched RecursionError), oversize test passed via invalid JSON (fixed: valid padded JSON), snapshot commit message (rebutted).
Escalation: none. Every B/S fixed or rebutted; the BLOCKER fix changes behaviour, so one fresheyes delta pass --since 6b78558b runs over the committed fix (repo not roborev-enrolled; Review Cycle "One delta").

## Chunks
- [x] chunk 1 — spec files, schema.py, tests, fixtures (commit below)

## Notes
- kata search: A1 run (jibot-code#zq90, docs/superpowers/runs/2026-11-05-alerts-bootstrap.md) set the conventions: stdlib only, scripts/test-gate.sh = pytest -q, Agency MCP was not loaded in that session.
