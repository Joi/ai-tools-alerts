# Run: 9cch-poster-mirror-reads
Instruction: Read TASK-ai-tools-alerts#9cch.md in this worktree root, then run `kata show ai-tools-alerts#9cch` and follow the brief and the dispatch rules pasted after this sentence. (The dispatch rules: /do-it, starting rung floored at medium; scripts/test-gate.sh, one independent review, a pull request this session merges.)
Stage: spec-review
Rung: medium (start-floor medium: default, BR1 REV1 NOV1 INT0 FC1 = 4; hard trigger none; no lens; the evaluator called it torn between light and medium and took the higher, which is also the dispatch floor)
Last reviewed: spec 39a16f065de8615fad21fa25520cf4f8d3d667a5
Spec: docs/superpowers/specs/2026-11-28-9cch-poster-mirror-reads-design.md   Plan: docs/superpowers/plans/2026-11-28-9cch-poster-mirror-reads.md
Agency project: — (no agency tools in this session; see Notes)
Kata: ai-tools-alerts#9cch
Limits: wall clock 5 hours from 2026-11-27T22:08Z; one independent review each of spec, plan and code, one delta only after a BLOCKER fix that changes behaviour; completion check: a test per read with a forged relay-bot event passes in scripts/test-gate.sh.

## Scorecards
Pass 1 [spec]: 0B/2S/1C/0R · fixed -/- · velocity = (—→3, escalation no)
spec: passes: 1 · elapsed: 6 min. Fixed both SUBSTANTIVE: (1) the curator-translation pass could translate from a copy with a forged block while the record is not started, and that translation stays: the pass now waits for the record (`translate=no-record`); (2) the tests lacked the forged-block path and a forged `of:` translation: both added. COSMETIC, not acted on: the snapshot commit's message (a dangling review snapshot, never pushed; later snapshots name their artifact).

## Chunks
- [ ] own-reads — one helper, four reads, tests, changelog

## Notes
- Prior work searched (kata search "poster mirror copy foreign relay-bot events"): m729 (closed; filed this issue), pdag (open; the pull-level filter, not this issue), 5fry (rollout), h29n (the design). No experiment issue on this.
- This repo has no `.repoman-managed` marker and no registry row: the landing is the brief's (scripts/test-gate.sh, one independent review, a pull request merged by this session), not a repoman handoff.
- Agency execution (Step 3) is not available: the session lists no agency tools. The one chunk is built in this session and reviewed as the rung requires.
