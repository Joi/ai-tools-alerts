# Run: nx25-aliases-answered-or-waived
Instruction: Read TASK-ai-tools-alerts#nx25.md in this worktree root, then run `kata show ai-tools-alerts#nx25` and follow the brief and the dispatch rules (run as /do-it, starting rung floored at medium).
Stage: code-review:whole-branch
Rung: medium (start-floor medium: constraint-lens, BR1 REV1 NOV1 INT0 FC1 = 4; the dispatch floors it at medium too)
Lens: "Nothing you build may wait for a person to act."; "lowerings unchanged" (a lowering keeps today's rule whole; a first id that answers 404 is a failed read, as today); "Stay inside this issue."; "No host, tailnet, VM or home-path names and no personal email in any commit, PR text or run record."
Last reviewed: spec deee8fdc575b6d9748fa1d0932302152f6f14ee1
Last reviewed: plan ae0e972b5bbfe2ba84938d4ad5559cc291c49589
Spec: docs/superpowers/specs/2026-11-27-nx25-aliases-answered-or-waived-design.md   Plan: docs/superpowers/plans/2026-11-27-nx25-aliases-answered-or-waived.md
Agency project: — (no Agency tools in this session and its server does not answer; the three tasks are built in this session)
Kata: ai-tools-alerts#nx25
Limits: wall clock 5 hours from 2026-11-26T20:27Z; one independent review per artifact (spec, plan, code), one delta only after a behaviour-changing BLOCKER fix; completion check: the acceptance cases of the issue pass as tests in `scripts/test-gate.sh`.
Landing: this repo has no `.repoman-managed` marker, so the brief's landing applies: `scripts/test-gate.sh`, one independent review, a pull request this session merges.

## Scorecards
Pass 1 [spec]: 4B/3S/0C/0R · fixed -/- · velocity = (—→7, escalation no)
spec — passes: 1 · elapsed: 12 min. Fixed 6/7 in the spec text (its Review section): only a refused answer is waived; a tied alias stays tied through a 404; a place a run for refreshing an answer; `asked` in the result key; the first eight aliases count; every tied alias read in one run. Rebutted: the message of the review snapshot commit, a dangling object that is never pushed. No delta pass: this rung has none, and the plan and code reviews read the revised rule.
Pass 1 [plan]: 2B/2S/0C/0R · fixed -/- · velocity = (—→4, escalation no)
plan — passes: 1 · elapsed: 9 min. Fixed 4/4 (the plan's Review section): the first-eight selection in the result key; the `MAX_PAIRS` test in tests/test_verify_narrowing.py; a test that a waived alias never makes a result whole; a test of `TooLarge` for a chunked body.

## Chunks
- [x] verify: alias memory, the reads of a run, the deadline, the lowering's own key; tests
- [x] docs: CHANGELOG, README

## Notes
- Prior work read: issues nx25, 2mgd (spec, plan, run record, close-out), h29n (design review D1 to D14); `kata search "alias first id incomplete unread 404"` is the issue's own search (2mgd, fv4g, tavj).
