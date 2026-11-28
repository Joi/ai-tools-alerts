# Run: vszx-admit-lane-turns
Instruction: Read TASK-ai-tools-alerts#vszx.md in this worktree root, then run `kata show ai-tools-alerts#vszx` and follow the brief and the dispatch rules (run as /do-it, starting rung floored at medium).
Stage: code-review:admit-turns
Rung: medium (start-floor medium: constraint-lens, BR1 REV1 NOV1 INT1 FC1 = 5; the dispatch brief also floors it at medium)
Lens: "the service runs with no human in the loop; nothing built may wait for a person"; "No rollout, no install, no signing in this run"
Spec: docs/superpowers/specs/2026-11-28-vszx-admit-lane-turns-design.md   Plan: docs/superpowers/plans/2026-11-28-vszx-admit-lane-turns.md
Agency project: — (the Agency tools are not offered to this session; the plan is executed directly)
Kata: ai-tools-alerts#vszx
Limits: wall clock 5 hours from the 2026-11-28T10:41Z dispatch; one independent pass per artifact and one delta only after a behaviour-changing BLOCKER fix; completion check `scripts/test-gate.sh` green and the pull request merged with the no-reply author.
Last reviewed: spec 25df706df6dd578deeff0f8b0570a8871cae1963
Last reviewed: plan 25df706df6dd578deeff0f8b0570a8871cae1963

## Scorecards
Pass 1 [spec]: 1B/3S/1C/0R · fixed -/- · velocity = (—→5, escalation no)
Pass 1 [plan]: 2B/0S/0C/0R · fixed -/- · velocity = (—→2, escalation no)
spec passes: 1 · plan passes: 1 (both fresheyes, gpt-6.1-sol, high; watchdog REASON=- for both)

## Chunks
- [ ] admit-turns — the pre-pass, `sources.in_turn`, the turn file, the log line, tests, changelog

## Notes
- This repository has no `.repoman-managed` marker: the ending is a pull request this session merges (the brief's Landing section), not a repoman handoff.
- The spec and plan reviews were launched together on one commit, to save wall clock; each artifact still had its one pass.
- The spec review's two substantive findings on the clock-counted turn (a slow API; missed runs) were fixed by a redesign, not by narrowing the claim: the turn is kept in a file of its own. Every finding's disposition is in the spec's and the plan's "Review dispositions". No finding is rebutted.
- The spec review's output file was empty at the status line; the review was read from the reviewer's log, as the protocol says.
- Mutations: recorded below once run.
