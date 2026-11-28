# Run: vszx-admit-lane-turns
Instruction: Read TASK-ai-tools-alerts#vszx.md in this worktree root, then run `kata show ai-tools-alerts#vszx` and follow the brief and the dispatch rules (run as /do-it, starting rung floored at medium).
Stage: verifying
Rung: medium (start-floor medium: constraint-lens, BR1 REV1 NOV1 INT1 FC1 = 5; the dispatch brief also floors it at medium)
Lens: "the service runs with no human in the loop; nothing built may wait for a person"; "No rollout, no install, no signing in this run"
Spec: docs/superpowers/specs/2026-11-28-vszx-admit-lane-turns-design.md   Plan: docs/superpowers/plans/2026-11-28-vszx-admit-lane-turns.md
Agency project: — (the Agency tools are not offered to this session; the plan is executed directly)
Kata: ai-tools-alerts#vszx (follow-up filed: ai-tools-alerts#xm9j)
Limits: wall clock 5 hours from the 2026-11-28T10:41Z dispatch; one independent pass per artifact and one delta only after a behaviour-changing BLOCKER fix; completion check `scripts/test-gate.sh` green and the pull request merged with the no-reply author.
Last reviewed: spec 25df706df6dd578deeff0f8b0570a8871cae1963
Last reviewed: plan 25df706df6dd578deeff0f8b0570a8871cae1963
Last reviewed: code:admit-turns 89e51d22b48cf37c260b53f1883a75022f71d902 (whole branch), then delta 91915b5503694f113259af7defc07f29a19855fb (`--since 89e51d2`)

## Scorecards
Pass 1 [spec]: 1B/3S/1C/0R · fixed -/- · velocity = (—→5, escalation no)
Pass 1 [plan]: 2B/0S/0C/0R · fixed -/- · velocity = (—→2, escalation no)
Pass 1 [code:admit-turns]: 1B/2S/0C/0R · fixed -/- · velocity = (—→3, escalation no)   (fresheyes, whole branch at 89e51d2)
Pass 1 [code:admit-turns, same-model]: 0B/2S/3C/0R (one substantive is the fresheyes blocker)
Pass 2 [code:admit-turns]: 1B/1S/0C/0R · fixed 3/3 prior · velocity ↓ (3→2, escalation no)   (fresheyes delta at 91915b5)
spec passes: 1 · plan passes: 1 · code passes: 2 (all fresheyes on gpt-6.1-sol, high; watchdog REASON=- for every run)

## Chunks
- [x] admit-turns — the pre-pass, `sources.in_turn`, the turn file, the log line, tests, changelog. Commits 89e51d2 (the change), 91915b5 (the whole-branch review's findings), 3cbf602 (the delta's findings), then the commit that carries this record (a bounded FIFO test and this file).

## Notes
- This repository has no `.repoman-managed` marker: the ending is a pull request this session merges (the brief's Landing section), not a repoman handoff.
- The spec and plan reviews were launched together on one commit, to save wall clock; each artifact still had its one pass.
- The design changed twice on review evidence. The spec review showed a clock-counted turn leaves ids unread under a slow API or missed runs: the turn is kept in a file of its own. The same-model code review showed a new candidate could wait a round: ids never asked for go first. Every finding's disposition is in the spec's "Review dispositions" (1 to 14). None is rebutted; three cosmetic points are answered there (11, 12) or fixed in text (10).
- Not seen by an independent pass: `git diff 91915b5..HEAD` (the delta's two fixes with their tests, the bounded FIFO test, this record). The rule allows no pass after the delta.
- The rung stayed medium. The one delta pass is the one the Review Cycle requires after a behaviour-changing BLOCKER fix; no finding was left standing, and no hard trigger is in the diff.
- Two review outputs were read from the reviewer's log because the output file was empty at the status line.
- The spec, plan and this record were edited in part with scripted replacements, each guarded by an assertion that the old text was there; the rule asks for the Edit tool.
- Size: 978 added lines at 3cbf602, about 430 of them these three documents, 390 tests, 150 code. One deliverable, so not split.
- Mutations (a copy of the tree, the three test files): sixteen, each fails a named test.
  1 record order; 2 no pre-pass; 3 turn never saved; 4 an id asked for counts as a request made; 5 `in_turn` ignores `after`; 6 `bisect_left`; 7 a failed save raises; 8 `load_turn` takes any `after`; 9 the log line names every unread id; 10 the clash is not checked; 11 a blocking read; 12 new ids not first; 13 a first request moves the place; 14 the remembered ids cut to the run's candidates; 15 remembered ids not checked; 16 the other files not compared resolved.
- Gate: `scripts/public-scan.sh --hit-ids` in the shared clone exits 1 on 66 objects of other sessions' refs, none of them reachable from this branch; the gate is run in a clone that holds this branch alone. Result in the close-out comment on the issue.
