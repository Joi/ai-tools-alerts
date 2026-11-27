# Run: cftg-member-strike-rule
Instruction: Read TASK-ai-tools-alerts#cftg.md in this worktree root, then run `kata show ai-tools-alerts#cftg` and follow the brief and the dispatch rules (run as /do-it, starting rung floored at medium).
Stage: spec
Rung: medium (dispatch floor; the start-floor evaluator's verdict is recorded below when it returns)
Lens: "the service runs with no human in the loop. Nothing you build may wait for a person to act."
Spec: docs/superpowers/specs/2026-11-28-cftg-member-strike-rule-design.md   Plan: docs/superpowers/plans/2026-11-28-cftg-member-strike-rule.md
Agency project: — (no Agency tools in this session; the build is done in the session itself)
Kata: ai-tools-alerts#cftg
Limits: wall clock 5 hours from 2026-11-27T22:09Z; one independent review per artifact (spec, plan, code), one delta only after a behaviour-changing BLOCKER fix, three review rounds at most on any artifact; completion check: the three acceptance cases of the issue pass as tests in `scripts/test-gate.sh`.
Landing: this repo has no `.repoman-managed` marker, so the brief's landing applies: `scripts/test-gate.sh`, one independent whole-branch review, a pull request this session merges with the no-reply author address.

## Scorecards

## Chunks
- [ ] the record of strikes and probations (`state.py`), the step that writes it and the two places it bites (`cli.py`), tests
- [ ] docs: CHANGELOG, README

## Notes
- Prior work read: the issue and its note from 0z4e; finding D14, the D8 table row "one strike against the key" and revised rule 10 on ai-tools-alerts#h29n; the m729 run record; `cli.py` (`_support_step`, `_note_support`, `_never`, `_note_offers`, `_interrupts`, `_reserve`, `_start_again`), `state.py` (`_load_unverified`), `pull.py` (`offers`, `standing`, `_filter`). `kata search "probation strike"` returns m729, cftg and h29n only: no earlier attempt, no dead end.
