# Run: 2mgd-unjudgeable-by-construction
Instruction: Read TASK-ai-tools-alerts#2mgd.md in this worktree root, then run `kata show ai-tools-alerts#2mgd` and follow the brief and the dispatch rules (run as /do-it, starting rung floored at medium).
Stage: executing
Rung: medium (start-floor medium: constraint-lens, BR1 REV1 NOV1 INT1 FC1 = 5; the dispatch floors it at medium too)
Lens: "no human in the loop"; "Stay inside this issue"; "Public repo; no rollout"
Last reviewed: spec b8f9cc7ae0b7e5f7befbfab5b60db0053962fe8d
Last reviewed: plan 8192babc3c9faab38b10c1acfe6187856aadf353
Spec: docs/superpowers/specs/2026-11-26-2mgd-unjudgeable-by-construction-design.md   Plan: docs/superpowers/plans/2026-11-26-2mgd-unjudgeable-by-construction.md
Agency project: —
Kata: ai-tools-alerts#2mgd
Limits: wall clock 5 hours from 2026-11-26T02:14Z; one independent review per artifact (spec, plan, code), one delta only after a behaviour-changing BLOCKER fix; completion check: the acceptance cases of the issue pass as tests in `scripts/test-gate.sh`.
Landing: this repo has no `.repoman-managed` marker, so the brief's landing applies: `scripts/test-gate.sh`, one independent review, a pull request this session merges.

## Scorecards
Pass 1 [spec]: 2B/4S/1C/0R · fixed -/- · velocity = (—→7, escalation no)
spec — passes: 1 · elapsed: 9 min. Fixed 6/6 in the spec text (see its Review section); the cosmetic one (the snapshot commit's message) rebutted: the snapshot is a dangling review object, never pushed.
Pass 1 [plan]: 1B/6S/0C/0R · fixed -/- · velocity = (—→7, escalation no)
plan — passes: 1 · elapsed: 8 min. Blocker (pull history keyed by name) and two substantive (budget fallback, test migration) fixed in the plan; four substantive on alias scheduling moved with the alias half to ai-tools-alerts#nx25 (split, `notice:` comment on 2mgd).

## Chunks
- [ ] identity in check, verify and pull
- [ ] cli: a match that cannot be judged does not interrupt; buckets and lines by scope name
- [ ] docs: CHANGELOG, README

## Notes
- Prior work read: issue 2mgd, 0z4e (in flight on another branch, not pushed; touches cli.py and verify.py), specs fv4g, tavj, jsje, c1g2 in docs/superpowers/specs.
