# Run: z360-partial-retraction
Instruction: Read TASK-ai-tools-alerts#z360.md in this worktree root, then run `kata show ai-tools-alerts#z360` and follow the brief and the dispatch rules (do-it, start rung floored at medium; PR landing; one independent review).
Stage: spec-review
Rung: medium (start-floor medium: dispatch floor; no hard trigger in scope: no secrets, auth or deploy path)
Spec: docs/superpowers/specs/2026-11-28-z360-partial-retraction-design.md   Plan: docs/superpowers/plans/2026-11-28-z360-partial-retraction.md
Agency project: —
Kata: ai-tools-alerts#z360

## Scorecards

## Chunks
- [ ] poster reposts the survivors of a retracted fix group

## Notes
- Start-floor evaluator not dispatched: the dispatch floors the run at medium and no hard trigger is in scope; as faxq.
- Deviation (as faxq, 9kgk): spec and plan reviewed in one fresheyes pass.
- Agency not used (as every run in this repo): the plan is one chunk executed directly.
- Prior work: faxq (fix groups; z360 rebutted there and filed), d3f6 (digest leaves out retracted), c1g2 (curator hold), h340 (admit), 0dvh (age limit). kata search "partial retraction fix group": only z360 and faxq.
- Landed code vs issue text: the issue says the poster "finds them in the existing ledger entry and posts no replacement"; true at 3d376b8 (ledger.lookup has no notion of retraction).
