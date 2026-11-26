# Run: swfe-narrowing-checked-like-lowering
Instruction: ai-tools-alerts#swfe (starting rung floored at medium; repoman-lane ending). Brief: `TASK-ai-tools-alerts#swfe.md`: a relay-bot narrowing of products, range or fixed version is checked by the member like a lowering (revised design rule 6).
Stage: spec
Rung: medium (start-floor medium: dispatch brief; evaluator verdict below)
Spec: docs/superpowers/specs/2026-11-26-swfe-narrowing-checked-like-lowering-design.md   Plan: docs/superpowers/plans/2026-11-26-swfe-narrowing-checked-like-lowering.md
Agency project: —
Kata: ai-tools-alerts#swfe
Last reviewed: —

Limits: wall clock 5 hours from 2026-11-26T01:49Z; one independent review per artifact (spec, plan, code), one delta only after a behaviour-changing BLOCKER fix; completion check: the four acceptance cases pass in `scripts/test-gate.sh`.

Ending: the repository has no `.repoman-managed` marker, so the brief's landing applies: `scripts/test-gate.sh`, one independent whole-branch review, a pull request this session merges, the issue closed on the merge commit.

## Scorecards

## Chunks
- [ ] reader: the published narrowing, the record, `standing`
- [ ] source check: stated ranges in the cache, `verify.narrowing`
- [ ] CLI: the check wired in, the lines and JSON keys
- [ ] wire test, wire.md, README, changelog

## Notes
- Prior work read: the design review and revised design on ai-tools-alerts#h29n (finding D1, rule 6), the close-out and notes of ai-tools-alerts#tavj, ai-tools-alerts#2wa6, `docs/superpowers/specs/2026-11-24-tyje-bot-patch-never-narrows-design.md` by its code, `spec/wire.md`.
- Agency execution: the agency tools are not available in this session; the plan is executed directly, chunk by chunk, with the tests of each chunk as its evaluator.
