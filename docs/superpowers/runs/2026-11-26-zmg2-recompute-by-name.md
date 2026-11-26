# Run: zmg2-recompute-by-name
Instruction: ai-tools-alerts#zmg2 (starting rung floored at medium): the recompute resolves a thread's scope by its stored name, through one helper shared with the catalog; a thread whose product name is not a scope identity (Codex, Cursor, Hermes, git, Python, Go, mcp) is judged like any other
Stage: executing
Rung: medium (start-floor medium: constraint-lens, BR1 REV1 NOV1 INT1 FC1 = 5; the dispatch brief floors it at medium too)
Lens: "no human in the loop; nothing you build may wait for a person to act"; "a thread whose product left the scope file is still not judged"
Last reviewed: spec cba6a3701fb0d64f26ea1cd4954f3c86ab1d1795
Last reviewed: plan c5ec01ee849b069a9fe2dbc139d0286cbdadebaa
Spec: docs/superpowers/specs/2026-11-26-zmg2-recompute-by-name-design.md   Plan: docs/superpowers/plans/2026-11-26-zmg2-recompute-by-name.md
Agency project: 01a215a7-ac37-75e1-a523-09334512ccbc
Kata: ai-tools-alerts#zmg2
Limits: wall clock 5 hours from the 2026-11-26T02:12Z dispatch; review shape one independent pass per artifact (fleet default reviewer) and one delta only after a behaviour-changing BLOCKER fix; completion check `scripts/test-gate.sh` green and the pull request merged with the no-reply author.

## Scorecards
Pass 1 [spec]: 0B/2S/0C/0R · fixed -/- · velocity = (—→2, escalation no)
spec passes: 1 · reviewer gpt-6.1-sol at high (fresheyes run 20261126-111619-4b4a4b) · one SUBSTANTIVE fixed (the rollback paragraph), one rebutted (the throwaway snapshot's message); nothing survives, so the rung stays medium
Pass 1 [plan]: 3B/1S/0C/0R · fixed -/- · velocity = (—→4, escalation no)
plan passes: 1 · reviewer gpt-6.1-sol at high (fresheyes run 20261126-112039-fc1c5c) · all four fixed in the plan and the test file (three tests that could not pass as first written, one that did not pin what it claimed); nothing survives, so the rung stays medium

## Chunks
- [ ] by-name: `rules.scope_named`, the recompute and the catalog use it, tests, changelog

## Notes
- The repository has no repoman marker: the run ends with a pull request this session merges, as the brief says, not a repoman handoff.
- The test file and the lookup were drafted while the plan's review ran, to learn whether the planned tests could be built; the draft met three of the review's four findings on its own (the Cursor thread that would not post, the floor, the Hermes source) before the review returned. The plan was amended to what was built.
- Mutations (4), each fails a named test of `tests/poster/test_recompute_names.py`: `_judge` on `rules.scope_of` (the Cursor raise, the Cursor lowering, the Hermes lowering, the former-name test); `_judge` with `former=True` (the former-name test); a case-insensitive name match (two cases of the not-a-name test); a former name resolved unasked (the former-name lookup test and the former-name run test).
