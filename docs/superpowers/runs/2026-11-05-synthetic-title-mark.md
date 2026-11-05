# Run: synthetic-title-mark
Instruction: Task ai-tools-alerts#hhe3 per TASK-ai-tools-alerts#hhe3.md — when the primary id is reserved (is_synthetic), the aitools-alert block's title starts with `SYNTHETIC TEST: ` and the head line keeps its mark; check, plan, run notifications and the skill then show it. Tests in test_compose and test_cli; the session-start hook line unchanged. Under 150 changed lines. /do-it with the rung floored at medium; security-shaped review on gpt-6-astra. Non-repoman repo (ff-merge ending).
Stage: code-review:compose-title
Rung: medium (start-floor medium: constraint-lens, evaluator BR1 REV1 NOV0 INT1 FC1 = 4, no hard trigger)
Lens: "the session-start hook line is unchanged"; "a synthetic test is never labelled real"; for any id that is not reserved, "the title never carries the mark"
Last reviewed: spec+plan ee1c94c0f30c3e6f238b6eeb51df5acdd12d13d7 (pass 1, gpt-6-astra)
Spec: docs/superpowers/specs/2026-11-05-synthetic-title-mark-design.md   Plan: docs/superpowers/plans/2026-11-05-synthetic-title-mark.md
Agency project: — (no mcp__agency tools in this session; built inline, as the earlier runs on this repo did)
Kata: ai-tools-alerts#hhe3

## Scorecards
Pass 1 [spec+plan]: 5B/0S/0C/0R · fixed -/- · velocity = (—→5, escalation no)
- fresheyes gpt-6-astra, run 20261105-153244-8141aa; reviewer graded all five "major", read as BLOCKER.
- Fixed 1 (legacy synthetic roots, replayed journal entries and the Atom exporter stay unmarked) and 3 (a reader accepts a patch that removes the mark): `schema.validate` marks the title of any reserved primary id, so every reader path (pull roots and patches, parse_post, the exporter, the ledger) marks it whatever the post says.
- Fixed 2 (`test=True` could mark a real id): `root_post` drops `test`; only the id marks.
- Fixed 4 (the acceptance grep matched the plan itself): scoped to `aitools_alerts tests`.
- Rebutted 5 (snapshot commit message): ee1c94c is a dangling review snapshot built by commit-tree; it never lands on a branch.
- Medium rung: no delta on the documents; the BLOCKER fixes are code-reviewed in the code pass.

## Chunks
- [ ] compose-title — title mark, _titles, digest, tests

## Notes
- Skill rule slip: the spec/plan amendments after pass 1 were applied with a python str.replace script, not Edit; each replacement asserted or was checked by the harness diff shown afterwards, and the files read as intended. Later artifact edits use Edit.
- decided: no skill or hook edit. The skill quotes `title`, so the marked title reaches the agent; ai-tools-alerts#h260 edits the skills in parallel.
- decided: the head line keeps `(SYNTHETIC TEST)` per the brief, so it reads `CRITICAL (SYNTHETIC TEST): SYNTHETIC TEST: ...`.
